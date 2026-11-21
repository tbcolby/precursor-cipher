//! Screen state machine. Pure: the app crate maps device keys to [`Input`],
//! carries out the returned [`Effect`] (storage, leaving), reports the outcome
//! back, and draws from the public state.
//!
//! Every screen has an exit on Backspace or F4. The menu key `∴` is consumed
//! by GAM and never reaches the app, so nothing is bound to it.

use zeroize::Zeroize;

use crate::ciphers::{frequencies, CipherKey, CipherType, KeyKind};
use crate::entropy::Entropy;
use crate::record::{new_key, Record, RECORD_VERSION};

/// Longest message accepted in the text field.
pub const MAX_INPUT: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    Up,
    Down,
    Left,
    Right,
    Enter,
    Backspace,
    F(u8),
    Char(char),
}

impl Input {
    fn is_back(self) -> bool { matches!(self, Input::Backspace | Input::F(4)) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Select,
    Input,
    Key,
    Output,
    Frequency,
    Saved,
    View,
    ConfirmDelete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

impl Mode {
    pub fn flip(self) -> Mode {
        match self {
            Mode::Encrypt => Mode::Decrypt,
            Mode::Decrypt => Mode::Encrypt,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Mode::Encrypt => "Encrypt",
            Mode::Decrypt => "Decrypt",
        }
    }
}

/// Work for the app crate.
#[derive(Debug)]
pub enum Effect {
    None,
    /// Hand focus back to GAM.
    Leave,
    /// Write this record under this PDDB key, then call `on_saved` / `on_save_failed`.
    Save(String, Record),
    /// Delete this PDDB key, then call `on_deleted` / `on_delete_failed`.
    Delete(String),
}

#[derive(Debug)]
pub struct Saved {
    pub key: String,
    pub record: Record,
}

pub struct Ui {
    pub screen: Screen,
    pub mode: Mode,
    pub cursor: usize,
    pub cipher: CipherType,
    /// The message being typed (plaintext when encrypting, ciphertext when decrypting).
    pub input: String,
    /// Letter key being typed (Vigenère / substitution), uppercase.
    pub key_text: String,
    /// Numeric key (Caesar shift / rail count).
    pub number: u8,
    /// Digits typed so far for the numeric key.
    digits: String,
    key: Option<CipherKey>,
    pub output: String,
    pub output_saved: bool,
    pub freq: [u32; 26],
    pub freq_top: usize,
    /// Rows the frequency screen can show; set by the app when it draws.
    pub freq_visible: usize,
    pub saved: Vec<Saved>,
    pub saved_cursor: usize,
    /// Records present in storage that couldn't be read (never rewritten).
    pub unreadable: usize,
    /// One-line message for the user (errors, "Saved").
    pub status: String,
}

impl Default for Ui {
    fn default() -> Self { Self::new() }
}

impl Drop for Ui {
    fn drop(&mut self) { self.clear_work(); }
}

/// Apply a typed digit to a numeric field in `min..=max`. Digits accumulate
/// while the result stays in range; a digit that would leave the range starts
/// a new number instead. Regression for the old `shift*10 + digit` entry,
/// which turned every digit typed after the default 3 into 30-39 and
/// rejected it, locking Caesar at shift 3.
pub fn type_digit(buf: &mut String, d: char, min: u8, max: u8) -> Option<u8> {
    let d = d.to_digit(10)? as u8;
    let extended = buf.parse::<u16>().ok().map(|v| v * 10 + d as u16);
    match extended {
        Some(v) if !buf.is_empty() && buf.len() < 3 && (min as u16..=max as u16).contains(&v) => {
            buf.push((b'0' + d) as char);
            Some(v as u8)
        }
        _ => {
            buf.clear();
            if (min..=max).contains(&d) {
                buf.push((b'0' + d) as char);
                Some(d)
            } else if d != 0 {
                // A single digit below the minimum: keep it as the start of a
                // two-digit number (e.g. "1" then "0" for 10 rails).
                buf.push((b'0' + d) as char);
                None
            } else {
                None
            }
        }
    }
}

impl Ui {
    pub fn new() -> Self {
        Ui {
            screen: Screen::Select,
            mode: Mode::Encrypt,
            cursor: 0,
            cipher: CipherType::Caesar,
            input: String::new(),
            key_text: String::new(),
            number: 3,
            digits: String::new(),
            key: None,
            output: String::new(),
            output_saved: false,
            freq: [0; 26],
            freq_top: 0,
            freq_visible: 26,
            saved: Vec::new(),
            saved_cursor: 0,
            unreadable: 0,
            status: String::new(),
        }
    }

    /// Replace the saved list (startup and after a basis change). Anything on
    /// screen that came from the old list is dropped.
    pub fn set_saved(&mut self, mut saved: Vec<Saved>, unreadable: usize) {
        saved.sort_by_key(|s| s.record.seq);
        self.saved = saved;
        self.unreadable = unreadable;
        self.saved_cursor = self.saved_cursor.min(self.saved.len().saturating_sub(1));
        if matches!(self.screen, Screen::View | Screen::ConfirmDelete) {
            self.screen = Screen::Saved;
        }
    }

    pub fn selected(&self) -> Option<&Saved> { self.saved.get(self.saved_cursor) }

    /// The current key, as entered (for the output screen).
    pub fn key_info(&self) -> String { self.key.as_ref().map(|k| k.describe()).unwrap_or_default() }

    /// (plaintext, ciphertext) of the current result.
    pub fn plain_and_cipher(&self) -> (&str, &str) {
        match self.mode {
            Mode::Encrypt => (&self.input, &self.output),
            Mode::Decrypt => (&self.output, &self.input),
        }
    }

    /// Wipe the message, key and result.
    fn clear_work(&mut self) {
        self.input.zeroize();
        self.key_text.zeroize();
        self.digits.zeroize();
        self.output.zeroize();
        self.key = None;
        self.output_saved = false;
    }

    pub fn on_key<E: Entropy + ?Sized>(&mut self, key: Input, rng: &mut E) -> Effect {
        self.status.clear();
        match self.screen {
            Screen::Select => self.key_select(key),
            Screen::Input => self.key_input(key),
            Screen::Key => self.key_key(key),
            Screen::Output => self.key_output(key, rng),
            Screen::Frequency => self.key_frequency(key),
            Screen::Saved => self.key_saved(key),
            Screen::View => self.key_view(key),
            Screen::ConfirmDelete => self.key_confirm(key),
        }
    }

    fn key_select(&mut self, key: Input) -> Effect {
        let n = CipherType::ALL.len();
        match key {
            Input::Up => self.cursor = self.cursor.saturating_sub(1),
            Input::Down => self.cursor = (self.cursor + 1).min(n - 1),
            Input::Enter => {
                self.clear_work();
                self.cipher = CipherType::ALL[self.cursor];
                if let KeyKind::Number { default, .. } = self.cipher.key_kind() {
                    self.number = default;
                }
                self.screen = Screen::Input;
            }
            Input::Char('m') | Input::Char('M') | Input::F(1) => self.mode = self.mode.flip(),
            Input::Char('s') | Input::Char('S') | Input::F(2) => self.screen = Screen::Saved,
            k if k.is_back() => return Effect::Leave,
            _ => {}
        }
        Effect::None
    }

    fn key_input(&mut self, key: Input) -> Effect {
        match key {
            Input::Backspace if !self.input.is_empty() => {
                self.input.pop();
            }
            k if k.is_back() => {
                self.clear_work();
                self.screen = Screen::Select;
            }
            Input::Enter => {
                if self.input.is_empty() {
                    self.status = "Type a message first".into();
                } else if self.cipher.key_kind() == KeyKind::None {
                    self.run(CipherKey::new(self.cipher, 0, ""));
                } else {
                    self.key_text.zeroize();
                    self.digits.clear();
                    self.screen = Screen::Key;
                }
            }
            Input::Char(c) if (' '..='~').contains(&c) => {
                if self.input.len() < MAX_INPUT {
                    self.input.push(c);
                } else {
                    self.status = format!("Limit is {MAX_INPUT} characters");
                }
            }
            _ => {}
        }
        Effect::None
    }

    fn key_key(&mut self, key: Input) -> Effect {
        match self.cipher.key_kind() {
            KeyKind::Number { min, max, .. } => match key {
                Input::Left | Input::Down => {
                    self.digits.clear();
                    self.number = if self.number <= min { max } else { self.number - 1 };
                }
                Input::Right | Input::Up => {
                    self.digits.clear();
                    self.number = if self.number >= max { min } else { self.number + 1 };
                }
                Input::Char(c) if c.is_ascii_digit() => {
                    if let Some(v) = type_digit(&mut self.digits, c, min, max) {
                        self.number = v;
                    }
                }
                Input::Enter => self.run(CipherKey::new(self.cipher, self.number, "")),
                k if k.is_back() => self.screen = Screen::Input,
                _ => {}
            },
            KeyKind::Letters { max } => match key {
                Input::Backspace if !self.key_text.is_empty() => {
                    self.key_text.pop();
                }
                k if k.is_back() => {
                    self.key_text.zeroize();
                    self.screen = Screen::Input;
                }
                Input::Enter => {
                    let k = CipherKey::new(self.cipher, 0, &self.key_text);
                    self.run(k);
                }
                Input::Char(c) if c.is_ascii_alphabetic() => {
                    let c = c.to_ascii_uppercase();
                    if self.key_text.len() >= max {
                        self.status = format!("Key is at most {max} letters");
                    } else if self.cipher == CipherType::Substitution && self.key_text.contains(c) {
                        self.status = format!("{c} is already used");
                    } else {
                        self.key_text.push(c);
                    }
                }
                Input::Char(_) => self.status = "Letters A-Z only".into(),
                _ => {}
            },
            KeyKind::None => self.screen = Screen::Input,
        }
        Effect::None
    }

    /// Letters a substitution alphabet still needs, for the key screen.
    pub fn missing_letters(&self) -> String {
        ('A'..='Z').filter(|c| !self.key_text.contains(*c)).collect()
    }

    fn run(&mut self, key: Result<CipherKey, crate::ciphers::KeyError>) {
        match key {
            Ok(k) => {
                self.output.zeroize();
                self.output = match self.mode {
                    Mode::Encrypt => k.encrypt(&self.input),
                    Mode::Decrypt => k.decrypt(&self.input),
                };
                self.key = Some(k);
                self.output_saved = false;
                self.screen = Screen::Output;
            }
            Err(e) => self.status = e.to_string(),
        }
    }

    fn key_output<E: Entropy + ?Sized>(&mut self, key: Input, rng: &mut E) -> Effect {
        match key {
            Input::Char('f') | Input::Char('F') | Input::F(1) => {
                let (_, cipher) = self.plain_and_cipher();
                self.freq = frequencies(cipher);
                self.freq_top = 0;
                self.screen = Screen::Frequency;
            }
            Input::Char('s') | Input::Char('S') | Input::F(2) => return self.save(rng),
            Input::Char('r') | Input::Char('R') | Input::F(3) => {
                // Feed the result back in with the mode flipped.
                if let Some(k) = self.key.take() {
                    core::mem::swap(&mut self.input, &mut self.output);
                    self.mode = self.mode.flip();
                    self.run(Ok(k));
                }
            }
            k if k.is_back() || k == Input::Enter => {
                self.clear_work();
                self.screen = Screen::Select;
            }
            _ => {}
        }
        Effect::None
    }

    fn save<E: Entropy + ?Sized>(&mut self, rng: &mut E) -> Effect {
        if self.output_saved {
            self.status = "Already saved".into();
            return Effect::None;
        }
        let key = match new_key(rng) {
            Ok(k) => k,
            Err(_) => {
                self.status = "TRNG error: not saved".into();
                return Effect::None;
            }
        };
        let (plain, cipher) = self.plain_and_cipher();
        let record = Record {
            version: RECORD_VERSION,
            seq: self.saved.iter().map(|s| s.record.seq).max().map_or(1, |m| m + 1),
            cipher: self.cipher,
            key_info: self.key_info(),
            plaintext: plain.to_string(),
            ciphertext: cipher.to_string(),
        };
        Effect::Save(key, record)
    }

    pub fn on_saved(&mut self, key: String, record: Record, basis: Option<&str>) {
        self.saved.push(Saved { key, record });
        self.output_saved = true;
        self.status = match basis {
            Some(b) => format!("Saved (basis {b})"),
            None => "Saved".into(),
        };
    }

    pub fn on_save_failed(&mut self, why: &str) { self.status = format!("Save failed: {why}"); }

    fn key_frequency(&mut self, key: Input) -> Effect {
        let max_top = 26usize.saturating_sub(self.freq_visible.max(1));
        match key {
            Input::Up => self.freq_top = self.freq_top.saturating_sub(1),
            Input::Down => self.freq_top = (self.freq_top + 1).min(max_top),
            k if k.is_back() || k == Input::Enter => self.screen = Screen::Output,
            _ => {}
        }
        Effect::None
    }

    fn key_saved(&mut self, key: Input) -> Effect {
        let n = self.saved.len();
        match key {
            Input::Up => self.saved_cursor = self.saved_cursor.saturating_sub(1),
            Input::Down => self.saved_cursor = (self.saved_cursor + 1).min(n.saturating_sub(1)),
            Input::Enter if n > 0 => self.screen = Screen::View,
            Input::Char('d') | Input::Char('D') | Input::F(3) if n > 0 => self.screen = Screen::ConfirmDelete,
            k if k.is_back() => self.screen = Screen::Select,
            _ => {}
        }
        Effect::None
    }

    fn key_view(&mut self, key: Input) -> Effect {
        match key {
            Input::Char('d') | Input::Char('D') | Input::F(3) => self.screen = Screen::ConfirmDelete,
            k if k.is_back() || k == Input::Enter => self.screen = Screen::Saved,
            _ => {}
        }
        Effect::None
    }

    fn key_confirm(&mut self, key: Input) -> Effect {
        self.screen = Screen::Saved;
        match (key, self.selected()) {
            (Input::Char('y') | Input::Char('Y'), Some(s)) => Effect::Delete(s.key.clone()),
            _ => {
                self.status = "Not deleted".into();
                Effect::None
            }
        }
    }

    pub fn on_deleted(&mut self, key: &str) {
        self.saved.retain(|s| s.key != key);
        self.saved_cursor = self.saved_cursor.min(self.saved.len().saturating_sub(1));
        self.status = "Deleted".into();
    }

    pub fn on_delete_failed(&mut self, why: &str) { self.status = format!("Delete failed: {why}"); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::testing::*;

    fn press(ui: &mut Ui, keys: &[Input]) -> Effect {
        let mut last = Effect::None;
        for &k in keys {
            last = ui.on_key(k, &mut XorShift(7));
        }
        last
    }

    fn type_str(ui: &mut Ui, s: &str) {
        for c in s.chars() {
            ui.on_key(Input::Char(c), &mut XorShift(7));
        }
    }

    fn pick(ui: &mut Ui, cipher: CipherType) {
        let idx = CipherType::ALL.iter().position(|&c| c == cipher).unwrap();
        for _ in 0..6 {
            press(ui, &[Input::Up]);
        }
        for _ in 0..idx {
            press(ui, &[Input::Down]);
        }
        press(ui, &[Input::Enter]);
        assert_eq!(ui.screen, Screen::Input);
        assert_eq!(ui.cipher, cipher);
    }

    #[test]
    fn every_screen_has_a_back_key() {
        // Regression: Output, Key and others exited only via ∴, which GAM eats.
        let mut ui = Ui::new();
        pick(&mut ui, CipherType::Caesar);
        type_str(&mut ui, "HI");
        press(&mut ui, &[Input::Enter]);
        assert_eq!(ui.screen, Screen::Key);
        press(&mut ui, &[Input::Enter]);
        assert_eq!(ui.screen, Screen::Output);
        press(&mut ui, &[Input::Char('f')]);
        assert_eq!(ui.screen, Screen::Frequency);
        press(&mut ui, &[Input::F(4)]);
        assert_eq!(ui.screen, Screen::Output);
        press(&mut ui, &[Input::Backspace]);
        assert_eq!(ui.screen, Screen::Select);
        assert!(ui.input.is_empty() && ui.output.is_empty(), "work is wiped on leaving output");
        press(&mut ui, &[Input::Char('s')]);
        assert_eq!(ui.screen, Screen::Saved);
        press(&mut ui, &[Input::F(4)]);
        assert_eq!(ui.screen, Screen::Select);
        assert!(matches!(press(&mut ui, &[Input::Backspace]), Effect::Leave));
    }

    #[test]
    fn backspace_edits_then_goes_back() {
        let mut ui = Ui::new();
        pick(&mut ui, CipherType::Vigenere);
        type_str(&mut ui, "AB");
        press(&mut ui, &[Input::Backspace]);
        assert_eq!(ui.input, "A");
        press(&mut ui, &[Input::Enter]);
        assert_eq!(ui.screen, Screen::Key);
        type_str(&mut ui, "k");
        press(&mut ui, &[Input::Backspace, Input::Backspace]);
        assert_eq!(ui.screen, Screen::Input);
        press(&mut ui, &[Input::Backspace, Input::Backspace]);
        assert_eq!(ui.screen, Screen::Select);
    }

    #[test]
    fn caesar_shift_can_be_typed_and_arrowed() {
        // Regression: digits after the default 3 gave 30-39 and were refused.
        let mut ui = Ui::new();
        pick(&mut ui, CipherType::Caesar);
        type_str(&mut ui, "ABC");
        press(&mut ui, &[Input::Enter]);
        type_str(&mut ui, "7");
        assert_eq!(ui.number, 7);
        type_str(&mut ui, "1");
        assert_eq!(ui.number, 1, "71 is out of range, so 1 starts a new number");
        type_str(&mut ui, "3");
        assert_eq!(ui.number, 13);
        press(&mut ui, &[Input::Right]);
        assert_eq!(ui.number, 14);
        press(&mut ui, &[Input::Enter]);
        assert_eq!(ui.output, "OPQ");
        assert_eq!(ui.key_info(), "shift=14");
    }

    #[test]
    fn numeric_wraps_at_ends() {
        let mut ui = Ui::new();
        pick(&mut ui, CipherType::Caesar);
        type_str(&mut ui, "A");
        press(&mut ui, &[Input::Enter]);
        type_str(&mut ui, "1");
        press(&mut ui, &[Input::Left]);
        assert_eq!(ui.number, 25);
        press(&mut ui, &[Input::Right]);
        assert_eq!(ui.number, 1);
    }

    #[test]
    fn type_digit_rules() {
        let mut b = String::new();
        assert_eq!(type_digit(&mut b, '2', 1, 25), Some(2));
        assert_eq!(type_digit(&mut b, '5', 1, 25), Some(25));
        assert_eq!(type_digit(&mut b, '9', 1, 25), Some(9));
        assert_eq!(type_digit(&mut b, '0', 1, 25), None);
        // Rails: "1" alone is below 2, but "10" is valid.
        let mut b = String::new();
        assert_eq!(type_digit(&mut b, '1', 2, 10), None);
        assert_eq!(type_digit(&mut b, '0', 2, 10), Some(10));
        assert_eq!(type_digit(&mut b, '3', 2, 10), Some(3));
    }

    #[test]
    fn rails_ten_by_typing() {
        let mut ui = Ui::new();
        pick(&mut ui, CipherType::RailFence);
        type_str(&mut ui, "WEAREDISCOVERED");
        press(&mut ui, &[Input::Enter]);
        type_str(&mut ui, "10");
        assert_eq!(ui.number, 10);
    }

    #[test]
    fn vigenere_key_entry_filters_letters() {
        // Regression: "my key" / "k3y" reached the cipher and underflowed.
        let mut ui = Ui::new();
        pick(&mut ui, CipherType::Vigenere);
        type_str(&mut ui, "ATTACKATDAWN");
        press(&mut ui, &[Input::Enter]);
        type_str(&mut ui, "le mon3");
        assert_eq!(ui.key_text, "LEMON");
        press(&mut ui, &[Input::Enter]);
        assert_eq!(ui.output, "LXFOPVEFRNHR");
    }

    #[test]
    fn empty_letter_key_stays_with_error() {
        let mut ui = Ui::new();
        pick(&mut ui, CipherType::Vigenere);
        type_str(&mut ui, "x");
        press(&mut ui, &[Input::Enter, Input::Enter]);
        assert_eq!(ui.screen, Screen::Key);
        assert_eq!(ui.status, "Key is empty");
    }

    #[test]
    fn substitution_needs_26_distinct() {
        let mut ui = Ui::new();
        pick(&mut ui, CipherType::Substitution);
        type_str(&mut ui, "flee");
        press(&mut ui, &[Input::Enter]);
        type_str(&mut ui, "ZEBRAS");
        type_str(&mut ui, "Z");
        assert_eq!(ui.status, "Z is already used");
        press(&mut ui, &[Input::Enter]);
        assert_eq!(ui.screen, Screen::Key, "short alphabet is refused, not passed through");
        assert_eq!(ui.status, "Need all 26 letters (have 6)");
        assert_eq!(ui.missing_letters(), "CDFGHIJKLMNOPQTUVWXY");
        type_str(&mut ui, "CDFGHIJKLMNOPQTUVWXY");
        press(&mut ui, &[Input::Enter]);
        assert_eq!(ui.output, "siaa");
    }

    #[test]
    fn rot13_skips_key_screen_and_reverse_round_trips() {
        let mut ui = Ui::new();
        pick(&mut ui, CipherType::Rot13);
        type_str(&mut ui, "Hello");
        press(&mut ui, &[Input::Enter]);
        assert_eq!(ui.screen, Screen::Output);
        assert_eq!(ui.output, "Uryyb");
        press(&mut ui, &[Input::Char('r')]);
        assert_eq!(ui.mode, Mode::Decrypt);
        assert_eq!(ui.input, "Uryyb");
        assert_eq!(ui.output, "Hello");
    }

    #[test]
    fn reverse_with_keyed_cipher() {
        let mut ui = Ui::new();
        pick(&mut ui, CipherType::RailFence);
        type_str(&mut ui, "WEAREDISCOVEREDFLEEATONCE");
        press(&mut ui, &[Input::Enter, Input::Enter]);
        assert_eq!(ui.output, "WECRLTEERDSOEEFEAOCAIVDEN");
        press(&mut ui, &[Input::F(3)]);
        assert_eq!(ui.output, "WEAREDISCOVEREDFLEEATONCE");
    }

    #[test]
    fn decrypt_mode() {
        let mut ui = Ui::new();
        press(&mut ui, &[Input::Char('m')]);
        assert_eq!(ui.mode, Mode::Decrypt);
        pick(&mut ui, CipherType::Vigenere);
        type_str(&mut ui, "LXFOPVEFRNHR");
        press(&mut ui, &[Input::Enter]);
        type_str(&mut ui, "LEMON");
        press(&mut ui, &[Input::Enter]);
        assert_eq!(ui.output, "ATTACKATDAWN");
        assert_eq!(ui.plain_and_cipher(), ("ATTACKATDAWN", "LXFOPVEFRNHR"));
    }

    fn to_output(ui: &mut Ui) {
        pick(ui, CipherType::Atbash);
        type_str(ui, "WIZARD");
        press(ui, &[Input::Enter]);
        assert_eq!(ui.screen, Screen::Output);
    }

    #[test]
    fn save_flow_and_no_duplicates() {
        let mut ui = Ui::new();
        to_output(&mut ui);
        let (key, rec) = match press(&mut ui, &[Input::Char('s')]) {
            Effect::Save(k, r) => (k, r),
            e => panic!("{e:?}"),
        };
        assert_eq!(rec.plaintext, "WIZARD");
        assert_eq!(rec.ciphertext, "DRAZIW");
        assert_eq!(rec.seq, 1);
        ui.on_saved(key, rec, Some(".System"));
        assert_eq!(ui.status, "Saved (basis .System)");
        assert!(matches!(press(&mut ui, &[Input::Char('s')]), Effect::None));
        assert_eq!(ui.status, "Already saved");
    }

    #[test]
    fn save_fails_closed_on_trng_error() {
        let mut ui = Ui::new();
        to_output(&mut ui);
        assert!(matches!(ui.on_key(Input::F(2), &mut Broken), Effect::None));
        assert_eq!(ui.status, "TRNG error: not saved");
        assert!(!ui.output_saved);
    }

    #[test]
    fn failed_save_can_be_retried() {
        let mut ui = Ui::new();
        to_output(&mut ui);
        press(&mut ui, &[Input::Char('s')]);
        ui.on_save_failed("NotFound");
        assert!(matches!(press(&mut ui, &[Input::Char('s')]), Effect::Save(..)));
    }

    fn rec(seq: u64, p: &str) -> Record {
        Record {
            version: RECORD_VERSION,
            seq,
            cipher: CipherType::Caesar,
            key_info: "shift=3".into(),
            plaintext: p.into(),
            ciphertext: String::new(),
        }
    }

    #[test]
    fn delete_targets_selected_record() {
        let mut ui = Ui::new();
        ui.set_saved(
            vec![Saved { key: "m.b".into(), record: rec(2, "two") }, Saved { key: "m.a".into(), record: rec(1, "one") }],
            0,
        );
        assert_eq!(ui.saved[0].record.plaintext, "one", "sorted by seq");
        press(&mut ui, &[Input::Char('s'), Input::Down, Input::Enter]);
        assert_eq!(ui.screen, Screen::View);
        press(&mut ui, &[Input::Char('d')]);
        assert_eq!(ui.screen, Screen::ConfirmDelete);
        match press(&mut ui, &[Input::Char('y')]) {
            Effect::Delete(k) => {
                assert_eq!(k, "m.b");
                ui.on_deleted(&k);
            }
            e => panic!("{e:?}"),
        }
        assert_eq!(ui.saved.len(), 1);
        assert_eq!(ui.saved_cursor, 0);
        // Any other key cancels.
        press(&mut ui, &[Input::Char('d'), Input::Char('n')]);
        assert_eq!(ui.status, "Not deleted");
        assert_eq!(ui.saved.len(), 1);
    }

    #[test]
    fn next_seq_follows_largest() {
        let mut ui = Ui::new();
        ui.set_saved(vec![Saved { key: "m.a".into(), record: rec(9, "x") }], 0);
        to_output(&mut ui);
        match press(&mut ui, &[Input::Char('s')]) {
            Effect::Save(_, r) => assert_eq!(r.seq, 10),
            e => panic!("{e:?}"),
        }
    }

    #[test]
    fn basis_change_leaves_detail_screens() {
        let mut ui = Ui::new();
        ui.set_saved(vec![Saved { key: "m.a".into(), record: rec(1, "x") }], 0);
        press(&mut ui, &[Input::Char('s'), Input::Enter]);
        assert_eq!(ui.screen, Screen::View);
        ui.set_saved(Vec::new(), 0);
        assert_eq!(ui.screen, Screen::Saved);
        assert!(ui.selected().is_none());
        // Enter / D do nothing on an empty list.
        press(&mut ui, &[Input::Enter, Input::Char('d')]);
        assert_eq!(ui.screen, Screen::Saved);
    }

    #[test]
    fn frequency_scroll_is_bounded() {
        let mut ui = Ui::new();
        to_output(&mut ui);
        press(&mut ui, &[Input::Char('f')]);
        // Ciphertext DRAZIW: one each of A D I R W Z.
        assert_eq!(ui.freq.iter().sum::<u32>(), 6);
        ui.freq_visible = 26;
        press(&mut ui, &[Input::Down]);
        assert_eq!(ui.freq_top, 0, "all 26 rows fit, so no scrolling");
        ui.freq_visible = 20;
        for _ in 0..10 {
            press(&mut ui, &[Input::Down]);
        }
        assert_eq!(ui.freq_top, 6);
    }

    #[test]
    fn input_limit_and_printable_only() {
        let mut ui = Ui::new();
        pick(&mut ui, CipherType::Caesar);
        type_str(&mut ui, &"a".repeat(MAX_INPUT + 5));
        assert_eq!(ui.input.len(), MAX_INPUT);
        ui.on_key(Input::Char('\u{7}'), &mut XorShift(1));
        assert_eq!(ui.input.len(), MAX_INPUT);
    }

    #[test]
    fn enter_on_empty_input_explains() {
        let mut ui = Ui::new();
        pick(&mut ui, CipherType::Caesar);
        press(&mut ui, &[Input::Enter]);
        assert_eq!(ui.screen, Screen::Input);
        assert_eq!(ui.status, "Type a message first");
    }
}
