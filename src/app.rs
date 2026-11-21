//! Drawing, storage and TRNG plumbing for Cipher Workshop. All decisions are
//! made by `cipher_workshop_core::Ui`; this file maps keys to it, carries out
//! its effects, and draws its state.

use cipher_workshop_core::ciphers::{caesar_guess, frequency_bar, most_common};
use cipher_workshop_core::record::is_record_key;
use cipher_workshop_core::{CipherType, Effect, Entropy, EntropyError, Input, KeyKind, Mode, Record, Saved, Screen, Ui};
use gam::menu::Point;
use gam::GlyphStyle;
use precursor_appkit::keys::Key;
use precursor_appkit::layout::{rows_that_fit, ListState};
use precursor_appkit::rng::Trng;
use precursor_appkit::screen::{Screen as Canvas, MARGIN};
use precursor_appkit::store::Store;
use zeroize::Zeroizing;

/// PDDB dictionary. One key per saved message (`m.<16 hex>`).
pub const DICT: &str = "cipher.data";

#[derive(PartialEq, Eq)]
pub enum Action {
    Stay,
    Leave,
}

/// The hardware TRNG as a fallible core entropy source (used only to name
/// saved records). An IPC error means the message isn't saved.
struct TrngSource<'a>(&'a Trng);

impl Entropy for TrngSource<'_> {
    fn try_u32(&mut self) -> Result<u32, EntropyError> { self.0.try_u32().map_err(|_| EntropyError) }
}

fn to_input(key: Key) -> Input {
    match key {
        Key::Up => Input::Up,
        Key::Down => Input::Down,
        Key::Left => Input::Left,
        Key::Right => Input::Right,
        Key::Enter => Input::Enter,
        Key::Backspace => Input::Backspace,
        Key::F(n) => Input::F(n),
        Key::Char(c) => Input::Char(c),
    }
}

pub struct App {
    canvas: Canvas,
    store: Store,
    trng: Trng,
    ui: Ui,
    select_list: ListState,
    saved_list: ListState,
    visible_rows: usize,
}

impl App {
    pub fn new(xns: &xous_names::XousNames, canvas: Canvas, store: Store) -> Self {
        let trng = Trng::new(xns).expect("can't connect to TRNG");
        let mut app = Self {
            canvas,
            store,
            trng,
            ui: Ui::new(),
            select_list: ListState::default(),
            saved_list: ListState::default(),
            visible_rows: 1,
        };
        app.reload();
        app
    }

    pub fn screen(&self) -> &Canvas { &self.canvas }

    /// (Re)load saved messages. Runs at start and whenever a basis is locked
    /// or unlocked, so nothing from a just-locked basis stays in memory or on
    /// screen. Unreadable records are counted and never rewritten.
    pub fn reload(&mut self) {
        let mut saved = Vec::new();
        let mut unreadable = 0;
        match self.store.keys() {
            Ok(names) => {
                for name in names.into_iter().filter(|n| is_record_key(n)) {
                    match self.store.read_bytes(&name) {
                        Ok(Some(bytes)) => {
                            let bytes = Zeroizing::new(bytes);
                            match Record::parse(&bytes) {
                                Ok(record) => saved.push(Saved { key: name, record }),
                                Err(e) => {
                                    log::warn!("record {} unreadable: {:?}", name, e);
                                    unreadable += 1;
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            log::warn!("couldn't read {}: {:?}", name, e.kind());
                            unreadable += 1;
                        }
                    }
                }
            }
            Err(e) => {
                log::error!("couldn't list keys: {:?}", e.kind());
                self.ui.status = "Couldn't read saved messages".into();
            }
        }
        self.ui.set_saved(saved, unreadable);
        self.draw();
    }

    pub fn on_key(&mut self, key: Key) -> Action {
        match self.ui.on_key(to_input(key), &mut TrngSource(&self.trng)) {
            Effect::None => {}
            Effect::Leave => return Action::Leave,
            Effect::Save(key, record) => self.save(key, record),
            Effect::Delete(key) => match self.store.delete(&key) {
                Ok(()) => self.ui.on_deleted(&key),
                Err(e) => {
                    log::error!("delete failed: {:?}", e.kind());
                    self.ui.on_delete_failed(&e.kind().to_string());
                }
            },
        }
        Action::Stay
    }

    fn save(&mut self, key: String, record: Record) {
        let bytes = match serde_json::to_vec(&record) {
            Ok(b) => Zeroizing::new(b),
            Err(_) => {
                self.ui.on_save_failed("encoding");
                return;
            }
        };
        match self.store.write_bytes(&key, &bytes) {
            Ok(()) => {
                let basis = self.store.basis_of(&key).ok().flatten();
                self.ui.on_saved(key, record, basis.as_deref());
            }
            Err(e) => {
                log::error!("save failed: {:?}", e.kind());
                self.ui.on_save_failed(&e.kind().to_string());
            }
        }
    }

    pub fn on_foreground(&mut self) {
        self.canvas.refresh_size();
        self.draw();
    }

    fn footer_and_status(&self, hint: &str) -> isize {
        let bottom = self.canvas.footer(hint);
        if self.ui.status.is_empty() {
            return bottom;
        }
        let h = self.canvas.line_height(GlyphStyle::Small);
        self.canvas.text(bottom - h, GlyphStyle::Small, &self.ui.status);
        bottom - h
    }

    /// Wrapped text in a box from `y` to `bottom`. Returns the next free y.
    fn para(&self, y: isize, bottom: isize, style: GlyphStyle, text: &str) -> isize {
        if y >= bottom {
            return y;
        }
        let w = self.canvas.size().x;
        y + self.canvas.text_in(Point::new(MARGIN, y), Point::new(w - MARGIN, bottom), style, text) + 4
    }

    pub fn draw(&mut self) {
        self.canvas.clear();
        match self.ui.screen {
            Screen::Select => self.draw_select(),
            Screen::Input => self.draw_input(),
            Screen::Key => self.draw_key(),
            Screen::Output => self.draw_output(),
            Screen::Frequency => self.draw_frequency(),
            Screen::Saved => self.draw_saved(),
            Screen::View => self.draw_view(),
            Screen::ConfirmDelete => self.draw_confirm(),
        }
        self.canvas.flush();
    }

    fn draw_select(&mut self) {
        let top = self.canvas.header(&format!("Cipher Workshop · {}", self.ui.mode.label()));
        let bottom = self.footer_and_status("↑↓ ⏎ pick · M mode · S saved · ⌫ quit");
        let labels: Vec<&str> = CipherType::ALL.iter().map(|c| c.label()).collect();
        // Leave room under the list for the description of the highlighted cipher.
        let info_h = 4 * self.canvas.line_height(GlyphStyle::Small);
        self.select_list.selected = self.ui.cursor;
        self.select_list.clamp(labels.len(), labels.len());
        let rows = self.canvas.list(top, bottom - info_h, &labels, &self.select_list).max(1);
        let row_h = self.canvas.line_height(GlyphStyle::Regular) + 4;
        let c = CipherType::ALL[self.ui.cursor];
        let y = top + rows.min(labels.len()) as isize * row_h + 6;
        let y = self.para(y, bottom, GlyphStyle::Small, c.description());
        self.para(y, bottom, GlyphStyle::Small, &format!("Weakness: {}", c.weakness()));
    }

    fn draw_input(&self) {
        let c = self.ui.cipher;
        let what = match self.ui.mode {
            Mode::Encrypt => "plaintext",
            Mode::Decrypt => "ciphertext",
        };
        let mut y = self.canvas.header(&format!("{} · {}", c.label(), self.ui.mode.label()));
        let bottom = self.footer_and_status("type · ⏎ next · ⌫ delete/back · F4 back");
        y += self.canvas.text(y, GlyphStyle::Small, &format!("Type the {} ({}/200):", what, self.ui.input.len()));
        let mut shown = Zeroizing::new(String::with_capacity(self.ui.input.len() + 1));
        shown.push_str(&self.ui.input);
        shown.push('_');
        let y = self.para(y, bottom - 60, GlyphStyle::Monospace, &shown);
        self.para(y + 8, bottom, GlyphStyle::Small, &format!("Weakness: {}", c.weakness()));
    }

    fn draw_key(&self) {
        let c = self.ui.cipher;
        let mut y = self.canvas.header(&format!("{} · key", c.label()));
        y += self.canvas.text(y, GlyphStyle::Small, c.key_hint());
        y += 4;
        match c.key_kind() {
            KeyKind::Number { .. } => {
                self.footer_and_status("←→ or digits · ⏎ run · ⌫ back");
                let name = if c == CipherType::Caesar { "Shift" } else { "Rails" };
                y += self.canvas.text(y, GlyphStyle::Bold, &format!("{}:  ◂ {} ▸", name, self.ui.number));
                if c == CipherType::Caesar {
                    let s = self.ui.number;
                    let preview = format!("A→{}  B→{}  Z→{}", (b'A' + s % 26) as char, (b'A' + (1 + s) % 26) as char, (b'A' + (25 + s) % 26) as char);
                    self.canvas.text(y, GlyphStyle::Regular, &preview);
                }
            }
            KeyKind::Letters { max } => {
                let bottom = self.footer_and_status("letters · ⏎ run · ⌫ delete/back · F4 back");
                let mut shown = Zeroizing::new(String::with_capacity(self.ui.key_text.len() + 1));
                shown.push_str(&self.ui.key_text);
                shown.push('_');
                y = self.para(y, bottom, GlyphStyle::Monospace, &shown);
                y += self.canvas.text(y, GlyphStyle::Small, &format!("{}/{} letters", self.ui.key_text.len(), max));
                if c == CipherType::Substitution && self.ui.key_text.len() < 26 {
                    self.para(y, bottom, GlyphStyle::Small, &format!("Still needed: {}", self.ui.missing_letters()));
                }
            }
            KeyKind::None => {
                self.footer_and_status("⌫ back");
            }
        }
    }

    fn draw_output(&self) {
        let c = self.ui.cipher;
        let mut y = self.canvas.header(&format!("{} · {}ed", c.label(), self.ui.mode.label()));
        let bottom = self.footer_and_status("F freq · S save · R reverse · ⌫ new");
        let (in_label, out_label) = match self.ui.mode {
            Mode::Encrypt => ("Plain:", "Cipher:"),
            Mode::Decrypt => ("Cipher:", "Plain:"),
        };
        let key_info = Zeroizing::new(self.ui.key_info());
        y += self.canvas.text(y, GlyphStyle::Small, &format!("Key: {}", key_info.as_str()));
        let half = y + (bottom - y) / 2;
        y += self.canvas.text(y, GlyphStyle::Small, in_label);
        self.para(y, half - 4, GlyphStyle::Monospace, &self.ui.input);
        self.canvas.line(Point::new(MARGIN, half - 2), Point::new(self.canvas.size().x - MARGIN, half - 2));
        let y = half + self.canvas.text(half, GlyphStyle::Small, out_label);
        self.para(y, bottom, GlyphStyle::Monospace, &self.ui.output);
    }

    fn draw_frequency(&mut self) {
        let top = self.canvas.header("Letter frequency (ciphertext)");
        let bottom = self.footer_and_status("↑↓ scroll · ⏎/⌫ back");
        let small = self.canvas.line_height(GlyphStyle::Small);
        let hint = match (most_common(&self.ui.freq), caesar_guess(&self.ui.freq)) {
            (Some(t), Some(g)) => format!("Most common: {t}. If it stands for E, Caesar shift = {g}."),
            _ => "No letters to count.".to_string(),
        };
        let y = self.para(top, bottom, GlyphStyle::Small, &hint);
        let visible = rows_that_fit(bottom - y, small).clamp(1, 26);
        self.ui.freq_visible = visible;
        self.ui.freq_top = self.ui.freq_top.min(26 - visible);
        let max = self.ui.freq.iter().copied().max().unwrap_or(0);
        for (row, i) in (self.ui.freq_top..(self.ui.freq_top + visible).min(26)).enumerate() {
            let bar = frequency_bar((b'A' + i as u8) as char, self.ui.freq[i], max, 24);
            self.canvas.text(y + row as isize * small, GlyphStyle::Small, &bar);
        }
    }

    fn draw_saved(&mut self) {
        let n = self.ui.saved.len();
        let top = self.canvas.header(&format!("Saved messages ({n})"));
        let mut bottom = self.footer_and_status("⏎ view · D delete · ⌫ back");
        if self.ui.unreadable > 0 {
            let h = self.canvas.line_height(GlyphStyle::Small);
            self.canvas.text(bottom - h, GlyphStyle::Small, &format!("{} unreadable record(s) left untouched", self.ui.unreadable));
            bottom -= h;
        }
        if n == 0 {
            self.canvas.text(top + 10, GlyphStyle::Regular, "Nothing saved. Press S on a result.");
            return;
        }
        let labels: Vec<String> = self.ui.saved.iter().map(|s| s.record.title(18)).collect();
        self.saved_list.selected = self.ui.saved_cursor;
        self.saved_list.clamp(n, self.visible_rows);
        self.visible_rows = self.canvas.list(top, bottom, &labels, &self.saved_list).max(1);
    }

    fn draw_view(&self) {
        let Some(s) = self.ui.selected() else { return };
        let r = &s.record;
        let mut y = self.canvas.header(&format!("{} · {}", r.cipher.label(), r.key_info));
        let bottom = self.footer_and_status("D delete · ⏎/⌫ back");
        let half = y + (bottom - y) / 2;
        y += self.canvas.text(y, GlyphStyle::Small, "Plain:");
        self.para(y, half - 4, GlyphStyle::Monospace, &r.plaintext);
        self.canvas.line(Point::new(MARGIN, half - 2), Point::new(self.canvas.size().x - MARGIN, half - 2));
        let y = half + self.canvas.text(half, GlyphStyle::Small, "Cipher:");
        self.para(y, bottom, GlyphStyle::Monospace, &r.ciphertext);
    }

    fn draw_confirm(&self) {
        let Some(s) = self.ui.selected() else { return };
        let mut y = self.canvas.header("Delete saved message?");
        let bottom = self.footer_and_status("Y delete · any other key cancels");
        y += self.canvas.text(y, GlyphStyle::Regular, &s.record.title(24));
        y += 6;
        self.para(
            y,
            bottom,
            GlyphStyle::Small,
            "Removes the PDDB key. Old flash pages are not overwritten immediately.",
        );
    }
}
