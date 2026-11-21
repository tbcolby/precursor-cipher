//! Classical ciphers with validated keys.
//!
//! These are teaching ciphers. Every one of them is broken by hand or with a
//! few seconds of computation; [`CipherType::weakness`] says how. Nothing here
//! provides confidentiality.
//!
//! Letters are ASCII `A-Z`/`a-z`; case is preserved. Everything else (digits,
//! spaces, punctuation, non-ASCII) passes through unchanged, except in the rail
//! fence, which transposes every character.
//!
//! Keys are checked when they are built ([`CipherKey`]), so encryption can't
//! hit the old failure modes: a non-letter Vigenère key used to underflow
//! (panic in debug builds, non-invertible output in release), and a short or
//! duplicated substitution alphabet used to return the plaintext unchanged or
//! decrypt letters to NUL.

use core::fmt;

use serde::{Deserialize, Serialize};

/// Available ciphers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherType {
    Caesar,
    Rot13,
    Atbash,
    Vigenere,
    Substitution,
    RailFence,
}

/// What kind of key a cipher takes, which decides the key-entry screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    None,
    /// A number in `min..=max`, adjusted with arrows or typed.
    Number { min: u8, max: u8, default: u8 },
    /// Letters only, at most `max` of them.
    Letters { max: usize },
}

pub const CAESAR_MIN: u8 = 1;
pub const CAESAR_MAX: u8 = 25;
pub const RAILS_MIN: u8 = 2;
pub const RAILS_MAX: u8 = 10;
pub const VIGENERE_MAX: usize = 30;

impl CipherType {
    pub const ALL: [CipherType; 6] = [
        CipherType::Caesar,
        CipherType::Rot13,
        CipherType::Atbash,
        CipherType::Vigenere,
        CipherType::Substitution,
        CipherType::RailFence,
    ];

    pub fn label(self) -> &'static str {
        match self {
            CipherType::Caesar => "Caesar shift",
            CipherType::Rot13 => "ROT13",
            CipherType::Atbash => "Atbash",
            CipherType::Vigenere => "Vigenere",
            CipherType::Substitution => "Substitution",
            CipherType::RailFence => "Rail fence",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            CipherType::Caesar => "Shift each letter by N places",
            CipherType::Rot13 => "Caesar with shift 13; its own inverse",
            CipherType::Atbash => "A<->Z, B<->Y, ...; its own inverse",
            CipherType::Vigenere => "A Caesar shift per letter of a keyword",
            CipherType::Substitution => "Any rearrangement of A-Z",
            CipherType::RailFence => "Write in a zigzag, read row by row",
        }
    }

    /// Why this cipher offers no real protection.
    pub fn weakness(self) -> &'static str {
        match self {
            CipherType::Caesar => "Only 25 keys: try them all, or assume the commonest letter is E.",
            CipherType::Rot13 => "No key at all: anyone who knows ROT13 can read it.",
            CipherType::Atbash => "No key at all: one fixed mapping, undone by applying it again.",
            CipherType::Vigenere => {
                "The key repeats: Kasiski or Friedman tests find its length, then each column is a Caesar."
            }
            CipherType::Substitution => "Letter frequencies survive: E, T, A and short words give it away.",
            CipherType::RailFence => "Letters are only reordered, and there are few rail counts to try.",
        }
    }

    pub fn key_kind(self) -> KeyKind {
        match self {
            CipherType::Caesar => KeyKind::Number { min: CAESAR_MIN, max: CAESAR_MAX, default: 3 },
            CipherType::RailFence => KeyKind::Number { min: RAILS_MIN, max: RAILS_MAX, default: 3 },
            CipherType::Vigenere => KeyKind::Letters { max: VIGENERE_MAX },
            CipherType::Substitution => KeyKind::Letters { max: 26 },
            CipherType::Rot13 | CipherType::Atbash => KeyKind::None,
        }
    }

    pub fn key_hint(self) -> &'static str {
        match self {
            CipherType::Caesar => "Shift (1-25)",
            CipherType::Rot13 | CipherType::Atbash => "(no key)",
            CipherType::Vigenere => "Keyword: letters A-Z, up to 30",
            CipherType::Substitution => "All 26 letters, each once, in any order",
            CipherType::RailFence => "Rails (2-10)",
        }
    }
}

/// Why a key was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    Empty,
    /// The key contains this non-letter.
    NotALetter(char),
    /// Substitution alphabet has this many letters instead of 26.
    WrongLength(usize),
    /// Substitution alphabet uses this letter twice.
    Duplicate(char),
    /// Number outside the cipher's range.
    OutOfRange,
    /// A key was given for the wrong cipher.
    WrongKind,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Empty => write!(f, "Key is empty"),
            KeyError::NotALetter(c) => write!(f, "Only letters A-Z allowed (not {c:?})"),
            KeyError::WrongLength(n) => write!(f, "Need all 26 letters (have {n})"),
            KeyError::Duplicate(c) => write!(f, "Letter {c} is used twice"),
            KeyError::OutOfRange => write!(f, "Number out of range"),
            KeyError::WrongKind => write!(f, "Wrong key for this cipher"),
        }
    }
}

/// A validated key, ready to use.
#[derive(Clone, PartialEq, Eq)]
pub enum CipherKey {
    Caesar(u8),
    Rot13,
    Atbash,
    /// Shifts 0..26, one per key letter.
    Vigenere(Vec<u8>),
    /// `table[i]` is the cipher letter (0..26) for plain letter `i`.
    Substitution([u8; 26]),
    RailFence(usize),
}

/// Keys are user secrets in a teaching sense; `Debug` doesn't print them.
impl fmt::Debug for CipherKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CipherKey::{:?}(<redacted>)", self.cipher())
    }
}

impl Drop for CipherKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        match self {
            CipherKey::Vigenere(v) => v.zeroize(),
            CipherKey::Substitution(t) => t.zeroize(),
            CipherKey::Caesar(s) => s.zeroize(),
            CipherKey::RailFence(r) => r.zeroize(),
            CipherKey::Rot13 | CipherKey::Atbash => {}
        }
    }
}

fn letter_index(c: char) -> Option<u8> {
    match c {
        'A'..='Z' => Some(c as u8 - b'A'),
        'a'..='z' => Some(c as u8 - b'a'),
        _ => None,
    }
}

/// Map a letter through `f` (on its 0..26 index), keeping case. Non-letters unchanged.
fn map_letter(c: char, f: impl FnOnce(u8) -> u8) -> char {
    match c {
        'A'..='Z' => (b'A' + f(c as u8 - b'A') % 26) as char,
        'a'..='z' => (b'a' + f(c as u8 - b'a') % 26) as char,
        _ => c,
    }
}

/// Uppercase `s`, requiring every character to be a letter.
fn letters_only(s: &str) -> Result<Vec<u8>, KeyError> {
    if s.is_empty() {
        return Err(KeyError::Empty);
    }
    s.chars().map(|c| letter_index(c).ok_or(KeyError::NotALetter(c))).collect()
}

impl CipherKey {
    /// Build a key for `cipher` from what the user entered: `number` for
    /// numeric keys, `text` for letter keys. The unused one is ignored.
    pub fn new(cipher: CipherType, number: u8, text: &str) -> Result<CipherKey, KeyError> {
        match cipher {
            CipherType::Caesar => CipherKey::caesar(number),
            CipherType::Rot13 => Ok(CipherKey::Rot13),
            CipherType::Atbash => Ok(CipherKey::Atbash),
            CipherType::Vigenere => CipherKey::vigenere(text),
            CipherType::Substitution => CipherKey::substitution(text),
            CipherType::RailFence => CipherKey::rail_fence(number as usize),
        }
    }

    pub fn caesar(shift: u8) -> Result<CipherKey, KeyError> {
        if (CAESAR_MIN..=CAESAR_MAX).contains(&shift) {
            Ok(CipherKey::Caesar(shift))
        } else {
            Err(KeyError::OutOfRange)
        }
    }

    /// Keyword of letters only (any case).
    pub fn vigenere(key: &str) -> Result<CipherKey, KeyError> {
        let k = letters_only(key)?;
        if k.len() > VIGENERE_MAX {
            return Err(KeyError::OutOfRange);
        }
        Ok(CipherKey::Vigenere(k))
    }

    /// Exactly 26 distinct letters (any case). The i-th letter is what plain
    /// letter `A + i` becomes.
    pub fn substitution(alphabet: &str) -> Result<CipherKey, KeyError> {
        let k = letters_only(alphabet)?;
        if k.len() != 26 {
            return Err(KeyError::WrongLength(k.len()));
        }
        let mut seen = [false; 26];
        let mut table = [0u8; 26];
        for (i, &v) in k.iter().enumerate() {
            if seen[v as usize] {
                return Err(KeyError::Duplicate((b'A' + v) as char));
            }
            seen[v as usize] = true;
            table[i] = v;
        }
        Ok(CipherKey::Substitution(table))
    }

    /// 2 or more rails. (The app limits entry to 2-10.)
    pub fn rail_fence(rails: usize) -> Result<CipherKey, KeyError> {
        if rails >= 2 {
            Ok(CipherKey::RailFence(rails))
        } else {
            Err(KeyError::OutOfRange)
        }
    }

    pub fn cipher(&self) -> CipherType {
        match self {
            CipherKey::Caesar(_) => CipherType::Caesar,
            CipherKey::Rot13 => CipherType::Rot13,
            CipherKey::Atbash => CipherType::Atbash,
            CipherKey::Vigenere(_) => CipherType::Vigenere,
            CipherKey::Substitution(_) => CipherType::Substitution,
            CipherKey::RailFence(_) => CipherType::RailFence,
        }
    }

    /// Human-readable key, e.g. `shift=3`, `key=LEMON`.
    pub fn describe(&self) -> String {
        match self {
            CipherKey::Caesar(s) => format!("shift={s}"),
            CipherKey::Rot13 | CipherKey::Atbash => String::from("(none)"),
            CipherKey::Vigenere(k) => format!("key={}", k.iter().map(|&v| (b'A' + v) as char).collect::<String>()),
            CipherKey::Substitution(t) => {
                format!("alphabet={}", t.iter().map(|&v| (b'A' + v) as char).collect::<String>())
            }
            CipherKey::RailFence(r) => format!("rails={r}"),
        }
    }

    pub fn encrypt(&self, text: &str) -> String {
        match self {
            CipherKey::Caesar(s) => shift_all(text, *s),
            CipherKey::Rot13 => shift_all(text, 13),
            CipherKey::Atbash => atbash(text),
            CipherKey::Vigenere(k) => vigenere(text, k, false),
            CipherKey::Substitution(t) => substitute(text, t),
            CipherKey::RailFence(r) => rail_fence_encrypt(text, *r),
        }
    }

    pub fn decrypt(&self, text: &str) -> String {
        match self {
            CipherKey::Caesar(s) => shift_all(text, 26 - s % 26),
            CipherKey::Rot13 => shift_all(text, 13),
            CipherKey::Atbash => atbash(text),
            CipherKey::Vigenere(k) => vigenere(text, k, true),
            CipherKey::Substitution(t) => {
                let mut inv = [0u8; 26];
                for (i, &v) in t.iter().enumerate() {
                    inv[v as usize] = i as u8;
                }
                substitute(text, &inv)
            }
            CipherKey::RailFence(r) => rail_fence_decrypt(text, *r),
        }
    }
}

fn shift_all(text: &str, shift: u8) -> String { text.chars().map(|c| map_letter(c, |i| i + shift % 26)).collect() }

fn atbash(text: &str) -> String { text.chars().map(|c| map_letter(c, |i| 25 - i)).collect() }

/// The key advances only on letters, as in the standard description.
fn vigenere(text: &str, key: &[u8], decrypt: bool) -> String {
    let mut ki = 0;
    text.chars()
        .map(|c| {
            if letter_index(c).is_none() {
                return c;
            }
            let k = key[ki % key.len()];
            ki += 1;
            let k = if decrypt { 26 - k } else { k };
            map_letter(c, |i| i + k)
        })
        .collect()
}

fn substitute(text: &str, table: &[u8; 26]) -> String {
    text.chars().map(|c| map_letter(c, |i| table[i as usize])).collect()
}

/// The rail (row) of each position in a zigzag over `rails` rows.
fn zigzag(n: usize, rails: usize) -> impl Iterator<Item = usize> {
    let cycle = 2 * (rails - 1);
    (0..n).map(move |i| {
        let p = i % cycle;
        if p < rails {
            p
        } else {
            cycle - p
        }
    })
}

fn rail_fence_encrypt(text: &str, rails: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let rows: Vec<usize> = zigzag(chars.len(), rails).collect();
    let mut out = String::with_capacity(text.len());
    for r in 0..rails {
        out.extend(chars.iter().zip(&rows).filter(|(_, &row)| row == r).map(|(&c, _)| c));
    }
    out
}

fn rail_fence_decrypt(text: &str, rails: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let rows: Vec<usize> = zigzag(n, rails).collect();
    // Positions in the order the ciphertext lists them: all of row 0, then row 1, ...
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|&i| rows[i]); // stable: keeps position order within a row
    let mut out = vec!['\0'; n];
    for (&pos, &c) in order.iter().zip(&chars) {
        out[pos] = c;
    }
    out.into_iter().collect()
}

/// Letter counts A..Z (case-insensitive).
pub fn frequencies(text: &str) -> [u32; 26] {
    let mut counts = [0u32; 26];
    for i in text.chars().filter_map(letter_index) {
        counts[i as usize] += 1;
    }
    counts
}

/// The most frequent letter (first in alphabet order on ties), if any letters.
pub fn most_common(counts: &[u32; 26]) -> Option<char> {
    let (i, &c) = counts.iter().enumerate().rev().max_by_key(|&(_, c)| *c)?;
    (c > 0).then_some((b'A' + i as u8) as char)
}

/// The Caesar shift that would turn `E` into the most common letter: the
/// classic first guess when breaking a Caesar cipher by frequency.
pub fn caesar_guess(counts: &[u32; 26]) -> Option<u8> {
    let top = most_common(counts)? as u8 - b'A';
    Some((top + 26 - 4) % 26)
}

/// One bar-chart row: `E:  12 ######`.
pub fn frequency_bar(letter: char, count: u32, max_count: u32, bar_width: usize) -> String {
    let w = if max_count > 0 { (count as usize * bar_width) / max_count as usize } else { 0 };
    format!("{}: {:>3} {}", letter, count, "#".repeat(w))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(k: &CipherKey, s: &str) -> String { k.encrypt(s) }

    // ---- Known vectors from standard references ----

    #[test]
    fn caesar_vector() {
        // The classic shift-3 pangram (e.g. Wikipedia "Caesar cipher").
        let k = CipherKey::caesar(3).unwrap();
        let p = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG";
        let c = "WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ";
        assert_eq!(enc(&k, p), c);
        assert_eq!(k.decrypt(c), p);
        // Case is kept, punctuation passes through.
        assert_eq!(enc(&k, "xyz, Abc!"), "abc, Def!");
    }

    #[test]
    fn rot13_vector() {
        let k = CipherKey::Rot13;
        assert_eq!(enc(&k, "Why did the chicken cross the road?"), "Jul qvq gur puvpxra pebff gur ebnq?");
        assert_eq!(k.decrypt("Jul qvq gur puvpxra pebff gur ebnq?"), "Why did the chicken cross the road?");
    }

    #[test]
    fn atbash_vector() {
        let k = CipherKey::Atbash;
        assert_eq!(enc(&k, "WIZARD"), "DRAZIW");
        assert_eq!(enc(&k, "Abc xyz"), "Zyx cba");
        assert_eq!(enc(&k, &enc(&k, "Hello, World")), "Hello, World");
    }

    #[test]
    fn vigenere_vector() {
        // Wikipedia "Vigenère cipher": ATTACKATDAWN / LEMON.
        let k = CipherKey::vigenere("LEMON").unwrap();
        assert_eq!(enc(&k, "ATTACKATDAWN"), "LXFOPVEFRNHR");
        assert_eq!(k.decrypt("LXFOPVEFRNHR"), "ATTACKATDAWN");
        // The key only advances on letters; lowercase key is fine.
        let k = CipherKey::vigenere("lemon").unwrap();
        assert_eq!(enc(&k, "attack at dawn!"), "lxfopv ef rnhr!");
    }

    #[test]
    fn substitution_vector() {
        // Wikipedia "Substitution cipher": keyword ZEBRAS.
        let k = CipherKey::substitution("ZEBRASCDFGHIJKLMNOPQTUVWXY").unwrap();
        assert_eq!(enc(&k, "FLEE AT ONCE. WE ARE DISCOVERED!"), "SIAA ZQ LKBA. VA ZOA RFPBLUAOAR!");
        assert_eq!(k.decrypt("SIAA ZQ LKBA. VA ZOA RFPBLUAOAR!"), "FLEE AT ONCE. WE ARE DISCOVERED!");
        assert_eq!(enc(&k, "flee"), "siaa");
    }

    #[test]
    fn rail_fence_vector() {
        // Wikipedia "Rail fence cipher", 3 rails.
        let k = CipherKey::rail_fence(3).unwrap();
        assert_eq!(enc(&k, "WEAREDISCOVEREDFLEEATONCE"), "WECRLTEERDSOEEFEAOCAIVDEN");
        assert_eq!(k.decrypt("WECRLTEERDSOEEFEAOCAIVDEN"), "WEAREDISCOVEREDFLEEATONCE");
        // 2 rails: even positions then odd.
        assert_eq!(enc(&CipherKey::rail_fence(2).unwrap(), "ABCDEF"), "ACEBDF");
    }

    // ---- Round trips ----

    #[test]
    fn every_cipher_round_trips() {
        let texts = ["", "A", "Hello, World! 123", "the quick brown fox jumps over the lazy dog", "ÅSCII? ñ ok"];
        let mut keys = vec![CipherKey::Rot13, CipherKey::Atbash];
        keys.extend((1..=25).map(|s| CipherKey::caesar(s).unwrap()));
        keys.extend((2..=12).map(|r| CipherKey::rail_fence(r).unwrap()));
        keys.push(CipherKey::vigenere("K").unwrap());
        keys.push(CipherKey::vigenere("Zebra").unwrap());
        keys.push(CipherKey::substitution("QWERTYUIOPASDFGHJKLZXCVBNM").unwrap());
        for k in &keys {
            for t in texts {
                assert_eq!(k.decrypt(&k.encrypt(t)), t, "{:?} on {:?}", k.describe(), t);
            }
        }
    }

    #[test]
    fn rail_fence_more_rails_than_text() {
        let k = CipherKey::rail_fence(10).unwrap();
        assert_eq!(enc(&k, "abc"), "abc");
        assert_eq!(k.decrypt("abc"), "abc");
    }

    // ---- Regressions for the audit's key-validation bugs ----

    #[test]
    fn vigenere_rejects_non_letters_instead_of_underflowing() {
        // Regression: `to_upper(c) as u8 - b'A'` underflowed for "my key"/"k3y".
        assert_eq!(CipherKey::vigenere("my key"), Err(KeyError::NotALetter(' ')));
        assert_eq!(CipherKey::vigenere("k3y"), Err(KeyError::NotALetter('3')));
        assert_eq!(CipherKey::vigenere(""), Err(KeyError::Empty));
        assert_eq!(CipherKey::vigenere(&"A".repeat(31)), Err(KeyError::OutOfRange));
    }

    #[test]
    fn substitution_requires_exactly_26() {
        // Regression: a short alphabet returned the plaintext as "ciphertext".
        assert_eq!(CipherKey::substitution("QWERTYUIOP"), Err(KeyError::WrongLength(10)));
        assert_eq!(CipherKey::substitution(&"AB".repeat(14)), Err(KeyError::WrongLength(28)));
    }

    #[test]
    fn substitution_requires_a_permutation() {
        // Regression: duplicates left letters without a preimage (decrypted to NUL).
        assert_eq!(CipherKey::substitution("AACDEFGHIJKLMNOPQRSTUVWXYZ"), Err(KeyError::Duplicate('A')));
        assert_eq!(CipherKey::substitution("ABCDEFGHIJKLMNOPQRSTUVWXY!"), Err(KeyError::NotALetter('!')));
        // Case-insensitive duplicate.
        assert_eq!(CipherKey::substitution("aBCDEFGHIJKLMNOPQRSTUVWXYA"), Err(KeyError::Duplicate('A')));
    }

    #[test]
    fn numeric_ranges() {
        assert_eq!(CipherKey::caesar(0), Err(KeyError::OutOfRange));
        assert_eq!(CipherKey::caesar(26), Err(KeyError::OutOfRange));
        assert_eq!(CipherKey::rail_fence(1), Err(KeyError::OutOfRange));
        assert!(CipherKey::new(CipherType::Caesar, 25, "").is_ok());
        assert!(CipherKey::new(CipherType::Atbash, 0, "ignored").is_ok());
    }

    #[test]
    fn debug_hides_key() {
        let k = CipherKey::vigenere("SECRETWORD").unwrap();
        let s = format!("{k:?}");
        assert!(!s.contains("SECRET"), "{}", s);
        assert!(s.contains("Vigenere"));
    }

    #[test]
    fn describe_keys() {
        assert_eq!(CipherKey::caesar(7).unwrap().describe(), "shift=7");
        assert_eq!(CipherKey::vigenere("lemon").unwrap().describe(), "key=LEMON");
        assert_eq!(CipherKey::rail_fence(4).unwrap().describe(), "rails=4");
        assert_eq!(CipherKey::Rot13.describe(), "(none)");
    }

    #[test]
    fn every_cipher_has_text() {
        for c in CipherType::ALL {
            assert!(!c.label().is_empty() && !c.description().is_empty() && !c.weakness().is_empty());
            assert!(!c.key_hint().is_empty());
        }
    }

    // ---- Frequency analysis ----

    #[test]
    fn frequency_counts_case_insensitive() {
        let f = frequencies("Hello, World");
        assert_eq!(f[(b'L' - b'A') as usize], 3);
        assert_eq!(f[(b'H' - b'A') as usize], 1);
        assert_eq!(f.iter().sum::<u32>(), 10);
        assert_eq!(most_common(&f), Some('L'));
        assert_eq!(most_common(&frequencies("123")), None);
    }

    #[test]
    fn caesar_guess_breaks_a_shift() {
        let plain = "meet me near the tree at eleven these evenings";
        let c = CipherKey::caesar(7).unwrap().encrypt(plain);
        assert_eq!(caesar_guess(&frequencies(&c)), Some(7));
    }

    #[test]
    fn bar_scales() {
        assert_eq!(frequency_bar('E', 10, 10, 5), "E:  10 #####");
        assert_eq!(frequency_bar('Q', 0, 0, 5), "Q:   0 ");
        assert_eq!(frequency_bar('T', 5, 10, 4), "T:   5 ##");
    }
}
