//! Saved messages. Each one is its own PDDB key (`m.<16 hex>`), so deleting a
//! message deletes its PDDB key and a message lives in exactly one basis.
//!
//! A record holds the plaintext, the ciphertext and the key together. That is
//! fine for a teaching tool and the README says so: the classical cipher adds
//! no protection; only PDDB encryption does.

use core::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::ciphers::CipherType;
use crate::entropy::{Entropy, EntropyError};

/// Bump when the format changes. Records with a newer version are counted as
/// unreadable and never rewritten.
pub const RECORD_VERSION: u32 = 1;
pub const KEY_PREFIX: &str = "m.";

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    pub version: u32,
    /// Ordering only (largest existing + 1); collisions are harmless.
    pub seq: u64,
    pub cipher: CipherType,
    /// e.g. `shift=3`, `key=LEMON`.
    pub key_info: String,
    pub plaintext: String,
    pub ciphertext: String,
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Record {{ seq: {}, cipher: {:?}, <{} plaintext chars, key redacted> }}",
            self.seq,
            self.cipher,
            self.plaintext.chars().count()
        )
    }
}

impl Drop for Record {
    fn drop(&mut self) {
        self.key_info.zeroize();
        self.plaintext.zeroize();
        self.ciphertext.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    Unparsable,
    NewerVersion(u32),
}

impl Record {
    /// Parse stored bytes. The caller wipes `bytes` afterwards.
    pub fn parse(bytes: &[u8]) -> Result<Record, RecordError> {
        #[derive(Deserialize)]
        struct V {
            version: u32,
        }
        let v: V = serde_json::from_slice(bytes).map_err(|_| RecordError::Unparsable)?;
        if v.version > RECORD_VERSION {
            return Err(RecordError::NewerVersion(v.version));
        }
        serde_json::from_slice(bytes).map_err(|_| RecordError::Unparsable)
    }

    /// One line for the saved list: cipher and the start of the plaintext.
    pub fn title(&self, max_chars: usize) -> String {
        let mut s = format!("[{}] ", self.cipher.label());
        let n = self.plaintext.chars().count();
        s.extend(self.plaintext.chars().take(max_chars));
        if n > max_chars {
            s.push('…');
        }
        s
    }
}

/// True for PDDB key names this app wrote.
pub fn is_record_key(name: &str) -> bool {
    name.len() == KEY_PREFIX.len() + 16
        && name.starts_with(KEY_PREFIX)
        && name[KEY_PREFIX.len()..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// A fresh random key name. Random rather than a counter, so it can't collide
/// with a record in a basis that is currently locked, and there is no
/// separately stored counter to lose.
pub fn new_key<E: Entropy + ?Sized>(e: &mut E) -> Result<String, EntropyError> {
    let hi = e.try_u32()?;
    let lo = e.try_u32()?;
    Ok(format!("{KEY_PREFIX}{hi:08x}{lo:08x}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::testing::*;

    fn sample() -> Record {
        Record {
            version: RECORD_VERSION,
            seq: 2,
            cipher: CipherType::Vigenere,
            key_info: "key=LEMON".into(),
            plaintext: "ATTACKATDAWN".into(),
            ciphertext: "LXFOPVEFRNHR".into(),
        }
    }

    #[test]
    fn roundtrip() {
        let j = serde_json::to_vec(&sample()).unwrap();
        assert_eq!(Record::parse(&j).unwrap(), sample());
    }

    #[test]
    fn debug_does_not_leak() {
        let s = format!("{:?}", sample());
        assert!(!s.contains("ATTACK") && !s.contains("LEMON") && !s.contains("LXFO"), "{}", s);
    }

    #[test]
    fn newer_version_is_refused() {
        assert_eq!(Record::parse(br#"{"version":7}"#).unwrap_err(), RecordError::NewerVersion(7));
    }

    #[test]
    fn corrupt_is_unparsable_not_empty() {
        // Regression: a parse failure used to load as an empty list, and the
        // next save overwrote everything.
        assert_eq!(Record::parse(b"{\"version\":1,").unwrap_err(), RecordError::Unparsable);
        // Stale tail from an in-place shorter rewrite (the old set_len call).
        let mut j = serde_json::to_vec(&sample()).unwrap();
        j.extend_from_slice(b"WN\"}");
        assert_eq!(Record::parse(&j).unwrap_err(), RecordError::Unparsable);
    }

    #[test]
    fn keys() {
        let k = new_key(&mut Seq(vec![0xdead_beef, 1], 0)).unwrap();
        assert_eq!(k, "m.deadbeef00000001");
        assert!(is_record_key(&k));
        assert!(!is_record_key("saved_messages"));
        assert!(!is_record_key("m.xyz"));
        assert!(new_key(&mut Broken).is_err());
    }

    #[test]
    fn title_truncates_by_chars() {
        assert_eq!(sample().title(6), "[Vigenere] ATTACK…");
        assert_eq!(sample().title(40), "[Vigenere] ATTACKATDAWN");
    }
}
