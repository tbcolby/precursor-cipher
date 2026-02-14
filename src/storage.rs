//! PDDB storage for Cipher Workshop.
//!
//! Dictionary: cipher.data
//! Keys: saved_messages — JSON array of saved encrypted/decrypted pairs

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

const DICT: &str = "cipher.data";
const KEY_SAVED: &str = "saved_messages";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedMessage {
    pub cipher_name: String,
    pub key_info: String,
    pub plaintext: String,
    pub ciphertext: String,
}

pub struct Storage {
    pddb: pddb::Pddb,
}

impl Storage {
    pub fn new() -> Result<Self, ()> {
        let pddb = pddb::Pddb::new();
        pddb.is_mounted_blocking();
        Ok(Self { pddb })
    }

    fn read_key(&mut self, key: &str) -> Option<Vec<u8>> {
        let mut handle = self
            .pddb
            .get(DICT, key, None, false, false, None, None::<fn()>)
            .ok()?;
        let mut buf = Vec::new();
        use std::io::Read;
        handle.read_to_end(&mut buf).ok()?;
        if buf.is_empty() {
            None
        } else {
            Some(buf)
        }
    }

    fn write_key(&mut self, key: &str, data: &[u8]) {
        if let Ok(mut handle) = self.pddb.get(
            DICT, key, None, true, true, Some(data.len()), None::<fn()>,
        ) {
            use std::io::{Seek, Write};
            handle.seek(std::io::SeekFrom::Start(0)).ok();
            handle.write_all(data).ok();
            handle.set_len(data.len() as u64).ok();
        }
        self.pddb.sync().ok();
    }

    pub fn load_saved(&mut self) -> Vec<SavedMessage> {
        self.read_key(KEY_SAVED)
            .and_then(|buf| serde_json::from_slice(&buf).ok())
            .unwrap_or_default()
    }

    pub fn save_messages(&mut self, msgs: &[SavedMessage]) {
        let data = serde_json::to_vec(msgs).unwrap_or_default();
        self.write_key(KEY_SAVED, &data);
    }
}
