//! State machine for Cipher Workshop.
//!
//! States:
//!   CipherSelect — choose which cipher to use
//!   Input        — type plaintext/ciphertext
//!   KeyEntry     — enter cipher key/parameter
//!   Output       — view encrypted/decrypted result
//!   Frequency    — letter frequency analysis
//!   Saved        — view saved messages

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

use crate::ciphers::*;
use crate::storage::{SavedMessage, Storage};

const KEY_UP: char = '\u{F700}';
const KEY_DOWN: char = '\u{F701}';
const KEY_LEFT: char = '\u{F702}';
const KEY_RIGHT: char = '\u{F703}';
const KEY_ENTER: char = '\u{000D}';
const KEY_BACKSPACE: char = '\u{0008}';
const KEY_MENU: char = '\u{2234}';

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppState {
    CipherSelect,
    Input,
    KeyEntry,
    Output,
    Frequency,
    Saved,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

pub struct CipherApp {
    pub state: AppState,
    pub needs_redraw: bool,

    // Cipher selection
    pub cipher_cursor: usize,
    pub selected_cipher: CipherType,

    // Mode
    pub mode: Mode,

    // Input text
    pub input_text: String,

    // Key/parameter
    pub key_text: String,
    pub caesar_shift: u8,
    pub rail_count: usize,

    // Output
    pub output_text: String,

    // Frequency analysis
    pub freq_data: [(char, u32); 26],
    pub freq_scroll: usize,

    // Saved messages
    pub saved: Vec<SavedMessage>,
    pub saved_cursor: usize,

    // Storage
    storage: Option<Storage>,
}

impl CipherApp {
    pub fn new() -> Self {
        Self {
            state: AppState::CipherSelect,
            needs_redraw: true,
            cipher_cursor: 0,
            selected_cipher: CipherType::Caesar,
            mode: Mode::Encrypt,
            input_text: String::new(),
            key_text: String::new(),
            caesar_shift: 3,
            rail_count: 3,
            output_text: String::new(),
            freq_data: [(' ', 0); 26],
            freq_scroll: 0,
            saved: Vec::new(),
            saved_cursor: 0,
            storage: None,
        }
    }

    pub fn init_storage(&mut self) {
        if let Ok(mut st) = Storage::new() {
            self.saved = st.load_saved();
            self.storage = Some(st);
        }
    }

    pub fn save_state(&mut self) {
        if let Some(ref mut st) = self.storage {
            st.save_messages(&self.saved);
        }
    }

    fn run_cipher(&mut self) {
        self.output_text = match (self.selected_cipher, self.mode) {
            (CipherType::Caesar, Mode::Encrypt) => {
                caesar_encrypt(&self.input_text, self.caesar_shift)
            }
            (CipherType::Caesar, Mode::Decrypt) => {
                caesar_decrypt(&self.input_text, self.caesar_shift)
            }
            (CipherType::Rot13, _) => rot13(&self.input_text),
            (CipherType::Atbash, _) => atbash(&self.input_text),
            (CipherType::Vigenere, Mode::Encrypt) => {
                vigenere_encrypt(&self.input_text, &self.key_text)
            }
            (CipherType::Vigenere, Mode::Decrypt) => {
                vigenere_decrypt(&self.input_text, &self.key_text)
            }
            (CipherType::Substitution, Mode::Encrypt) => {
                substitution_encrypt(&self.input_text, &self.key_text)
            }
            (CipherType::Substitution, Mode::Decrypt) => {
                substitution_decrypt(&self.input_text, &self.key_text)
            }
            (CipherType::RailFence, Mode::Encrypt) => {
                rail_fence_encrypt(&self.input_text, self.rail_count)
            }
            (CipherType::RailFence, Mode::Decrypt) => {
                rail_fence_decrypt(&self.input_text, self.rail_count)
            }
        };
    }

    fn save_current(&mut self) {
        let (plain, cipher) = match self.mode {
            Mode::Encrypt => (self.input_text.clone(), self.output_text.clone()),
            Mode::Decrypt => (self.output_text.clone(), self.input_text.clone()),
        };
        let key_info = match self.selected_cipher {
            CipherType::Caesar => format!("shift={}", self.caesar_shift),
            CipherType::Rot13 => String::from("(none)"),
            CipherType::Atbash => String::from("(none)"),
            CipherType::Vigenere => format!("key={}", self.key_text),
            CipherType::Substitution => format!("alpha={}", self.key_text),
            CipherType::RailFence => format!("rails={}", self.rail_count),
        };
        let msg = SavedMessage {
            cipher_name: String::from(self.selected_cipher.label()),
            key_info,
            plaintext: plain,
            ciphertext: cipher,
        };
        self.saved.push(msg);
        self.save_state();
    }

    pub fn handle_key(&mut self, key: char) -> bool {
        self.needs_redraw = true;
        match self.state {
            AppState::CipherSelect => self.handle_cipher_select(key),
            AppState::Input => self.handle_input(key),
            AppState::KeyEntry => self.handle_key_entry(key),
            AppState::Output => self.handle_output(key),
            AppState::Frequency => self.handle_frequency(key),
            AppState::Saved => self.handle_saved(key),
        }
    }

    fn handle_cipher_select(&mut self, key: char) -> bool {
        let ciphers = CipherType::all();
        match key {
            KEY_MENU => return false,
            KEY_UP => {
                if self.cipher_cursor > 0 {
                    self.cipher_cursor -= 1;
                }
            }
            KEY_DOWN => {
                if self.cipher_cursor < ciphers.len() - 1 {
                    self.cipher_cursor += 1;
                }
            }
            KEY_ENTER => {
                self.selected_cipher = ciphers[self.cipher_cursor];
                self.input_text.clear();
                self.state = AppState::Input;
            }
            'm' | 'M' => {
                self.mode = match self.mode {
                    Mode::Encrypt => Mode::Decrypt,
                    Mode::Decrypt => Mode::Encrypt,
                };
            }
            's' | 'S' => {
                self.saved_cursor = 0;
                self.state = AppState::Saved;
            }
            _ => {}
        }
        true
    }

    fn handle_input(&mut self, key: char) -> bool {
        match key {
            KEY_MENU => {
                self.state = AppState::CipherSelect;
            }
            KEY_BACKSPACE => {
                self.input_text.pop();
            }
            KEY_ENTER => {
                if !self.input_text.is_empty() {
                    if self.selected_cipher.needs_key() {
                        self.key_text.clear();
                        self.state = AppState::KeyEntry;
                    } else {
                        self.run_cipher();
                        self.state = AppState::Output;
                    }
                }
            }
            c if c >= ' ' && c <= '~' => {
                if self.input_text.len() < 200 {
                    self.input_text.push(c);
                }
            }
            _ => {}
        }
        true
    }

    fn handle_key_entry(&mut self, key: char) -> bool {
        match self.selected_cipher {
            CipherType::Caesar => match key {
                KEY_MENU => {
                    self.state = AppState::Input;
                }
                KEY_LEFT => {
                    if self.caesar_shift > 1 {
                        self.caesar_shift -= 1;
                    } else {
                        self.caesar_shift = 25;
                    }
                }
                KEY_RIGHT => {
                    if self.caesar_shift < 25 {
                        self.caesar_shift += 1;
                    } else {
                        self.caesar_shift = 1;
                    }
                }
                KEY_ENTER => {
                    self.run_cipher();
                    self.state = AppState::Output;
                }
                c @ '0'..='9' => {
                    let digit = c as u8 - b'0';
                    let new_val = self.caesar_shift.wrapping_mul(10).wrapping_add(digit);
                    if new_val >= 1 && new_val <= 25 {
                        self.caesar_shift = new_val;
                    }
                }
                _ => {}
            },
            CipherType::RailFence => match key {
                KEY_MENU => {
                    self.state = AppState::Input;
                }
                KEY_LEFT => {
                    if self.rail_count > 2 {
                        self.rail_count -= 1;
                    }
                }
                KEY_RIGHT => {
                    if self.rail_count < 10 {
                        self.rail_count += 1;
                    }
                }
                KEY_ENTER => {
                    self.run_cipher();
                    self.state = AppState::Output;
                }
                _ => {}
            },
            _ => match key {
                KEY_MENU => {
                    self.state = AppState::Input;
                }
                KEY_BACKSPACE => {
                    self.key_text.pop();
                }
                KEY_ENTER => {
                    if !self.key_text.is_empty() {
                        self.run_cipher();
                        self.state = AppState::Output;
                    }
                }
                c if c >= ' ' && c <= '~' => {
                    let max_len = if self.selected_cipher == CipherType::Substitution {
                        26
                    } else {
                        30
                    };
                    if self.key_text.len() < max_len {
                        self.key_text.push(c);
                    }
                }
                _ => {}
            },
        }
        true
    }

    fn handle_output(&mut self, key: char) -> bool {
        match key {
            KEY_MENU | KEY_LEFT => {
                self.state = AppState::CipherSelect;
            }
            'f' | 'F' => {
                self.freq_data = frequency_analysis(&self.output_text);
                self.freq_scroll = 0;
                self.state = AppState::Frequency;
            }
            's' | 'S' => {
                self.save_current();
            }
            'r' | 'R' => {
                // Reverse: use output as new input
                self.input_text = self.output_text.clone();
                self.mode = match self.mode {
                    Mode::Encrypt => Mode::Decrypt,
                    Mode::Decrypt => Mode::Encrypt,
                };
                self.run_cipher();
            }
            _ => {}
        }
        true
    }

    fn handle_frequency(&mut self, key: char) -> bool {
        match key {
            KEY_MENU | KEY_LEFT | KEY_ENTER => {
                self.state = AppState::Output;
            }
            KEY_UP => {
                if self.freq_scroll > 0 {
                    self.freq_scroll -= 1;
                }
            }
            KEY_DOWN => {
                if self.freq_scroll < 12 {
                    self.freq_scroll += 1;
                }
            }
            _ => {}
        }
        true
    }

    fn handle_saved(&mut self, key: char) -> bool {
        match key {
            KEY_MENU | KEY_LEFT => {
                self.state = AppState::CipherSelect;
            }
            KEY_UP => {
                if self.saved_cursor > 0 {
                    self.saved_cursor -= 1;
                }
            }
            KEY_DOWN => {
                if self.saved_cursor < self.saved.len().saturating_sub(1) {
                    self.saved_cursor += 1;
                }
            }
            'd' | 'D' => {
                if self.saved_cursor < self.saved.len() {
                    self.saved.remove(self.saved_cursor);
                    if self.saved_cursor > 0 && self.saved_cursor >= self.saved.len() {
                        self.saved_cursor = self.saved.len().saturating_sub(1);
                    }
                    self.save_state();
                }
            }
            _ => {}
        }
        true
    }
}
