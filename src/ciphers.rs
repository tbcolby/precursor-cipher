//! Classic cipher implementations.
//!
//! All ciphers operate on ASCII uppercase A-Z. Non-alpha characters
//! are passed through unchanged. Lowercase is converted to uppercase
//! before processing.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

/// Available cipher types.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CipherType {
    Caesar,
    Rot13,
    Atbash,
    Vigenere,
    Substitution,
    RailFence,
}

impl CipherType {
    pub fn all() -> &'static [CipherType] {
        &[
            CipherType::Caesar,
            CipherType::Rot13,
            CipherType::Atbash,
            CipherType::Vigenere,
            CipherType::Substitution,
            CipherType::RailFence,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            CipherType::Caesar => "Caesar Shift",
            CipherType::Rot13 => "ROT13",
            CipherType::Atbash => "Atbash Mirror",
            CipherType::Vigenere => "Vigenere",
            CipherType::Substitution => "Substitution",
            CipherType::RailFence => "Rail Fence",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            CipherType::Caesar => "Shift each letter by N positions",
            CipherType::Rot13 => "Caesar with shift=13 (self-inverse)",
            CipherType::Atbash => "A<->Z, B<->Y, ... (self-inverse)",
            CipherType::Vigenere => "Polyalphabetic cipher with keyword",
            CipherType::Substitution => "Custom alphabet mapping A-Z",
            CipherType::RailFence => "Zigzag transposition cipher",
        }
    }

    pub fn needs_key(&self) -> bool {
        match self {
            CipherType::Caesar | CipherType::RailFence => true, // numeric key
            CipherType::Vigenere | CipherType::Substitution => true, // text key
            CipherType::Rot13 | CipherType::Atbash => false,
        }
    }

    pub fn key_hint(&self) -> &'static str {
        match self {
            CipherType::Caesar => "Shift (1-25)",
            CipherType::Rot13 => "(no key needed)",
            CipherType::Atbash => "(no key needed)",
            CipherType::Vigenere => "Keyword (A-Z)",
            CipherType::Substitution => "26-letter alphabet",
            CipherType::RailFence => "Rails (2-10)",
        }
    }
}

fn to_upper(c: char) -> char {
    if c >= 'a' && c <= 'z' {
        (c as u8 - b'a' + b'A') as char
    } else {
        c
    }
}

fn is_alpha(c: char) -> bool {
    (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

/// Caesar cipher: shift each letter by `shift` positions.
pub fn caesar_encrypt(text: &str, shift: u8) -> String {
    let s = shift % 26;
    text.chars()
        .map(|c| {
            if is_alpha(c) {
                let base = if c >= 'a' && c <= 'z' { b'a' } else { b'A' };
                let shifted = ((c as u8 - base + s) % 26) + base;
                shifted as char
            } else {
                c
            }
        })
        .collect()
}

pub fn caesar_decrypt(text: &str, shift: u8) -> String {
    let s = shift % 26;
    caesar_encrypt(text, 26 - s)
}

/// ROT13: Caesar with shift=13, self-inverse.
pub fn rot13(text: &str) -> String {
    caesar_encrypt(text, 13)
}

/// Atbash: mirror the alphabet. A<->Z, B<->Y, etc. Self-inverse.
pub fn atbash(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c >= 'A' && c <= 'Z' {
                (b'Z' - (c as u8 - b'A')) as char
            } else if c >= 'a' && c <= 'z' {
                (b'z' - (c as u8 - b'a')) as char
            } else {
                c
            }
        })
        .collect()
}

/// Vigenere cipher: polyalphabetic substitution with keyword.
pub fn vigenere_encrypt(text: &str, key: &str) -> String {
    if key.is_empty() {
        return String::from(text);
    }
    let key_bytes: Vec<u8> = key.chars().map(|c| (to_upper(c) as u8 - b'A')).collect();
    let mut ki = 0;
    text.chars()
        .map(|c| {
            if is_alpha(c) {
                let base = if c >= 'a' && c <= 'z' { b'a' } else { b'A' };
                let shifted = ((c as u8 - base + key_bytes[ki % key_bytes.len()]) % 26) + base;
                ki += 1;
                shifted as char
            } else {
                c
            }
        })
        .collect()
}

pub fn vigenere_decrypt(text: &str, key: &str) -> String {
    if key.is_empty() {
        return String::from(text);
    }
    let key_bytes: Vec<u8> = key
        .chars()
        .map(|c| (26 - (to_upper(c) as u8 - b'A')) % 26)
        .collect();
    let inv_key: String = key_bytes.iter().map(|&b| (b + b'A') as char).collect();
    vigenere_encrypt(text, &inv_key)
}

/// Substitution cipher: remap A-Z using a 26-character alphabet.
pub fn substitution_encrypt(text: &str, alphabet: &str) -> String {
    if alphabet.len() < 26 {
        return String::from(text);
    }
    let alpha: Vec<char> = alphabet.chars().take(26).collect();
    text.chars()
        .map(|c| {
            if c >= 'A' && c <= 'Z' {
                alpha[(c as u8 - b'A') as usize]
            } else if c >= 'a' && c <= 'z' {
                let mapped = alpha[(c as u8 - b'a') as usize];
                // Preserve case
                if mapped >= 'A' && mapped <= 'Z' {
                    (mapped as u8 - b'A' + b'a') as char
                } else {
                    mapped
                }
            } else {
                c
            }
        })
        .collect()
}

pub fn substitution_decrypt(text: &str, alphabet: &str) -> String {
    if alphabet.len() < 26 {
        return String::from(text);
    }
    // Build inverse alphabet
    let alpha: Vec<char> = alphabet.chars().take(26).collect();
    let mut inv = [0u8; 26];
    for (i, &c) in alpha.iter().enumerate() {
        let idx = if c >= 'A' && c <= 'Z' {
            (c as u8 - b'A') as usize
        } else if c >= 'a' && c <= 'z' {
            (c as u8 - b'a') as usize
        } else {
            continue;
        };
        if idx < 26 {
            inv[idx] = i as u8 + b'A';
        }
    }
    let inv_alpha: String = inv.iter().map(|&b| b as char).collect();
    substitution_encrypt(text, &inv_alpha)
}

/// Rail Fence cipher: zigzag transposition.
pub fn rail_fence_encrypt(text: &str, rails: usize) -> String {
    if rails < 2 || text.is_empty() {
        return String::from(text);
    }
    let chars: Vec<char> = text.chars().collect();
    let mut fence: Vec<Vec<char>> = (0..rails).map(|_| Vec::new()).collect();

    let mut rail: usize = 0;
    let mut going_down = true;

    for &c in chars.iter() {
        fence[rail].push(c);
        if rail == 0 {
            going_down = true;
        } else if rail == rails - 1 {
            going_down = false;
        }
        if going_down {
            rail += 1;
        } else {
            rail -= 1;
        }
    }

    fence.into_iter().flat_map(|row| row.into_iter()).collect()
}

pub fn rail_fence_decrypt(text: &str, rails: usize) -> String {
    if rails < 2 || text.is_empty() {
        return String::from(text);
    }
    let n = text.chars().count();
    let chars: Vec<char> = text.chars().collect();

    // Calculate the length of each rail
    let mut rail_lens = alloc::vec![0usize; rails];
    let mut rail: usize = 0;
    let mut going_down = true;
    for _ in 0..n {
        rail_lens[rail] += 1;
        if rail == 0 {
            going_down = true;
        } else if rail == rails - 1 {
            going_down = false;
        }
        if going_down {
            rail += 1;
        } else {
            rail -= 1;
        }
    }

    // Split ciphertext into rails
    let mut fence: Vec<Vec<char>> = Vec::new();
    let mut pos = 0;
    for &len in rail_lens.iter() {
        fence.push(chars[pos..pos + len].to_vec());
        pos += len;
    }

    // Read off in zigzag order
    let mut indices = alloc::vec![0usize; rails];
    let mut result = String::with_capacity(n);
    rail = 0;
    going_down = true;
    for _ in 0..n {
        result.push(fence[rail][indices[rail]]);
        indices[rail] += 1;
        if rail == 0 {
            going_down = true;
        } else if rail == rails - 1 {
            going_down = false;
        }
        if going_down {
            rail += 1;
        } else {
            rail -= 1;
        }
    }

    result
}

/// Frequency analysis of a text (A-Z counts).
pub fn frequency_analysis(text: &str) -> [(char, u32); 26] {
    let mut counts = [0u32; 26];
    for c in text.chars() {
        let upper = to_upper(c);
        if upper >= 'A' && upper <= 'Z' {
            counts[(upper as u8 - b'A') as usize] += 1;
        }
    }
    let mut result = [(' ', 0u32); 26];
    for i in 0..26 {
        result[i] = ((b'A' + i as u8) as char, counts[i]);
    }
    result
}

/// Format frequency as a bar chart string for display.
pub fn frequency_bar(letter: char, count: u32, max_count: u32, bar_width: usize) -> String {
    let w = if max_count > 0 {
        ((count as usize) * bar_width) / (max_count as usize)
    } else {
        0
    };
    let bar: String = (0..w).map(|_| '#').collect();
    format!("{}: {:>3} {}", letter, count, bar)
}
