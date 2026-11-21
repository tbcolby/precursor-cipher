//! Pure logic for Cipher Workshop: classical ciphers with validated keys,
//! frequency analysis, the saved-message format, and the screen state
//! machine. No Xous dependencies; everything here is unit-tested on the host.
//!
//! These ciphers are for learning. None of them protects anything.

pub mod ciphers;
pub mod entropy;
pub mod record;
pub mod ui;

pub use ciphers::{CipherKey, CipherType, KeyError, KeyKind};
pub use entropy::{Entropy, EntropyError};
pub use record::Record;
pub use ui::{Effect, Input, Mode, Saved, Screen, Ui};
