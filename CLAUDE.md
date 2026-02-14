# Cipher Workshop — Build Notes

## Architecture
- 6-state machine: CipherSelect, Input, KeyEntry, Output, Frequency, Saved
- 6 cipher implementations: Caesar, ROT13, Atbash, Vigenere, Substitution, Rail Fence
- All ciphers operate on ASCII, non-alpha chars passed through
- Frequency analysis with bar chart display

## Key Patterns
**Cipher module** — pure functions, no Xous dependencies
**Key entry branching** — KeyEntry state handles numeric (Caesar/RailFence) vs text (Vigenere/Substitution) keys differently
**Reverse operation** — output becomes input with mode flipped
**Wrapped text display** — draw_wrapped helper splits long text across lines

## Build
```bash
cargo build -p cipher --target riscv32imac-unknown-xous-elf
```
