# precursor-cipher

Interactive cipher workshop for the [Precursor](https://precursor.dev) hardware platform.

## What This Is

A hands-on cryptography tool for learning and using classic ciphers. Encrypt and decrypt messages with six different cipher algorithms, analyze letter frequencies, and save your work — all on a device with no network connection. Your encrypted messages stay on your device, in hardware-encrypted flash.

## Ciphers

| Cipher | Type | Key | Self-Inverse |
|--------|------|-----|:---:|
| Caesar Shift | Monoalphabetic | Shift 1-25 | No |
| ROT13 | Monoalphabetic | (none) | Yes |
| Atbash | Monoalphabetic | (none) | Yes |
| Vigenere | Polyalphabetic | Keyword | No |
| Substitution | Monoalphabetic | 26-letter alphabet | No |
| Rail Fence | Transposition | Rails 2-10 | No |

## Features

- **Encrypt/Decrypt** — toggle between modes with M key
- **Frequency Analysis** — letter distribution bar chart for ciphertext
- **Save Messages** — store encrypted/decrypted pairs in PDDB
- **Reverse** — one-key swap: use output as input with mode flipped
- **Caesar Preview** — live A→? mapping as you adjust shift
- **Wrapped Display** — long messages wrap cleanly on 336px screen

## Controls

| Key | Action |
|-----|--------|
| ↑/↓ | Navigate/scroll |
| ←/→ | Adjust numeric parameters |
| Enter | Confirm/select |
| M | Toggle Encrypt/Decrypt |
| F | Frequency analysis (in output) |
| S | Save message / View saved |
| R | Reverse (swap input/output) |
| Backspace | Delete character |
| Menu (∴) | Back/quit |

## Build

```bash
cargo build -p cipher --target riscv32imac-unknown-xous-elf
```

---

## Development

This app was developed using the methodology described in [xous-dev-toolkit](https://github.com/tbcolby/xous-dev-toolkit) — an LLM-assisted approach to Precursor app development on macOS ARM64.

---

## Author

Made by Tyler Colby — [Colby's Data Movers, LLC](https://colbysdatamovers.com)

Contact: [tyler@colbysdatamovers.com](mailto:tyler@colbysdatamovers.com) | [GitHub Issues](https://github.com/tbcolby/precursor-cipher/issues)

---

## License

Licensed under the Apache License, Version 2.0.

See [LICENSE](LICENSE) for the full text.
