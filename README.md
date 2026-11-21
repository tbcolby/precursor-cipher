# precursor-cipher: Cipher Workshop

A workshop for classical ciphers on the [Precursor](https://precursor.dev): encrypt and decrypt with six historical ciphers, look at letter frequencies, and see why each one breaks.

**These ciphers are for learning. None of them protects anything.** Each is broken by hand or in seconds by a computer, and the app tells you how. If you need to keep a message secret, don't rely on anything in this app.

Package name: `cipher-workshop` (RustCrypto's `cipher` crate is already in the xous-core dependency graph). The repo is still `precursor-cipher`.

## Ciphers

| Cipher | Kind | Key | How it breaks |
|---|---|---|---|
| Caesar shift | monoalphabetic | shift 1–25 | 25 keys to try, or match the commonest letter to E |
| ROT13 | monoalphabetic | none | no key at all |
| Atbash | monoalphabetic | none | no key at all; applying it again undoes it |
| Vigenère | polyalphabetic | keyword, letters A–Z, up to 30 | the key repeats: Kasiski/Friedman find its length, then each column is a Caesar |
| Substitution | monoalphabetic | all 26 letters, each once | letter frequencies and short words survive |
| Rail fence | transposition | rails 2–10 | letters are only reordered; few rail counts to try |

Letters keep their case. Digits, spaces and punctuation pass through unchanged, except in the rail fence, which reorders every character. Each cipher is tested against the worked example from its standard reference (e.g. `ATTACKATDAWN` + `LEMON` → `LXFOPVEFRNHR`; `WEAREDISCOVEREDFLEEATONCE` on 3 rails → `WECRLTEERDSOEEFEAOCAIVDEN`) and round-trips for every key.

Keys are checked before the cipher runs, with a message on screen:
- Vigenère key entry accepts letters only (`my key` or `k3y` used to crash or produce output that wouldn't decrypt).
- A substitution alphabet must have all 26 letters, each once. Typing a letter twice is refused, and the screen lists the letters still needed (a short alphabet used to pass the plaintext through as "ciphertext").
- Shift and rail count are set with the arrows or by typing digits (typing used to be stuck at the default shift of 3).

## Features

- Encrypt or decrypt (M or F1 on the cipher list).
- Each cipher shows a one-line description and its weakness.
- Caesar key screen previews `A→? B→? Z→?`.
- **Frequency analysis** of the ciphertext: a bar for every letter, the most common letter, and the Caesar shift you'd guess if it stands for E.
- **Reverse**: feed the result back in with the mode flipped, to check it decrypts.
- **Save** a result (plaintext, ciphertext, cipher and key) to the PDDB; view it in full later, or delete it.

## Keys

| Screen | Key | Action |
|---|---|---|
| Cipher list | ↑ ↓ | Move |
| | Enter | Pick cipher |
| | M or F1 | Toggle encrypt / decrypt |
| | S or F2 | Saved messages |
| | Backspace / F4 | Leave the app |
| Message | type | Printable ASCII, up to 200 characters |
| | Enter | Next (key screen, or result for ROT13/Atbash) |
| | Backspace | Delete a character; on an empty field, back |
| | F4 | Back to the cipher list |
| Key (number) | ← → ↑ ↓ | Adjust (wraps at the ends) |
| | digits | Type the number |
| | Enter | Run |
| | Backspace / F4 | Back to the message |
| Key (letters) | letters | Type the key |
| | Enter | Run (or show why the key is refused) |
| | Backspace | Delete a letter; on an empty key, back |
| | F4 | Back to the message |
| Result | F or F1 | Frequency analysis |
| | S or F2 | Save |
| | R or F3 | Reverse |
| | Enter / Backspace / F4 | New message (back to the cipher list) |
| Frequency | ↑ ↓ | Scroll (only if all 26 rows don't fit) |
| | Enter / Backspace / F4 | Back to the result |
| Saved list | ↑ ↓, Enter | Move, view in full |
| | D or F3 | Delete (asks Y to confirm) |
| | Backspace / F4 | Back |
| View | D or F3 | Delete |
| | Enter / Backspace / F4 | Back |

The menu key `∴` opens the system menu; the app never sees it.

## Storage

PDDB dictionary `cipher.data`, one key per saved message named `m.<16 random hex>`, holding JSON `{"version":1, "seq", "cipher", "key_info", "plaintext", "ciphertext"}`.

- **A saved message stores the plaintext and the key next to the ciphertext.** That is the point of a workshop, and it means the cipher adds nothing: the only protection is PDDB encryption, and anyone who can unlock the basis can read it.
- New messages go to the most recently unlocked basis, and the confirmation says which basis. An existing key is only rewritten in its own basis.
- When a basis is locked or unlocked the list is reloaded, so messages from a locked basis disappear from memory and screen.
- Record names are random, so there is no counter to lose or collide. If the TRNG fails, the message isn't saved and the app says so.
- A record that can't be parsed, or that a newer version wrote, is counted as "unreadable" and left untouched.
- Delete removes that PDDB key and syncs. The PDDB doesn't overwrite old flash pages immediately, so treat deletion as "gone from the app", not secure erasure.
- Nothing is written except on S (save) and D (delete).

## Limitations

- Classical ciphers only; no modern cryptography, by design.
- Input is printable ASCII (the keyboard's characters), up to 200 characters.
- Message, key and result buffers are wiped when you leave a result and on drop (`zeroize`), and `Debug` output never contains them. Copies made by GAM when drawing, and transient buffers inside `serde_json` and the PDDB, are outside the app's control. This is hygiene, not a security claim.
- The 0.1.0 key `saved_messages` (a JSON array) is not migrated: that version never compiled, so no device has such data.
- Renode capture not yet run. `capture.py` is written but not executed; verification so far is the hosted build, clippy, lint and 51 host tests.

## Build and test

```bash
cd core && cargo test                                   # host tests
cd xous-dev-toolkit && bin/integrate --xous-root ~/xous-core --grade ../precursor-cipher
cd ~/xous-core && cargo xtask run cipher-workshop        # hosted mode
```

Layout: `core/` (`cipher-workshop-core`: ciphers, key validation, frequency analysis, record format, screen state machine; no Xous deps), `src/main.rs` (message routing), `src/app.rs` (drawing, PDDB, TRNG on `precursor-appkit`).

---

Made by Tyler Colby, [Colby's Data Movers, LLC](https://colbysdatamovers.com). Issues: [GitHub](https://github.com/tbcolby/precursor-cipher/issues).

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
