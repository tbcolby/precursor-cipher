# Cipher Workshop — agent notes

Rebuilt 2026-11-20 on `precursor-appkit` (strategy R from the portfolio
remediation plan). Read `CLAUDE.md` for layout. Rules that matter here:

- Keys are validated when built (`CipherKey::new`); never run a cipher on an
  unchecked key. Every cipher has known-vector and round-trip tests.
- These are teaching ciphers. Don't describe them as protecting anything.
- No key or message text in logs or `Debug`; message buffers are zeroized.
- Every screen exits on Backspace or F4; `∴` is never delivered to apps.
