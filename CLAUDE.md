# Cipher Workshop — Build Notes

Package `cipher-workshop` (not `cipher`: RustCrypto's `cipher` crate is in the
xous-core graph). Repo name `precursor-cipher` is unchanged.

## Architecture
- `core/` (`cipher-workshop-core`, no Xous deps, host-tested): ciphers with
  validated keys (`CipherKey`), frequency analysis, saved-record format, and
  the screen state machine (`Ui`, which returns `Effect`s for storage and
  leaving).
- `src/main.rs` routes GAM messages (template pattern); `src/app.rs` maps keys
  to `Ui`, performs effects via `appkit::store::Store`, draws via
  `appkit::screen::Screen`. No pump: nothing changes without a key press.
- One PDDB key per saved message (`cipher.data` / `m.<16 hex>`, random names
  from the TRNG, fail closed), so delete removes the key and each record
  stays in its own basis. Reloaded on every basis change.

## Test / gate
```bash
cd core && cargo test
cd ../xous-dev-toolkit && bin/integrate --xous-root <xous-core> --grade -v ../precursor-cipher
```
