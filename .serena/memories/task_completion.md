# Task completion checklist

Run in order, fix failures:
1. `cargo fmt`
2. `cargo clippy --all-targets --all-features` (no new warnings)
3. `cargo test`
4. `cargo build`

- If the change touches sign/prompt/key-loading paths, note that the manual e2e check in `mem:suggested_commands` is still required (can't be automated; tell the user rather than claiming it was verified).
- Do not commit unless asked.
