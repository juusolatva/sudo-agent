# Task completion checklist

Run in order, fix failures:
1. `cargo fmt`
2. `cargo clippy --all-targets --all-features -- -D warnings` (CI fails on any warning)
3. `cargo test`
4. `cargo build`

- If the change touches sign/prompt/key-loading paths, note that the manual e2e check in `mem:suggested_commands` is still required (can't be automated; tell the user rather than claiming it was verified).
- If dependencies or `Cargo.lock` changed: `cargo audit --deny warnings` and `cargo deny --locked check bans licenses sources` must pass. New license → `deny.toml` allow-list, advisory → `.cargo/audit.toml` ignore, only with the user's agreement plus a reason comment.
- SonarQube quality gate (incl. coverage on new code) gates CI: new code needs tests.
- Never commit; leave changes for the user.
