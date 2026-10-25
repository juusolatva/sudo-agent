# Task completion checklist

Run in order, fix failures:
1. `cargo fmt` (CI runs `cargo fmt --check`)
2. `cargo clippy --all-targets --all-features -- -D warnings` (CI fails on any warning)
3. `cargo test`
4. `cargo build`

- If the change touches sign/prompt/key-loading paths, note that the manual e2e check in `mem:suggested_commands` is still required (can't be automated; tell the user rather than claiming it was verified).
- If dependencies or `Cargo.lock` changed: `cargo audit --deny warnings`, `cargo deny --locked check bans licenses sources`, and `osv-scanner -r ./` must pass. New license → `deny.toml` allow-list, advisory → `.cargo/audit.toml` and `osv-scanner.toml` ignores, only with the user's agreement plus a reason comment.
- SonarQube quality gate (Sonar way: incl. coverage ≥ 80% on new code) gates CI: new code needs tests. The gate lets some new code smells through; aim for zero open issues (issues API in `mem:suggested_commands`) before a release.
- Version bump: also `sonar.projectVersion`, and remind the user to tag + release (steps in `mem:suggested_commands`).
- Commits are allowed and pull requests on feature branches are preferred; signed release tags and `cargo publish` remain with the user.
