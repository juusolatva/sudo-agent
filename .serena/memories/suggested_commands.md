# Suggested commands

- `cargo check` — fast type-check
- `cargo build` / `cargo run` — run daemon (listens on `/tmp/sudo_agent.sock`, runs in foreground)
- `cargo test`, `cargo test <name>`
- `cargo clippy --all-targets --all-features`
- `cargo fmt` / `cargo fmt --check`

## Manual e2e (roadmap "Now" verification)
- `SSH_AUTH_SOCK=/tmp/sudo_agent.sock ssh-add -l` — list identities from the running agent
- `sudo` configured with `pam_ssh_agent_auth` pointed at that socket; configure PAM by hand only, never via tooling (see `mem:core` invariants).
