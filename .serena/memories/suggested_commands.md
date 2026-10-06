# Suggested commands

- `cargo check` — fast type-check
- `cargo run -- --key ~/.ssh/id_ed25519 [--ttl 15m] [--socket PATH]` — run daemon in foreground (default socket `$XDG_RUNTIME_DIR/sudo-agent/agent.sock`; it prints the `export SSH_AUTH_SOCK=…` line)
- `cargo test`, `cargo test <name>`
- `cargo clippy --all-targets --all-features`
- `cargo fmt` / `cargo fmt --check`

## Manual e2e (roadmap "Now" verification)
- `SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/sudo-agent/agent.sock ssh-add -l` — list identities from the running agent
- `ssh-keygen -Y sign -n file -f key.pub FILE` (with `SSH_AUTH_SOCK` set) — real sign request to exercise the approval prompt
- `sudo` configured with `pam_ssh_agent_auth` pointed at that socket; configure PAM by hand only, never via tooling (see `mem:core` invariants).
