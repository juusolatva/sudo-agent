# Suggested commands

- `cargo check` — fast type-check
- `cargo run -- serve --key ~/.ssh/id_ed25519 [--ttl 15m] [--max-ttl 8h] [--approval-timeout 2m] [--agent-socket PATH]` (or `SUDO_AGENT_SOCKET=PATH`; bare form without `serve` also works) — run daemon in foreground (default socket `$XDG_RUNTIME_DIR/sudo-agent/agent.sock`; it prints the `export SSH_AUTH_SOCK=…` line)
- `cargo test`, `cargo test <name>`
- `cargo clippy --all-targets --all-features`
- `cargo fmt` / `cargo fmt --check`
- After `cargo publish`/`cargo package` (even `--dry-run`): `cargo clean -p sudo-agent`, else `cargo build` keeps a stale dev binary.
- SonarQube Cloud (public, analyses pushed `main`): `curl -s 'https://sonarcloud.io/api/issues/search?componentKeys=juusolatva_sudo-agent&resolved=false'`
- Prompt behaviour on a real tty without a server: drive the binary under a pty (Python `pty.fork()`) and send requests with `ssh-keygen -Y sign`; kill the signer / write `\x03` to test cancellation.

## Manual e2e (roadmap "Now" verification)
- `SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/sudo-agent/agent.sock ssh-add -l` — list identities from the running agent
- `ssh-keygen -Y sign -n file -f key.pub FILE` (with `SSH_AUTH_SOCK` set) — real sign request to exercise the approval prompt
- `sudo` configured with `pam_ssh_agent_auth` pointed at that socket; configure PAM by hand only, never via tooling (see `mem:core` invariants).
