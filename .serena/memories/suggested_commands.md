# Suggested commands

- `cargo check` — fast type-check
- `cargo run -- serve --key ~/.ssh/id_ed25519 [--ttl 15m] [--max-ttl 8h] [--approval-timeout 2m] [--pinentry PROGRAM] [--pinentry-timeout 60s | --no-pinentry] [--agent-socket PATH] [--control-socket PATH]` (or `SUDO_AGENT_SOCKET` / `SUDO_AGENT_CONTROL_SOCKET`; bare form without `serve` also works; `--key` optional) — run daemon in foreground (default sockets `$XDG_RUNTIME_DIR/sudo-agent/{agent,control}.sock`; it prints the `export SSH_AUTH_SOCK=…` line). Socket paths must fit 107 bytes, so the scratchpad is too long: use `mktemp -d "$XDG_RUNTIME_DIR/…"` for throwaway sockets.
- `cargo test`, `cargo test <name>`
- `cargo clippy --all-targets --all-features`
- `cargo fmt` / `cargo fmt --check`
- CI equivalents (`.github/workflows/build.yml`, `security.yml`): `cargo clippy --all-targets --all-features --locked -- -D warnings`; `cargo audit --deny warnings` (ignores with reasons in `.cargo/audit.toml`); `cargo deny --locked check bans licenses sources` (`deny.toml`; advisories left to cargo-audit, so a full `cargo deny check` still reports the ignored RUSTSEC-2023-0071). Known harmless `cargo deny` warning: duplicate `syn` 2.x/3.x.
- After `cargo publish`/`cargo package` (even `--dry-run`): `cargo clean -p sudo-agent`, else `cargo build` keeps a stale dev binary.
- SonarQube Cloud (public, analyses pushed `main`): `curl -s 'https://sonarcloud.io/api/issues/search?componentKeys=juusolatva_sudo-agent&resolved=false'`
- Popups: with `DISPLAY` set (agents' shells often have it) a request opens a real pinentry on the user's screen. Don't trigger one unasked: use `--no-pinentry`, `env -u DISPLAY -u WAYLAND_DISPLAY`, or `--pinentry <fake script>` (a `/bin/sh` script answering `OK` to every line approves) to exercise routing.
- Real popup checks (for the user, on the desktop): `cargo test real_pinentry -- --ignored --nocapture` (`PINENTRY=pinentry-curses` to check a terminal variant fails cleanly).
- Prompt behaviour on a real tty without a server: drive the binary under a pty (Python `pty.fork()`) and send requests with `ssh-keygen -Y sign`; kill the signer / write `\x03` to test cancellation.

## Manual e2e (roadmap "Now" verification)
- `SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/sudo-agent/control.sock ssh-add [-t 4h] KEY` — add a key (only over `control.sock`)
- `SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/sudo-agent/agent.sock ssh-add -l` — list identities with time left in comments
- `ssh-keygen -Y sign -n file -f key.pub FILE` (with `SSH_AUTH_SOCK` set) — real sign request to exercise the approval prompt
- `sudo` configured with `pam_ssh_agent_auth` pointed at that socket; configure PAM by hand only, never via tooling (see `mem:core` invariants).
