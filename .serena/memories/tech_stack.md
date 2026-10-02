# Tech stack

- Rust, edition 2024 (local toolchain rustc 1.98.x); single binary crate, Cargo, `Cargo.lock` committed.
- Deps: `ssh-agent-lib` 0.6.0, `ssh-key` 0.6.7, `tokio` 1.x (`full`), `async-trait`.
- `ssh-agent-lib`: implementing `Session` on a `Clone` type gives a blanket `Agent` impl → each socket connection gets its own clone; shared state must live behind `Arc`. `listen(UnixListener::bind(path)?, agent)` runs the accept loop. Errors use `ssh_agent_lib::error::AgentError`.
- `ssh-agent-lib` also implements OpenSSH destination-restriction extensions (`restrict-destination`, `session-bind@openssh.com`; see its `key-storage.rs` example) — relevant only for the "Someday" forwarding work.
- Runtime target: Linux; `sudo` side uses `pam_ssh_agent_auth` reading `SSH_AUTH_SOCK`.
