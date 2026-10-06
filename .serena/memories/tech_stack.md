# Tech stack

- Rust, edition 2024 (local toolchain rustc 1.98.x); single binary crate, Cargo, `Cargo.lock` committed.
- Deps: `ssh-agent-lib` 0.6.0, `ssh-key` 0.6.7, `tokio` 1.x (`full`), `async-trait`.
- `ssh-agent-lib`: implementing `Session` on a `Clone` type gives a blanket `Agent` impl (clone per connection). We instead implement `Agent<UnixListener>` manually on `SudoAgent` to read peer creds in `new_session(&UnixStream)`; `SudoAgent` must therefore NOT implement `Session` (coherence conflict). Shared state lives behind `Arc`. RSA: `ssh-key` signs only SHA-512 → check `ssh_agent_lib::proto::signature::RSA_SHA2_512` flag. `Signer`/`Verifier` traits come from the `signature` crate (not re-exported by `ssh-key`). `listen(UnixListener::bind(path)?, agent)` runs the accept loop. Errors use `ssh_agent_lib::error::AgentError`.
- `ssh-agent-lib` also implements OpenSSH destination-restriction extensions (`restrict-destination`, `session-bind@openssh.com`; see its `key-storage.rs` example) — relevant only for the "Someday" forwarding work.
- Runtime target: Linux; `sudo` side uses `pam_ssh_agent_auth` reading `SSH_AUTH_SOCK`.
