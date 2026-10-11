# sudo-agent — core

PAM-aware SSH agent daemon (Rust) gating `sudo` (via `pam_ssh_agent_auth`) on agent-side key TTL + per-sign yes/no approval.
Authoritative design docs: `AGENTS.md` (invariants, scope, conventions) and `TODO.md` (Now/Next/Someday roadmap + rationale).
Status: core loop done, "Now" gaps closed (stale prompts, Ctrl-C at a prompt), verified against real `pam_ssh_agent_auth` 0.10.4 (openSUSE) and 0.10.3 (Debian) (`docs/manual-e2e.md`). Published on crates.io (0.1.1). Next: the background-daemon plan (design + steps 0, 1a–1c, 2–4, then "Later" in TODO.md; decisions settled 2026-10-12), steps 0 and 1a done 2026-10-12, next 1b (two sockets: forwarded `agent.sock` list+sign only, `control.sock` for ssh-add + approve, protected against forwarding; pinentry + `sudo-agent approve` backends, asked all at once). See AGENTS.md "Planned Architecture".

## Source map
- `src/cli.rs` — clap: `serve` subcommand + bare-form alias (same `ServeArgs` flattened at top level; options before `serve` rejected); flags `--key`, `--ttl`, `--max-ttl`, `--approval-timeout`, `--agent-socket` (alias `--socket`). Socket env vars are resolved in code (`socket::choose_path`, empty = unset), not with clap's `env`.
- `src/main.rs` — startup key loading, expiry reaper (purges 250 ms after deadline so a withdrawn prompt's line ends first), signals (SIGINT at an open prompt denies it; again within `STOP_WINDOW` stops), `listen()`.
- `src/agent.rs` — `SudoAgent` (manual `Agent<UnixListener>` factory) → per-connection `Connection` (`Session`: `request_identities`, approval-gated `sign`; prompt withdrawn via `CancellationToken` on client hang-up (`hung_up`: `AsyncFd` on a dup of the client fd, read-closed) or key expiry (`key_gone`)), `Peer` via `SO_PEERCRED`, `sanitize()`.
- `src/keys.rs` — `KeyEntry { private_key, expires_at }` on `CLOCK_BOOTTIME` (`keys::now()`), `load`/decrypt, `purge_expired`, TTL parse/format.
- `src/prompt.rs` — `Prompter` trait (`confirm(msg, &CancellationToken)`), `TerminalPrompter` (blocking tty work in `spawn_blocking`; `poll()` on tty + per-prompt wake pipe, CLOCK_BOOTTIME deadline; `interrupt()` for Ctrl-C), test-only `testing::ScriptedPrompter`.
- `src/server.rs` — `serve(listener, agent, shutdown)` (step 1b adds `control.sock` here) + socket-level tests (temp socket, `ssh_agent_lib::client::Client`, refusals pinned as `Response::Failure`). Shared test helpers: `keys::testing::entry`, `prompt::testing::{ScriptedPrompter, ApprovesAfter}`.
- `src/socket.rs` — default socket path (XDG runtime dir, cache fallback), dir checks, stale-socket handling, bind.
- Unit tests live in each module; no config file.

## Invariants (summary; full text in AGENTS.md)
- TTL tracked inside agent (`KeyEntry`), never via `ssh-add -t`; starts when the key is decrypted. Cap policy (for future `ssh-add -t`): above `--max-ttl` (default 8h) clamp + log; no `-t` → default `--ttl`. Expiry check = `!entry.is_expired(keys::now())`; `sign()` checks before prompting and again after approval, never trusting `request_identities`. Never use `Instant` (pauses during suspend).
- Passphrase only at load time; sign-time approval is yes/no only.
- One prompt abstraction, two kinds (secret input, confirm); terminal backend first and must stay working.
- Never write code that edits PAM config; docs + `--check` dry-run only.
- Scope: background-daemon steps (TODO.md → Next) one at a time, in order; no other "Next"/"Someday" features before them.

## Related memories
- Language/crate versions and API notes for `ssh-agent-lib`: `mem:tech_stack`
- Locking, error handling, style rules: `mem:conventions`
- Build/run/manual e2e commands: `mem:suggested_commands`
- Checks to run before declaring a task done: `mem:task_completion`
