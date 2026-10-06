# sudo-agent — core

PAM-aware SSH agent daemon (Rust) gating `sudo` (via `pam_ssh_agent_auth`) on agent-side key TTL + per-sign yes/no approval.
Authoritative design docs: `AGENTS.md` (invariants, scope, conventions) and `TODO.md` (Now/Next/Someday roadmap + rationale).
Status: core loop done and verified against real `pam_ssh_agent_auth` (`docs/manual-e2e.md`). Remaining "Now" gaps are in TODO.md; after them comes the background-daemon plan (two sockets: forwarded `agent.sock` list+sign only, `control.sock` for add/status/approve; pinentry + `sudo-agent approve` backends). See AGENTS.md "Planned Architecture".

## Source map
- `src/main.rs` — clap `Args` (`--key`, `--ttl`, `--socket`), startup key loading, expiry reaper, `listen()`.
- `src/agent.rs` — `SudoAgent` (manual `Agent<UnixListener>` factory) → per-connection `Connection` (`Session`: `request_identities`, approval-gated `sign`), `Peer` via `SO_PEERCRED`, `sanitize()`.
- `src/keys.rs` — `KeyEntry { private_key, expires_at }` on `CLOCK_BOOTTIME` (`keys::now()`), `load`/decrypt, `purge_expired`, TTL parse/format.
- `src/prompt.rs` — `Prompter` trait, `TerminalPrompter`, test-only `testing::ScriptedPrompter`.
- `src/socket.rs` — default socket path (XDG runtime dir, cache fallback), dir checks, stale-socket handling, bind.
- Unit tests live in each module; no config file.

## Invariants (summary; full text in AGENTS.md)
- TTL tracked inside agent (`KeyEntry`), never via `ssh-add -t`. Expiry check = `!entry.is_expired(keys::now())`; `sign()` checks before prompting and again after approval, never trusting `request_identities`. Never use `Instant` (pauses during suspend).
- Passphrase only at load time; sign-time approval is yes/no only.
- One prompt abstraction, two kinds (secret input, confirm); terminal backend first and must stay working.
- Never write code that edits PAM config; docs + `--check` dry-run only.
- Scope: only roadmap "Now" items until core loop works end-to-end.

## Related memories
- Language/crate versions and API notes for `ssh-agent-lib`: `mem:tech_stack`
- Locking, error handling, style rules: `mem:conventions`
- Build/run/manual e2e commands: `mem:suggested_commands`
- Checks to run before declaring a task done: `mem:task_completion`
