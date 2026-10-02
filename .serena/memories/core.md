# sudo-agent — core

PAM-aware SSH agent daemon (Rust) gating `sudo` (via `pam_ssh_agent_auth`) on agent-side key TTL + per-sign yes/no approval.
Authoritative design docs: `AGENTS.md` (invariants, scope, conventions) and `TODO.md` (Now/Next/Someday roadmap + rationale). Read them before design-level changes; don't duplicate them here.

## Source map
- `src/main.rs` — everything currently: `KeyEntry` (public_key, loaded_at: Instant, ttl: Duration), `CustomAgent` (`#[derive(Clone)]`, `keys: Arc<std::sync::Mutex<Vec<KeyEntry>>>`), `impl Session for CustomAgent` (`request_identities` filters expired keys; `sign` is `todo!()`), `main` (binds `/tmp/sudo_agent.sock`, removes stale socket first).
- No tests, no modules, no config file yet. Nothing populates `keys` yet.

## Invariants (summary; full text in AGENTS.md)
- TTL tracked inside agent (`KeyEntry`), never via `ssh-add -t`. Expiry check = `now.duration_since(loaded_at) < ttl`; `sign()` must re-check it, not trust `request_identities`.
- Passphrase only at load time; sign-time approval is yes/no only.
- One prompt abstraction, two kinds (secret input, confirm); terminal backend first and must stay working.
- Never write code that edits PAM config; docs + `--check` dry-run only.
- Scope: only roadmap "Now" items until core loop works end-to-end.

## Related memories
- Language/crate versions and API notes for `ssh-agent-lib`: `mem:tech_stack`
- Locking, error handling, style rules: `mem:conventions`
- Build/run/manual e2e commands: `mem:suggested_commands`
- Checks to run before declaring a task done: `mem:task_completion`
