# sudo-agent — core

PAM-aware SSH agent daemon (Rust) gating `sudo` (via `pam_ssh_agent_auth`) on agent-side key TTL + per-sign yes/no approval.
Authoritative design docs: `AGENTS.md` (invariants, scope, conventions) and `TODO.md` (Now/Next/Someday roadmap + rationale).
Status: core loop done, "Now" gaps closed (stale prompts, Ctrl-C at a prompt), verified against real `pam_ssh_agent_auth` 0.10.4 (openSUSE) and 0.10.3 (Debian) (`docs/manual-e2e.md`). Published on crates.io (0.2.0: `serve`, `control.sock` + `ssh-add`; 0.2.1: time left in listed key comments; 0.3.0: pinentry popups + approval routing). Background-daemon plan (design + steps 0, 1a–1c, 2–4, then "Later" in TODO.md; decisions settled 2026-10-12): steps 0, 1a, 1b done 2026-10-12, 1c and 2 (2a routing, 2b pinentry client, 2c wiring) done + verified 2026-10-17; next 3: systemd user unit + log timestamps, then 4: `sudo-agent approve` (two sockets: forwarded `agent.sock` list+sign only, `control.sock` for ssh-add + approve, protected against forwarding). See AGENTS.md "Planned Architecture".

## Source map
- `src/cli.rs` — clap: `serve` subcommand + bare-form alias (same `ServeArgs` flattened at top level; options before `serve` rejected); flags `--key`, `--ttl`, `--max-ttl`, `--approval-timeout` (terminal prompt), `--pinentry` (default `pinentry`), `--pinentry-timeout` (15s), `--no-pinentry` (conflicts with the other two), `--agent-socket` (alias `--socket`), `--control-socket`. Socket env vars are resolved in code (`socket::choose_path`, empty = unset), not with clap's `env`.
- `src/main.rs` — builds the approval `Router` (terminal, then pinentry unless `--no-pinentry`) and the `Approvals: …` startup line (`approvals_line`), startup key loading (terminal directly), expiry reaper (purges 250 ms after deadline so a withdrawn prompt's line ends first), signals (SIGINT at an open prompt denies it; again within `STOP_WINDOW` stops), `listen()`.
- `src/agent.rs` — `SudoAgent` (manual `Agent<UnixListener>` factory, holds `Arc<Router>`) → per-connection `Connection` (`Session`: `request_identities`, approval-gated `sign` logging who answered: `Approved (pinentry) …`, `denied (terminal)`, plus backend problems once; prompt withdrawn via `CancellationToken` on client hang-up (`hung_up`: `AsyncFd` on a dup of the client fd, read-closed) or key expiry (`key_gone`)), `Peer` via `SO_PEERCRED`, `sanitize()`.
- `src/keys.rs` — `KeyEntry { private_key, expires_at }` on `CLOCK_BOOTTIME` (`keys::now()`), `load`/decrypt, `purge_expired`, TTL parse/format, `TtlPolicy`; `listed_comment` = `<comment> (14m30s left)` for `request_identities` on both sockets (stored comment, prompts, logs unchanged).
- `src/prompt.rs` — `Prompter` trait (`confirm(msg, &CancellationToken)`: `Ok` = answer, `Err` = no answer; `available()`), `TerminalPrompter` (available if `/dev/tty` opened at startup; blocking tty work in `spawn_blocking`; `poll()` on tty + per-prompt wake pipe, CLOCK_BOOTTIME deadline; `interrupt()` for Ctrl-C = a deny answer), test-only `testing::{ScriptedPrompter, ApprovesAfter, GivesUp, Unavailable}`.
- `src/routing.rs` — `Router::ask()` asks every available backend at once; first `Ok` wins, the rest are withdrawn and awaited; denied only when all give up or none is available (a lone backend's error passes through). `Answer { approved, by, problems }`: `problems` are other backends' non-timeout failures, each reported once. Tests: `Router::only(prompter)`.
- `src/pinentry.rs` — `Pinentry` backend: one `pinentry` per request, own session (`setsid`) + `PR_SET_PDEATHSIG`, stderr null; Assuan `SETTITLE`/`SETPROMPT` (gnome3 heading)/`SETDESC` (+ "This popup closes in …")/`SETOK Allow`/`SETCANCEL Deny`/`SETTIMEOUT`/`CONFIRM`. Only error code 99 (cancel) is a denial; 114 "Not confirmed" (pinentry-tty without a tty) etc. are failures. Withdraw = SIGTERM, SIGKILL after 1 s, reap. Available iff `DISPLAY`/`WAYLAND_DISPLAY` set at startup. Tests drive a fake `sh -c` pinentry; `real_pinentry_*` are `#[ignore]`d manual tests (`$PINENTRY`).
- `src/control.rs` — `control.sock`: `ControlAgent`/`ControlConnection` wrap `SudoAgent`, reuse `agent::Connection` for list/sign, add `ssh-add` add/remove (`keys::TtlPolicy`; `-c` ok; `-h`/unknown constraints/certs/smartcard refused; re-add restarts TTL). Protections: `refusal()` (uid, `ssh` exe tripwire) at connect, `session-bind` → refused for good. Every refusal logged.
- `src/server.rs` — `serve(Listeners { agent, control }, agent, ttl, shutdown)` + socket-level tests (temp socket, `ssh_agent_lib::client::Client`, refusals pinned as `Response::Failure`). Shared test helpers: `keys::testing::entry`, `prompt::testing::{ScriptedPrompter, ApprovesAfter, GivesUp, Unavailable}`, `Router::only`.
- `src/socket.rs` — default socket path (XDG runtime dir, cache fallback), dir checks, stale-socket handling, bind.
- Unit tests live in each module; no config file.

## Invariants (summary; full text in AGENTS.md)
- TTL tracked and enforced inside agent (`KeyEntry`); `ssh-add -t` only sets it. Starts when the key is decrypted/added. Cap policy: above `--max-ttl` (default 8h) clamp + log; no `-t` (or `-t 0`) → default `--ttl`. Expiry check = `!entry.is_expired(keys::now())`; `sign()` checks before prompting and again after approval, never trusting `request_identities`. Never use `Instant` (pauses during suspend).
- Passphrase only at load time; sign-time approval is yes/no only.
- One prompt abstraction, two kinds (secret input, confirm); terminal backend first and must stay working. Approvals are routed to every available backend at once (terminal, pinentry; later `approve` clients).
- Never write code that edits PAM config; docs + `--check` dry-run only.
- Scope: background-daemon steps (TODO.md → Next) one at a time, in order; no other "Next"/"Someday" features before them.

## Related memories
- Language/crate versions and API notes for `ssh-agent-lib`: `mem:tech_stack`
- Locking, error handling, style rules: `mem:conventions`
- Build/run/manual e2e commands, plus the CI checks (clippy `-D warnings`, cargo-audit, cargo-deny): `mem:suggested_commands`
- Checks to run before declaring a task done: `mem:task_completion`
