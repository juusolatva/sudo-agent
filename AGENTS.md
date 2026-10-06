# AGENTS.md

Guidance and repository conventions for AI coding agents working on `sudo-agent`.

## Project Overview

`sudo-agent` is a lightweight, PAM-aware SSH agent daemon written in Rust for time-bound, human-approved `sudo` authentication. Instead of relying on static keys trusted indefinitely or re-typing passwords on every elevation, `sudo` challenges an SSH key held by this agent (via `pam_ssh_agent_auth`). The agent only signs authentication challenges if:
1. The key has not exceeded its configured Time-To-Live (TTL).
2. The user explicitly approves the signature request.

## Current State & Priority

- **Status**: Core loop implemented (socket, key loading, approval-gated `sign()`), unit-tested, and verified end-to-end: `sudo` on a server via `pam_ssh_agent_auth` 0.10.4 (openSUSE) over a forwarded agent, approve/deny/expiry/concurrent requests (2026-10-07, results in `docs/manual-e2e.md`). Next up are the known gaps listed under "Now" in `TODO.md`.
  - Rust 2024 edition (`ssh-agent-lib` 0.6.0, `ssh-key` 0.6.7, `tokio` 1.x, `async-trait`).
  - Socket listener binds to `$XDG_RUNTIME_DIR/sudo-agent/agent.sock`, falling back to `${XDG_CACHE_HOME:-~/.cache}/sudo-agent/agent-<hostname>.sock`, or `--socket <path>` (see `src/socket.rs`). Directory is `0700` (verified), socket `0600`; a stale socket is removed only if nothing answers on it. `socket::bind` returns a `SocketFile` that removes the socket on drop (if the file is still the one it bound).
  - Shutdown: SIGINT/SIGTERM/SIGHUP end `run()` cleanly (keys cleared, socket removed). The handlers are installed only after key loading, so Ctrl-C during passphrase entry keeps the default action, because echo is off at that point. `main` builds the runtime by hand and calls `shutdown_background()`, so exit never waits on a prompt blocked reading the terminal.
  - Keys are loaded at startup via `--key <PATH>` (repeatable) and `--ttl <DURATION>` (default `15m`), parsed with `clap`; encrypted keys prompt for the passphrase (3 attempts, empty aborts). See `src/keys.rs`.
  - `KeyEntry` holds the decrypted `ssh_key::PrivateKey` (zeroized on drop by `ssh-key`) and an `expires_at` deadline on `CLOCK_BOOTTIME` (`keys::now()`), so suspend time counts against the TTL. Do not use `Instant` for TTLs (`CLOCK_MONOTONIC` pauses during suspend).
  - A background reaper drops expired keys every second; `request_identities()` also filters them.
  - `sign()` (`src/agent.rs`) looks up the requested key and checks its TTL under the lock, releases the lock, asks `Prompter::confirm()` (prompt errors count as denial), then re-locks and re-checks expiry before signing. Unknown/expired keys and unsupported requests are refused *before* prompting. Every approval/refusal is logged to stderr.
  - `SudoAgent` implements `Agent<UnixListener>` manually (not the clone-per-connection blanket impl) so each `Connection` records its peer via `SO_PEERCRED` (pid, uid, `/proc/<pid>/cmdline`). Peer-supplied text is passed through `sanitize()` before reaching the terminal; keep doing that for anything new shown in prompts.
  - RSA keys sign only with SHA-512 (`ssh-key` limitation), so RSA requests without the `rsa-sha2-512` flag are refused; Ed25519 is the recommended key type.
  - Approvals time out: `--approval-timeout` (default `2m`, a deliberate compromise until per-backend values are set). The terminal prompt waits with `poll()` against a `keys::now()` (`CLOCK_BOOTTIME`) deadline and then gives up the terminal, so a stale read can't swallow the next prompt's answer. A timeout surfaces as an `ErrorKind::TimedOut` error from `confirm()`, logged as `not approved: no answer within …`. Durations for flags are parsed by `keys::parse_duration`.
  - Prompt abstraction (`src/prompt.rs`: `Prompter` trait + `TerminalPrompter`) serves both passphrases and approvals through one shared `Arc<dyn Prompter>`. Tests use `prompt::testing::ScriptedPrompter`.
- **Immediate Focus ("Now")**: Focus strictly on the end-to-end core loop:
  1. ~~Implement `sign()`: verify TTL, trigger approval prompt, sign challenge, and return signature.~~ Done.
  2. ~~Implement a terminal-based prompt abstraction (pinentry style) usable for both load-time passphrase entry and sign-time approval.~~ Done.
  3. ~~Implement key loading into `keys` (manual passphrase entry on load; no secrets-manager integration yet).~~ Done.
  4. ~~Manual end-to-end verification (`pam_ssh_agent_auth` challenging the running agent via `SSH_AUTH_SOCK`).~~ Done; procedure and results in `docs/manual-e2e.md`. Re-run it after changes to `sign()`, prompting or logging.
  - Remaining: the known gaps listed in `TODO.md` under "Now" (stale prompts; whether Ctrl-C at a prompt should deny instead of shutting down). Optional hardening: socket-level integration tests (spawn the listener on a temp socket, drive it with `ssh_agent_lib::client`, script answers with `ScriptedPrompter`).
- **After "Now": background daemon** (`TODO.md` → Next → "Background daemon"), in the listed order: (1) `serve` + client subcommands, `control.sock`, keys added with `ssh-add`, `sudo-agent status`; (2) pinentry approvals; (3) systemd user unit; (4) `sudo-agent approve` terminal client. See [Planned Architecture](#planned-architecture-background-daemon).
- **Scope Discipline**: Do **not** jump ahead to other "Next" or "Someday" features (config files, desktop notifications, native secrets-manager fetch, forwarding chain, destination restriction) before the "Now" gaps and the background-daemon steps they depend on. Work through the background-daemon steps one at a time.

## Core Architectural Invariants

Agents modifying or extending this codebase must strictly preserve the following architectural principles:

1. **TTL Stays Inside the Agent**:
   - Do not rely on client-side `ssh-add -t`. Once keys can be added with `ssh-add`, a `-t` lifetime may *set* a key's TTL, but the agent itself tracks and enforces it (and may cap it).
   - The expiration timer must be tracked inside `sudo-agent` so that key expiration status can be queried and surfaced remotely (e.g. warning remote users that a key is approaching expiry before or during `sudo`).
2. **Approval Prompt is Yes/No, Never Passphrase Re-entry**:
   - The key passphrase is required **once**, only when decrypting the key into agent memory at load time.
   - Per-signature approval is strictly a cheap confirmation (yes/no keypress). It serves as a sanity check and a detection mechanism against silent elevation (e.g. by another process reaching the socket). Requiring passphrases on every sign defeats usability.
3. **Pluggable Prompt Abstraction with Terminal First**:
   - Design a single prompt abstraction supporting two kinds of interaction: secret input (passphrase at load) and binary confirmation (yes/no on sign).
   - Start with a terminal-based backend. It must remain functional even after other backends (GUI, desktop notifications) are introduced.
   - Planned backends: **pinentry** (desktop popup, spawned per request) and **`sudo-agent approve`** (terminal client on `control.sock`) are the focus. Once the approve client exists it is the terminal backend that must keep working; the daemon's own foreground prompt (today's `TerminalPrompter`) stays as a backup as long as it causes no problems.
   - Once the daemon loads keys via `ssh-add`, the passphrase part is the client's job; the daemon itself only ever asks yes/no.
4. **No Automated PAM Configuration Writing**:
   - Do not write automated PAM configuration mutators. Incorrect PAM modifications risk locking users out of root access on live systems, and PAM tooling differs across Linux distributions.
   - Setup must remain manual documentation (exact stanzas to paste) and non-destructive dry-run validation (`--check` flag).

## Planned Architecture (background daemon)

Agreed design for the "Background daemon" steps in `TODO.md`. Keep new code compatible with it even before it lands:

- **Two sockets, different trust.**
  - `agent.sock` is the forwarded one. It serves **only** `request_identities`, approval-gated `sign`, and at most a read-only status extension.
  - `control.sock` is never forwarded. It takes the full protocol (add/remove keys, lock) plus our own commands (status, stop, approve).
  - Never let `agent.sock` add or remove keys, lock or unlock, or answer approvals. Anything reachable through forwarding must be harmless to a hostile server.
- **The daemon is independent of terminals.** It runs as `sudo-agent serve` (systemd user service, or `setsid -f`), so closing a terminal never kills it. Logs go to stderr, which ends up in the journal under systemd.
- **Approval routing**: an attached `sudo-agent approve` client first, then pinentry when a desktop session is available, otherwise deny and log. Foreground mode (`serve` holding a terminal) remains the backup.
- **Keys are added from a client**: `ssh-add` / `sudo-agent add` over `control.sock`. The daemon starts with no keys, and restarting it drops them all (intended).

## Machines & Manual Testing

Work on this project happens on two kinds of machine, and an agent must know which one it is on:

- **Laptop (agent host)**: Fedora 44. Holds the private keys and runs `sudo-agent`. It has **no** `pam_ssh_agent_auth`: the module isn't packaged for Fedora 44, so `sudo` can't be tested here. Local testing uses `ssh-add -l` and `ssh-keygen -Y sign` against the socket.
- **Servers (sudo hosts)**: `pam_ssh_agent_auth` is already set up for `sudo`: `palvelin` (openSUSE Tumbleweed, `pam_ssh_agent_auth` 0.10.4) and `vakoilu` (Debian, `libpam-ssh-agent-auth` 0.10.3). Their sudo timestamp timeout is zero, so every `sudo` authenticates. They hold **no private keys**; keys reach them only through the agent forwarded from the laptop (`ssh -o ForwardAgent=<sudo-agent socket>`). Do not try to run or load keys into `sudo-agent` on a server. `cargo build`/`cargo test` work there as usual.
- **Approval prompts appear on the laptop's terminal**, not in the server session. An agent on a server cannot see or answer them; ask the user to answer and relay what the prompt showed.
- **On a server, PAM and sudoers are read-only for agents.** Inspect (`/etc/pam.d/sudo`, the `file=` keys list, logs), then *propose* changes for the user to apply (`visudo`, with a root shell kept open). Never edit them, and never run `sudo` in a way that could change them. This extends invariant 4 below to manual testing.
- Full step-by-step procedure, test matrix and troubleshooting: `docs/manual-e2e.md`.

## Project Structure

- `Cargo.toml`: Package definition and dependencies (`ssh-agent-lib`, `ssh-key`, `tokio`, `async-trait`, `clap`, `libc`, `rpassword`, `signature`, `zeroize`; dev: `tempfile`; `ssh-key` with `crypto` + `encryption`).
- `src/main.rs`: Entry point: CLI arguments, startup key loading, the expiry reaper, and the listener loop.
- `src/agent.rs`: `SudoAgent` (per-connection `Agent` factory) and `Connection` (implements `Session`: identities + approval-gated `sign()`), peer identification, and prompt sanitizing.
- `src/keys.rs`: `KeyEntry`, the `CLOCK_BOOTTIME` clock, key loading/decryption, expiry purging, and TTL parsing/formatting.
- `src/prompt.rs`: `Prompter` trait (secret input + yes/no confirm) and the `/dev/tty` `TerminalPrompter` backend. Prompts are serialized; approval requires typed `y`/`yes` + Enter and discards type-ahead first.
- `src/socket.rs`: Socket path selection (XDG runtime dir with cache-dir fallback), private-directory checks, stale-socket handling, and binding.
- `docs/manual-e2e.md`: Manual `pam_ssh_agent_auth` end-to-end test procedure (laptop agent ↔ forwarded server `sudo`).
- `TODO.md`: Detailed roadmap (Now, Next, Someday) and in-depth rationales for core design decisions.

## Common Development Commands

```sh
# Fast type-checking
cargo check

# Build debug binary
cargo build

# Run daemon
cargo run

# Run tests
cargo test
cargo test <test_name>

# Linting and code formatting
cargo clippy --all-targets --all-features
cargo fmt --check
cargo fmt
```

## Coding Conventions & Guidelines

- **Rust Edition & Idioms**: Target Rust 2024 edition. Use idiomatic Rust error handling, integrating with `ssh_agent_lib::error::AgentError`.
- **Async Runtime**: Built on `tokio` (multi-threaded runtime). `SudoAgent` implements `ssh_agent_lib::agent::Agent<UnixListener>`; `listen()` calls its `new_session()` for each accepted socket, which returns a `Connection` (the `Session`) sharing the key store and prompter. `SudoAgent` must not implement `Session` itself, or it would collide with `ssh-agent-lib`'s clone-per-connection blanket impl.
- **Concurrency & Locking**: Keys in `SudoAgent` are guarded by an `Arc<Mutex<Vec<KeyEntry>>>`. Keep mutex lock guards scoped as tightly as possible; never hold locks across async points or while waiting for user interaction/prompt approval. The one deliberate exception is `SudoAgent::requests` (a fair `tokio::sync::Mutex<()>`), held for a whole `sign()` so requests are served one at a time in arrival order; it guards no data, only the user's attention.
- **Terminal output**: Anything printed while requests are served goes through the `log!` macro (`src/main.rs`), not `eprintln!`: it writes the whole line in one `write()`, so it can't split a prompt (which is also written in one `write()`). `eprintln!` is fine before listening starts (key loading) and for the final error in `main`.
- **Testing**: Unit tests live next to the code (`#[cfg(test)] mod tests`). Never commit private keys as fixtures: generate them at test time (`PrivateKey::random(&mut OsRng, …)`) into a `tempfile::tempdir()`. Generating RSA keys in debug builds is slow; test RSA-specific logic without a real RSA key (see `agent::tests::rsa_needs_sha512_flag`).
- **Secret scanning**: The user's pre-commit hook runs `betterleaks` and should stay strict. Silence a false positive with an inline marker on the flagged line, `# betterleaks:allow (<reason>)` (see `rpassword` in `Cargo.toml`), rather than loosening the scanner.
- **Git & Commits**: Never commit changes automatically unless explicitly requested by the user.
