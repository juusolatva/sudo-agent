# AGENTS.md

Guidance and repository conventions for AI coding agents working on `sudo-agent`.

## Project Overview

`sudo-agent` is a lightweight, PAM-aware SSH agent daemon written in Rust for time-bound, human-approved `sudo` authentication. Instead of relying on static keys trusted indefinitely or re-typing passwords on every elevation, `sudo` challenges an SSH key held by this agent (via `pam_ssh_agent_auth`). The agent only signs authentication challenges if:
1. The key has not exceeded its configured Time-To-Live (TTL).
2. The user explicitly approves the signature request.

## Current State & Priority

- **Status**: Minimal working skeleton.
  - Rust 2024 edition (`ssh-agent-lib` 0.6.0, `ssh-key` 0.6.7, `tokio` 1.x, `async-trait`).
  - Socket listener binds to `$XDG_RUNTIME_DIR/sudo-agent/agent.sock`, falling back to `${XDG_CACHE_HOME:-~/.cache}/sudo-agent/agent-<hostname>.sock`, or `--socket <path>` (see `src/socket.rs`). Directory is `0700` (verified), socket `0600`; a stale socket is removed only if nothing answers on it.
  - `KeyEntry` holds the decrypted `ssh_key::PrivateKey` (zeroized on drop by `ssh-key`).
  - `request_identities()` filters expired keys based on TTL.
  - `sign()` is currently stubbed with `todo!()`.
  - Prompt abstraction exists (`src/prompt.rs`: `Prompter` trait + `TerminalPrompter`) but is not yet called from key loading or `sign()`; `main.rs` carries a temporary `#[expect(dead_code)]` on `mod prompt` to remove once it is wired up.
  - In-memory `keys` list is not yet populated (no key-loading mechanism yet).
- **Immediate Focus ("Now")**: Focus strictly on the end-to-end core loop:
  1. Implement `sign()`: verify TTL, trigger approval prompt, sign challenge, and return signature.
  2. Implement a terminal-based prompt abstraction (pinentry style) usable for both load-time passphrase entry and sign-time approval.
  3. Implement key loading into `keys` (manual passphrase entry on load; no secrets-manager integration yet).
  4. Manual end-to-end verification (`pam_ssh_agent_auth` challenging the running agent via `SSH_AUTH_SOCK`).
- **Scope Discipline**: Do **not** jump ahead to "Next" or "Someday" features (config files, GUI/desktop notifications, secrets manager integration, destination restriction) until the core "Now" loop is fully functional.

## Core Architectural Invariants

Agents modifying or extending this codebase must strictly preserve the following architectural principles:

1. **TTL Stays Inside the Agent**:
   - Do not rely on client-side `ssh-add -t`.
   - The expiration timer must be tracked inside `sudo-agent` so that key expiration status can be queried and surfaced remotely (e.g. warning remote users that a key is approaching expiry before or during `sudo`).
2. **Approval Prompt is Yes/No, Never Passphrase Re-entry**:
   - The key passphrase is required **once**, only when decrypting the key into agent memory at load time.
   - Per-signature approval is strictly a cheap confirmation (yes/no keypress). It serves as a sanity check and a detection mechanism against silent elevation (e.g. by another process reaching the socket). Requiring passphrases on every sign defeats usability.
3. **Pluggable Prompt Abstraction with Terminal First**:
   - Design a single prompt abstraction supporting two kinds of interaction: secret input (passphrase at load) and binary confirmation (yes/no on sign).
   - Start with a terminal-based backend. It must remain functional even after other backends (GUI, desktop notifications) are introduced.
4. **No Automated PAM Configuration Writing**:
   - Do not write automated PAM configuration mutators. Incorrect PAM modifications risk locking users out of root access on live systems, and PAM tooling differs across Linux distributions.
   - Setup must remain manual documentation (exact stanzas to paste) and non-destructive dry-run validation (`--check` flag).

## Project Structure

- `Cargo.toml`: Package definition and dependencies (`ssh-agent-lib`, `ssh-key`, `tokio`, `async-trait`, `libc`, `rpassword`, `zeroize`; `ssh-key` with `crypto` + `encryption`).
- `src/main.rs`: Entry point containing `CustomAgent` (implements `Session`), `KeyEntry`, argument parsing, and listener loop.
- `src/prompt.rs`: `Prompter` trait (secret input + yes/no confirm) and the `/dev/tty` `TerminalPrompter` backend. Prompts are serialized; approval requires typed `y`/`yes` + Enter and discards type-ahead first.
- `src/socket.rs`: Socket path selection (XDG runtime dir with cache-dir fallback), private-directory checks, stale-socket handling, and binding.
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
- **Async Runtime**: Built on `tokio` (multi-threaded runtime). `CustomAgent` implements `ssh_agent_lib::agent::Session`. Because `CustomAgent` is `Clone`, `ssh-agent-lib`'s blanket implementation treats it as an `Agent` where each accepted socket connection gets a fresh clone.
- **Concurrency & Locking**: Keys in `CustomAgent` are guarded by an `Arc<Mutex<Vec<KeyEntry>>>`. Keep mutex lock guards scoped as tightly as possible; never hold locks across async points or while waiting for user interaction/prompt approval.
- **Git & Commits**: Never commit changes automatically unless explicitly requested by the user.
