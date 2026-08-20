# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

`Cargo.toml` has its real dependencies (`tokio`, `async-trait`, `ssh-agent-lib` 0.6.0, `ssh-key`) and `src/main.rs` builds cleanly against `ssh-agent-lib`'s actual API (`Session`/`Agent`/`listen`, not the older/hypothetical `handle(Request) -> Request` shape an earlier draft assumed). `cargo build` / `cargo clippy` are clean.

That said, it's still a minimal skeleton functionally: `sign()` is `todo!()`, nothing populates `keys` yet, and there's no PAM integration. **Current priority is the simplest possible working end-to-end version** — see `TODO.md`'s "Now" section for exactly what that means. Don't get pulled into the secondary items below (or in `TODO.md`) before that loop works.

## What this is

`sudo-agent` is a lightweight, PAM-aware SSH agent daemon for time-bound, human-approved sudo authentication — an alternative to a static sudo key that's trusted forever. The intent is that `sudo` (via a `pam_ssh_agent_auth`-style PAM module) challenges a key held by this agent instead of a password, and the agent only signs if the key hasn't expired and (eventually) a human approves.

Design, from `src/main.rs`:

- `CustomAgent` implements `ssh-agent-lib`'s `Session` trait (and is `Clone`, which makes it an `Agent` via the crate's blanket impl) and listens on a Unix socket (currently hardcoded to `/tmp/my_custom_agent.sock`).
- It holds an in-memory list of `KeyEntry` records (public key + `loaded_at` + `ttl`), guarded by a `Mutex`.
- `request_identities()` filters out any key whose `ttl` has elapsed since `loaded_at`, so keys are automatically time-bound/expiring — this is the core "time-bound sudo authentication" mechanism.
- `sign()` is the intended interception point for signing: checking expiration, triggering an approval prompt, and only then signing — this is currently `todo!()` and unimplemented. The approval prompt is a plain **yes/no confirm, not a passphrase re-prompt** (the passphrase is only needed once, at key-load time) — see `TODO.md`'s note on why.
- There's a commented-out sketch of an `ApprovalProvider` trait (`request_approval(server_identity, key_fp) -> bool`) suggesting the planned approval flow is pluggable/async — see `TODO.md`'s pinentry-style approach for where that's headed.

When implementing further, keep signing gated behind explicit approval + TTL checks — that's the entire point of the agent (short-lived, human-approved sudo credentials rather than long-lived static keys).

## Roadmap

See `TODO.md` for the full, tiered list. Summary:

- **Now**: `sign()` implemented for real, a terminal-based pinentry-style prompt used for both passphrase entry (on load, once) and per-signature approval (on sign, a plain yes/no — never a passphrase re-prompt), and a way to load a key at startup with the passphrase typed manually — no secrets manager yet.
- **Next** (committed direction, not yet scheduled): a configuration file (local-vs-remote approval, TTL-expiry warnings), non-terminal pinentry backends layered onto the terminal-first one, and a secrets-manager-backed passphrase fetch that replaces/improves on the `~/.bashrc` `ssh-load`/`ssh-askpass-rbw` workaround (which does this today for stock `ssh-add` via `rbw`).
- **Someday** (only if genuinely motivated — not commitments, fine to drop entirely): Bitwarden SSH agent protocol interop (a different architecture than the `rbw` passphrase fetch — this agent becoming a client of another live agent), Windows' native OpenSSH agent from WSL2 via `npiperelay`, and hardening agent-forwarding exposure via OpenSSH's destination-restriction extensions (`ssh-agent-lib` already implements `restrict-destination` / `session-bind@openssh.com`, see its `key-storage.rs` example) — real security work, worth doing carefully or not at all, not worth half-doing.
- **Setup**: explicitly *not* an automated PAM config writer — a buggy one could break `sudo` on a live system, and distros diverge enough in PAM tooling (Fedora vs. Debian/Ubuntu, etc.) that "generic" automation isn't safe anyway. Instead: an installation guide with the exact `pam_ssh_agent_auth` stanza to paste in, plus a `--check`/dry-run in `sudo-agent` to validate config without touching the system.

Note on why TTL is tracked inside the agent rather than relying on `ssh-add -t`: it needs to be queryable/surfaceable on the *remote* machine too (e.g. an expiry warning shown where you're `sudo`-ing, not just inferred from local agent state) — a local `ssh-add -t` timer alone can't do that. See `TODO.md` for the full note.

Note on why per-signature approval is yes/no rather than a passphrase re-prompt: requiring the passphrase on every `sudo` would just reproduce ordinary `sudo`'s "type your password every time" with extra steps. The confirm step is doing something different — it's a sanity check ("did I mean to elevate right now") and a detection mechanism (a sign request you didn't make, e.g. from another root-privileged process on the same machine, becomes a prompt you see instead of a silent success). Both only work if approving stays cheap, hence yes/no. See `TODO.md` for the full note.

## Commands

```sh
cargo build          # compile
cargo run            # run the agent daemon
cargo check          # fast type-check
cargo test           # run tests (none exist yet)
cargo fmt             # format
cargo clippy          # lint
```

There is no single-test invocation yet since no tests exist. Once tests are added, use `cargo test <name>` to run one.
