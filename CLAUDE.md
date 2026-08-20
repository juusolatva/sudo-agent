# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

This is an early-stage skeleton (see commit "add preliminary files for a Rust project"). `Cargo.toml` currently declares **no dependencies**, but `src/main.rs` already imports `tokio`, `async_trait`, `ssh-agent-lib`, and `ssh-key` — the crate does not build yet. Before making functional changes, add the missing dependencies with `cargo add` (or edit `Cargo.toml` directly) matching the APIs already used in `src/main.rs`.

## What this is

`sudo-agent` is a lightweight, PAM-aware SSH agent daemon for time-bound sudo authentication. The intended design (from `src/main.rs`):

- A `CustomAgent` implements the `ssh-agent-lib` `Agent` trait and listens on a Unix socket (currently hardcoded to `/tmp/my_custom_agent.sock`).
- It holds an in-memory list of `KeyEntry` records (public key + `loaded_at` + `ttl`), guarded by a `Mutex`.
- `RequestIdentities` filters out any key whose `ttl` has elapsed since `loaded_at`, so keys are automatically time-bound/expiring — this is the core "time-bound sudo authentication" mechanism.
- `SignRequest` is the intended interception point for signing: checking expiration, triggering an approval prompt (desktop notification, PAM), and only then signing — this is currently `todo!()` and unimplemented.
- There's a commented-out sketch of an `ApprovalProvider` trait (`request_approval(server_identity, key_fp) -> bool`) suggesting the planned approval flow is pluggable/async.

When implementing further, keep signing gated behind explicit approval + TTL checks — that's the entire point of the agent (short-lived, human-approved sudo credentials rather than long-lived static keys).

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
