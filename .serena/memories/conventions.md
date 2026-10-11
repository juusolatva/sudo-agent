# Conventions

- `keys` uses `std::sync::Mutex` (not tokio's): guard is `!Send`, so never hold it across `.await`; scope locks tightly, copy/clone what's needed, drop before prompting the user or awaiting.
- Never hold the keys lock while waiting on approval/passphrase prompts (prompts can block indefinitely). Exception by design: `SudoAgent::requests` (fair tokio mutex, no data) is held across the whole `sign()` to serve requests one at a time.
- Runtime output uses `log!` (single `write()` per line), not `eprintln!`, so log lines can't split prompts on the shared terminal.
- Errors: return `AgentError` from `Session` methods; idiomatic `?` propagation; avoid new `unwrap()` outside lock poisoning.
- Prompt code goes behind a backend-agnostic abstraction (secret input + yes/no confirm); callers must not depend on the terminal backend directly.
- Every `Prompter::confirm()` backend must honour its `CancellationToken`: withdraw the question, *then* return `Err` (so the caller's log line follows the prompt).
- No blocking file I/O inside `async fn`: `tokio::fs` or `spawn_blocking` (SonarQube `rust:S7493`).
- Formatting: default `rustfmt` (no rustfmt.toml/clippy.toml); clippy defaults.
- Git: never commit, not even for version bumps/publishing; the user makes all commits.
