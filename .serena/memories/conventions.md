# Conventions

- `keys` uses `std::sync::Mutex` (not tokio's): guard is `!Send`, so never hold it across `.await`; scope locks tightly, copy/clone what's needed, drop before prompting the user or awaiting.
- Never hold the keys lock while waiting on approval/passphrase prompts (prompts can block indefinitely).
- Errors: return `AgentError` from `Session` methods; idiomatic `?` propagation; avoid new `unwrap()` outside lock poisoning.
- Prompt code goes behind a backend-agnostic abstraction (secret input + yes/no confirm); callers must not depend on the terminal backend directly.
- Formatting: default `rustfmt` (no rustfmt.toml/clippy.toml); clippy defaults.
- Git: never commit unless the user explicitly asks.
