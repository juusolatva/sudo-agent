# TODO

## Now

The current priority is the core loop end-to-end, nothing else:

- [x] Implement `sign()` for real: check TTL, gate on approval, sign, return.
- [x] A pinentry-style prompt used for **both** the key passphrase (on load)
      and per-signature approval (on sign) — one prompt abstraction, two call
      sites, but two different kinds of prompt: the passphrase prompt asks
      for a secret (once, at load time); the approval prompt is a plain
      **yes/no confirm with no passphrase involved** (every sign). Start with
      a **terminal-based** backend (simplest thing that works, and needs to
      keep working in-terminal even after other backends exist), shaped so a
      GUI/other backend can be swapped in later without touching the calling
      code.
- [x] A way to load a key into `keys` (currently nothing populates it —
      `AddIdentity` handling, or a simple CLI/config-driven load at
      startup). Passphrase entry is manual for now — no secrets-manager
      integration needed yet.
- [x] Manual end-to-end test: agent running, `ssh-add -l` / `SSH_AUTH_SOCK`
      pointed at its socket, `sudo` configured via `pam_ssh_agent_auth` to
      challenge it, confirm a full elevate-with-approval cycle works.
      Procedure and results: `docs/manual-e2e.md` (agent on the laptop,
      `sudo` on a server with the agent forwarded). Passed 2026-10-07 on
      openSUSE with `pam_ssh_agent_auth` 0.10.4.

Known gaps from implementing the above. None of them blocks the end-to-end
test, but they should be fixed before calling the core loop done:

- [x] **Approval timeout**: an unanswered prompt is denied after
      `--approval-timeout` (default `2m`), and the terminal is freed for the
      next request. 2 minutes is a compromise for the foreground prompt.
      Revisit per backend once the others exist: pinentry 30–60 s, the
      `sudo-agent approve` client maybe up to 5 min.
- [x] **Stale prompts**: a prompt is withdrawn (via the `CancellationToken`
      passed to `Prompter::confirm()`) when it can no longer lead anywhere:
      - The client goes away: `sign()` watches the client socket (a
        duplicated fd under `AsyncFd`) for a hang-up, e.g. the SSH connection
        closing. A request still queued just leaves the queue. Ctrl-C on the
        remote `sudo` does *not* trigger this: `sudo` ignores it while
        `pam_ssh_agent_auth` waits for the agent.
      - The key expires (found in testing 2026-10-11: the prompt stayed until
        answered, and `y` was refused anyway). The reaper removes keys 250 ms
        after their deadline, so its log line follows the withdrawn prompt
        instead of landing inside it.
      Verified against a server 2026-10-11 (e2e cases 6 and 8).
- [x] **Ctrl-C at the agent's own prompt** denies just that request (the
      same cancellation path). Ctrl-C with no prompt open, or a second one
      within 2 s, still stops the agent, so a stream of requests can't keep
      it from stopping. Under the planned daemon this only applies to the
      foreground backup prompt.
- [x] **Socket removed on shutdown**: SIGINT/SIGTERM/SIGHUP and startup
      failures remove it (only if the file is still the one this process
      bound). The one exception is a kill during passphrase entry, where the
      default SIGINT action is kept because the terminal has echo off; the
      next start cleans that socket up as stale.

## Why TTL lives in the agent, not in `ssh-add -t`

Stock `ssh-add -t <mins>` already gives OpenSSH's agent a self-expiring key,
enforced locally. That's *not* what `KeyEntry.ttl` is duplicating for its own
sake — the point of tracking it inside `sudo-agent` itself is that the timer
then exists somewhere that can be queried and surfaced remotely too (e.g. a
warning that a key is about to expire, shown on the *remote* machine you're
`sudo`-ing on, not just inferred from local agent state). A plain local
`ssh-add -t` timer can't do that.

## Why per-signature approval is yes/no, not a passphrase re-prompt

The passphrase is only ever needed once, to decrypt the key into the agent's
memory at load time — TTL governs how long it stays usable after that. The
per-signature approval step is deliberately **not** another passphrase
prompt: requiring the passphrase on every `sudo` would just reproduce
ordinary `sudo`'s "type your password every time" annoyance with extra
steps, which isn't the point.

The confirm step exists for two different reasons:

1. **Sanity check** — a moment to notice "wait, did I actually mean to
   elevate right now" before it happens, the way WebAuthn/FIDO2 touch-to-sign
   or `ssh-add -c`'s confirm dialog work.
2. **Visibility/detection** — anyone able to reach the agent's socket (in
   particular another process with root on the same machine, which could
   otherwise use a loaded key silently) triggers a confirm prompt *you* see.
   It doesn't cryptographically stop a determined root-level attacker from
   extracting the key from agent memory, but it does mean a signing request
   you didn't make becomes visible instead of silent.

Both reasons only work if approving is cheap (a keypress), so the prompt
has to stay yes/no.

## Next

Committed direction, comes after "Now" — not yet scheduled, but intended.

### Background daemon (do these in order)

Goal: the agent runs on its own, independent of any terminal (closing a
terminal must not kill it or drop keys), and reacts only when a request
needs an answer. Design agreed 2026-10-07; open decisions settled
2026-10-12.

#### Design

- **CLI.** `sudo-agent serve` runs the agent. The bare form
  (`sudo-agent --key …`, i.e. today's invocation) keeps working as an alias
  for `serve`. Other subcommands are clients (`approve`, later `stop`). The
  release that adds subcommands is 0.2.0.
- **Two sockets.**
  - `agent.sock` is the one that gets forwarded. It only lists identities
    and signs (approval-gated). Later at most a read-only status extension.
  - `control.sock` is never forwarded. It speaks the full agent protocol
    (add/remove keys, later lock) plus our own commands as vendor
    extensions (approve, later status and stop).

  Nothing on a server can add keys or answer approvals through forwarding.
- **Socket paths.** Each socket has its own flag and environment variable;
  a flag beats the variable, which beats the default. Names (agreed
  2026-10-12): `--agent-socket` (with today's `--socket` kept as an alias)
  / `SUDO_AGENT_SOCKET`, and `--control-socket` /
  `SUDO_AGENT_CONTROL_SOCKET`. Defaults: `$XDG_RUNTIME_DIR/sudo-agent/`
  `agent.sock` and `control.sock`; the cache-dir fallback gets
  `agent-<hostname>.sock` and `control-<hostname>.sock`. Clients
  (`approve`, `stop`) look up the control socket the same way.
- **`control.sock` is protected in three layers**, so an accidental
  `ForwardAgent …/control.sock` (e.g. a copy-paste mistake) doesn't hand a
  server control over keys or approvals. File permissions alone can't stop
  that: the forwarding `ssh` runs as the user.
  1. **Refuse connections that come through `ssh`.** OpenSSH ≥ 8.9 sends
     `session-bind@openssh.com` on every agent connection it uses for a
     login or forwards. A `control.sock` connection that sends it is
     refused for good (every later request on it fails), with a warning
     in the log.
  2. **Same user only.** The peer's uid (`SO_PEERCRED`) must equal the
     agent's.
  3. **Tripwire.** Refuse when the peer process is `ssh` (its
     `/proc/<pid>/exe`), for clients older than 8.9. A heuristic, logged
     as such.
- **Keys are added from a client, not at daemon startup.** `ssh-add`
  decrypts the key and sends it over `control.sock`; the daemon never
  prompts for passphrases. `--key` on `serve` stays for foreground use.
  The daemon starts with no keys, and restarting it drops them all
  (intended).
  - **TTL cap policy** (decided 2026-10-11):
    - A lifetime above the cap is **clamped** to it, and the agent logs
      `lifetime 12h capped to 8h`. Refusing would leave `ssh-add` with only
      "Could not add identity", because the protocol can't carry a reason.
    - A key added with **no lifetime** (`ssh-add` without `-t`) gets the
      default TTL (`--ttl`, 15m), never "until removed".
    - The cap defaults to **8h** (`--max-ttl`, already enforced on
      `--ttl`). A `--ttl` above it is a startup error rather than a clamp:
      the user typed it and the agent can say why.
  - **`ssh-add` options:**
    - `-c` (confirm each use): accepted and ignored; every signature is
      confirmed anyway.
    - `-h` (destination restriction) and any unknown constraint: the key is
      **refused** and the reason logged. Silently ignoring a restriction
      the user asked for would give a false sense of safety.
    - Re-adding a key that is already loaded replaces it and **restarts
      its TTL** (with the new lifetime and comment). That is how a session
      is extended: the passphrase is typed again (invariant 2).
- **Time left, visible remotely: in the key comment.** Identities listed on
  either socket carry the time left in their comment, as
  `laptop (12m left)` (agreed 2026-10-12), so plain
  `ssh-add -l` shows it on any server with nothing installed there, and
  locally against `control.sock`. Comments are display-only;
  `pam_ssh_agent_auth` ignores them. This replaces `ssh-status` and its
  `.ssh_expiry` file, which only guess from outside the agent. A status
  extension and `sudo-agent status` come later (see "Later").
- **Approvals are answered by pinentry (desktop popup) or by
  `sudo-agent approve` in any terminal**; the foreground prompt on
  `serve`'s own terminal stays as a backup. **Routing: every available
  backend is asked at once; the first answer wins and the others are
  withdrawn** (their `CancellationToken`). Each backend keeps its own
  timeout. With no backend available the request is denied and logged.
- **`approve` protocol: vendor extensions on `control.sock`**: one that
  waits for the next pending request (long poll) and one that answers a
  request by id. It reuses the agent codec, and the `control.sock`
  protections apply to it automatically.
- **Lifecycle.**
  - **One instance per user**: one agent already serves any number of
    remote destinations. `serve` refuses to start while either socket
    answers (today's stale-socket check, applied to both).
  - systemd **user service**, no socket activation; `setsid -f
    sudo-agent serve` is the fallback without systemd (no double fork).
  - **Log lines carry timestamps** in `serve`, except when stderr is the
    journal (`JOURNAL_STREAM` set), which stamps them itself.
  - Stopping: signals / `systemctl --user stop` first; `sudo-agent stop`
    later for convenience.
- **Gap until step 2, documented:** a `serve` with no terminal has no
  approval backend before pinentry lands, so it denies (and logs) every
  request. The sockets, `ssh-add` and the key listing still work and can be
  tested that way.

#### Steps

- [x] **0. Prep, no visible change.** Done 2026-10-12.
   - Socket-level tests in `src/server.rs`: the agent served on a temp
     socket via the real `socket::bind`, driven by `ssh_agent_lib`'s
     `Client`. They pin listing, signing, refusal keeping the connection
     usable, hang-up withdrawing the prompt (through the real
     `new_session`), shutdown removing the socket, and that `agent.sock`
     answers `Failure` to add, add-constrained, remove, remove-all, lock,
     unlock and extensions (`session-bind@openssh.com` included), without
     prompting. Both the refusal and the hang-up test were checked to fail
     when the behaviour is broken.
   - Serving moved out of `run()` into `server::serve(listener, agent,
     shutdown)`, the one place step 1b extends to two listeners.
   - Shared test helpers: `keys::testing::entry`,
     `prompt::testing::{ScriptedPrompter, ApprovesAfter}`.
- [x] **1a. Subcommands and socket flags.** Done 2026-10-12.
   - `src/cli.rs`: `serve` subcommand; the bare form is the same `ServeArgs`
     flattened at the top level (`args_conflicts_with_subcommands`, so
     options before `serve` are rejected). `--ttl` > `--max-ttl` is checked
     there.
   - `--agent-socket` (`--socket` kept as a hidden alias) and
     `SUDO_AGENT_SOCKET`, resolved by `socket::choose_path`: flag, then the
     variable if set **and non-empty** (an empty one counts as unset; clap's
     own `env` treats it as a missing value, so it isn't used), then the
     default.
   - `--control-socket` / `SUDO_AGENT_CONTROL_SOCKET` moved to 1b: until
     `control.sock` exists they would be accepted and do nothing.
   - Candidate for 0.2.0 once 1b lands.
- [ ] **1b. `control.sock` and `ssh-add`.** Second listener with the three
   protection layers and its `--control-socket` / `SUDO_AGENT_CONTROL_SOCKET`
   (via `socket::choose_path`); `AddIdentity`/`AddIdConstrained`, `RemoveIdentity`,
   `RemoveAllIdentities`; lifetime → TTL with the cap policy; the `ssh-add`
   option rules above; single-instance check on both sockets. `serve` may
   start with no keys. `~/.bashrc`'s `ssh-load` (`rbw` → `SSH_ASKPASS` →
   `ssh-add -t 240m`) should work against `control.sock` almost unchanged.
   New e2e cases: `ssh-add` against `control.sock`; a forwarded
   `control.sock` is refused.
- [ ] **1c. Time left in key comments** on both sockets. New e2e case:
   `ssh-add -l` on a server shows the time left.
- [ ] **2. pinentry approvals**, plus the routing scaffold (all backends at
   once, first answer wins).
   - Spawn `pinentry` only when a request arrives and speak its Assuan
     protocol: `CONFIRM` for yes/no, `SETDESC`/`SETPROMPT` for the
     request details. Cancellation kills the child.
   - Talk to it directly, with no crate dependency; the `pinentry` package
     comes with GnuPG on most desktops.
   - Still to decide here: which program (a `--pinentry` flag; the default
     must skip curses/tty variants, since a daemon has no terminal) and its
     own timeout via `SETTIMEOUT` (30–60 s likely suits a popup better than
     the terminal's 2 min).
   - Check before trusting it: whether a popup that grabs the keyboard
     while you're typing can be approved by a stray Enter or Space (the
     GUI version of the type-ahead problem the terminal prompt already
     handles).
   - A daemon started by systemd needs `DISPLAY`/`WAYLAND_DISPLAY` and
     `DBUS_SESSION_BUS_ADDRESS` in its environment. Most desktops import
     them into the user manager; Cinnamon on the laptop does.
- [ ] **3. systemd user unit** (`sudo-agent.service`) and docs for
   `systemctl --user enable --now sudo-agent`.
   - Logs go to `journalctl --user -u sudo-agent` (stderr); timestamps in
     `serve`'s own log lines, skipped under the journal.
   - Restarting it drops all keys, which is intended.
   - `setsid -f sudo-agent serve` is the documented fallback for machines
     without systemd.
- [ ] **4. `sudo-agent approve`**: a terminal client on `control.sock`
   (the long-poll extension) that shows pending requests and takes `y/N`,
   with the same type-ahead flush and `sanitize()`d text as the foreground
   prompt; it joins the routing. Its own timeout, maybe up to 5 min.
   - This is the terminal backend from now on (invariant 3). It works from
     any terminal, including when SSH'd into the laptop with no desktop.

Re-run the server cases in `docs/manual-e2e.md` after 1b, 2 and 4: each
touches signing or prompting.

#### Later (agreed, after steps 0–4)

- **`sudo-agent stop`** over `control.sock`, so users don't need
  `systemctl` or signals.
- **Lock/unlock** (`ssh-add -x` / `-X`) on `control.sock` only: while
  locked, every request is refused without a prompt (a "pause" when away
  from the desk).
- **Status extension and `sudo-agent status`**: a read-only vendor
  extension (`name@domain`, e.g. `status@sudo-agent.juusolatva.github.io`)
  on both sockets with exact time left per key; `sudo-agent status` on a
  server talks to the forwarded `SSH_AUTH_SOCK`. Needs `sudo-agent`
  installed on the server, which is why key comments come first.

### Other

- [ ] **Configuration file** covering at least:
  - Whether approval confirmation happens on the **local** machine or on the
    **remote** machine being `sudo`'d on.
  - Warning thresholds/behavior as a key's TTL approaches expiry.
  - Grows as other items land: which approval backend (pinentry / `approve`
    client / foreground), maximum TTL, approval timeout.
- [ ] **Native secrets-manager passphrase fetch.** Mostly covered by step 1,
      since `ssh-load` with `rbw` + `SSH_ASKPASS` + `ssh-add` keeps working
      against `control.sock`. A native fetch in `sudo-agent add` (no askpass
      shim) is optional polish on top.
- [ ] **Show the forwarding chain in the approval prompt.** Today a request
      over a forwarded agent only shows the local client (`ssh -A bastion`),
      so multi-hop requests and login-vs-forwarded use look identical. Handle
      `session-bind@openssh.com` (OpenSSH ≥ 8.9; `ssh-agent-lib` decodes it
      as `SessionBind` and has `verify_signature()`), record the verified
      host-key chain + `is_forwarding` per connection, and show it in the
      prompt with names from `~/.ssh/known_hosts` where unhashed
      (fingerprints otherwise). Caveats to surface, not hide: only the first
      hop is verified by the local client — later hops are as trustworthy as
      the hosts before them; a pre-8.9 hop ends the chain ("unknown beyond
      X"); the remote *process* (sudo vs. anything else) is never visible.
      Display only, no enforcement — the groundwork for the destination
      restriction under "Someday", not a substitute for it.

## Someday (only if bothered — not committed, fine to drop)

These are real ideas but disconnected enough from the core "gate sudo behind
TTL + approval" value that they shouldn't be treated as roadmap commitments.
Pick up only if genuinely motivated to; dropping any of them costs nothing.

- **Agent-forwarding exposure (the `ProxyJump` problem)**: plain `ssh -A`
  forwarding exposes the agent socket on every intermediate host in the
  chain — anyone with access to a jump host can talk to the forwarded agent
  for as long as the connection lives, which is why people reach for
  `ProxyJump`/`ProxyCommand` instead of `-A`. Since this agent already gates
  every signature on TTL + approval, forwarding exposure is less
  catastrophic here than with a normal agent, but a real fix means using
  OpenSSH's destination-restriction extensions (`ssh-agent-lib` already
  implements `restrict-destination` / `session-bind@openssh.com`, see its
  `key-storage.rs` example). This is genuine protocol-level security work —
  worth doing carefully if pursued, not worth doing half-way (a partial
  implementation is worse than none: false sense of safety).
- **One agent for logins and sudo**: SSH logins signed without approval,
  `sudo` still approval-gated, so a single agent covers both. Strictly
  optional: two agents (a normal one for logins, `sudo-agent` forwarded
  via `ForwardAgent <socket path>`) already work.
  - The trustworthy discriminator is `session-bind@openssh.com`: a
    connection bound by the local `ssh` client for user authentication
    (`is_forwarding = false`) versus one that arrived through forwarding.
  - The signed data alone is not enough: a forwarded host can craft a
    request that looks like login auth, which is the classic
    agent-forwarding hijack.
  - Builds on the forwarding-chain item under "Next".
- **Bitwarden SSH agent protocol interop**: not the `rbw` CLI passphrase
  fetch above — this is `sudo-agent` proxying to Bitwarden desktop's own
  SSH-agent-protocol implementation as a key source. A materially different
  architecture (this agent becoming a client of another live agent), wanted
  later purely for convenience.
- **Windows' native OpenSSH agent from WSL2, via `npiperelay`**: lets keys
  live in the Windows agent while `sudo-agent` runs on the Linux side. A
  separate transport-bridging problem (Windows named pipes ↔ Unix socket),
  useful mainly as a personal-convenience feature on one specific machine
  rather than core to the project.

## Setup: documentation, not automation

Explicitly **not** doing an automated PAM config writer. The failure mode
(a buggy writer breaking `sudo` on a live system) is worse than the
inconvenience it would save, and distros diverge enough in how they handle
this (e.g. Fedora's PAM tooling isn't the same as Debian/Ubuntu's) that a
"generic" writer would need real per-distro logic to be safe anyway.

- [ ] Installation guide instead: the exact `pam_ssh_agent_auth` PAM stanza
      to paste in, socket path/env var setup, and a `--check`/dry-run in
      `sudo-agent` itself to validate a config without touching the system.
