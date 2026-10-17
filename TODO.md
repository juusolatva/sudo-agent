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
- [x] **1b. `control.sock` and `ssh-add`.** Done 2026-10-12; SonarQube
   Cloud clean. Verified on a server (e2e cases 9, 2, 6, 7). Released as
   0.2.0 (with 0 and 1a).
   - `src/control.rs`: `ControlAgent` / `ControlConnection` wrap the shared
     `SudoAgent` and reuse `Connection` for listing and approval-gated
     signing (so `ssh-add -l` / `-T` work there too). Add, add-constrained,
     remove, remove-all; `-t` → TTL via `keys::TtlPolicy` (cap logged,
     0 = default like OpenSSH's "no limit"); `-c` accepted; `-h`, unknown
     constraints, certificates and smartcard keys refused with a logged
     reason; re-adding replaces and restarts the TTL. Lock/unlock refused
     as not supported (a "Later" item).
   - The three protection layers, each logged once per connection: uid
     check and `ssh` tripwire at connect (`refusal`), `session-bind`
     refusing the connection for good (`extension`).
   - `agent.sock` now logs refused key management (add, remove, lock,
     smartcard): through forwarding that means a server tried it.
     Extensions there stay unlogged, as `ssh` sends `session-bind` on every
     forwarded connection.
   - `--control-socket` / `SUDO_AGENT_CONTROL_SOCKET` (via
     `socket::choose_path`); `socket::default_path(name)`; startup refuses
     the same path for both and a live agent on either; `--key` optional.
   - Verified locally against real OpenSSH 10.2 with a private `sshd`
     (`docs/manual-e2e.md`, 2026-10-12): all three layers fire, including
     `session-bind` alone (renamed `ssh`). OpenSSH only forwards when the
     client has an agent of its own, documented in README and e2e.
- [x] **1c. Time left in key comments** on both sockets. Done 2026-10-17;
   verified on a server (e2e case 12). Released as 0.2.1.
   - Shown as `<comment> (14m30s left)`, in the format the approval prompt
     already uses (`keys::format_remaining`: seconds below an hour, minutes
     above).
- [ ] **2. pinentry approvals**, plus the routing scaffold (all backends at
   once, first answer wins). Split into 2a–2c, each tested before the next.
   Decided 2026-10-17:
   - The popup is a pinentry `CONFIRM` dialog (Allow / Deny buttons) with
     the same text as the terminal prompt. It never asks for a passphrase
     and sends no `SETKEYINFO` (no "save in password manager" offer).
     `SETPROMPT sudo-agent` too: `pinentry-gnome3` shows it as the heading
     of a `CONFIRM` dialog ("Message" without it; found in testing). The
     description ends with when the popup closes, so its timeout isn't
     mistaken for the key's time left (now shown as `12m30s left`, as in
     `ssh-add -l`, instead of `expires in 12m30s`).
   - A stray Enter or Space may approve a popup that appears while you're
     typing. That's accepted: you expect a popup for every `sudo` you run,
     and one you didn't start is still seen. sudo-agent makes remote `sudo`
     convenient; it isn't an intrusion detection tool.
   - Its own timeout, 60 s (`SETTIMEOUT`); the popup is easy to notice and
     expected.
   - The program is `pinentry` (the distro's wrapper or alternatives
     symlink, which gpg-agent uses too), overridable with `--pinentry`
     (needed on NixOS, or to pick a variant).
   - It's used only when `DISPLAY` or `WAYLAND_DISPLAY` is set. That only
     says a GUI pinentry *could* work, not that anyone is looking (stale
     after logout, screen locked), which routing tolerates: a popup that
     fails or times out is no answer, not a denial, and the other backends
     are asked at the same time.
   - The child runs in its own session (`setsid`), so a curses/tty variant
     picked by the wrapper can't take `serve`'s terminal (it fails instead)
     and Ctrl-C doesn't reach it. `PR_SET_PDEATHSIG(SIGKILL)` (spawned from
     an async worker thread, as it follows the spawning thread) and the
     60 s timeout clean up after a daemon that dies abruptly.
   - Talk to it directly over pipes, with no crate dependency.
- [x] **2a. Routing scaffold**, still with the terminal as the only backend:
   no visible change apart from log wording. Done 2026-10-17 (`src/routing.rs`);
   tested by the user in a terminal (approve/deny, Ctrl-C now logs `denied`,
   timeout, hang-up).
   - A router `Prompter` asks every available backend at once, each with a
     child `CancellationToken`. The first real answer (approve or deny)
     wins; the others are withdrawn and awaited, so their lines end before
     the log line. A backend that times out or fails just drops out; when
     all have, the request is denied with their reasons logged. No backend
     available: deny and log.
   - Backends tell an answer apart from no answer (today `confirm()`'s
     `Err` covers both). Ctrl-C at the terminal prompt becomes a deny
     answer, so it withdraws the other backends instead of dropping out.
   - Each backend says whether it's available (the terminal: `/dev/tty`
     opens). `passphrase()` (`--key` at startup) stays on the terminal.
   - `--approval-timeout` becomes the terminal prompt's timeout.
   - Tests with the scripted prompters: first answer wins and withdraws the
     rest, a failed backend doesn't deny while another can still answer,
     all failing denies, cancelling the request withdraws every backend.
- [x] **2b. pinentry client** (`src/pinentry.rs`), not wired in yet.
   Done 2026-10-17; the user checked the real popup (Allow, Deny/Escape/
   close, its own timeout, withdrawal closing the gnome3 window, and
   `pinentry-curses` failing cleanly without taking the terminal).
   - Spawn per request: pipes for stdin/stdout, stderr to `/dev/null`,
     `setsid` + `PR_SET_PDEATHSIG` in `pre_exec`, `kill_on_drop`.
   - Send `SETTITLE`, `SETDESC`, `SETOK Allow`, `SETCANCEL Deny`,
     `SETTIMEOUT`, `CONFIRM`; `OK` approves, only the cancel error (99)
     denies, timeout or anything else is no answer. Found probing: without a
     terminal `pinentry-tty` (what the wrapper picks with no display)
     answers "Not confirmed" (114) and `pinentry-curses` "Inappropriate
     ioctl", so 114 must not count as a denial (a real Deny is always 99,
     as there's no third button). Percent-escape `%`, CR and LF,
     keep lines under Assuan's 1000 bytes, and give every reply a deadline
     (a curses fallback may write screen codes into the pipe).
   - Withdrawing: SIGTERM, then SIGKILL after about a second, then reap.
   - Tests against a fake pinentry script in a temp dir (approve, deny,
     timeout, garbage, hang, cancel kills it, escaping), plus an
     `#[ignore]`d test that pops up the real one on the laptop.
- [ ] **2c. Wire pinentry into routing.** Candidate for 0.3.0. Implemented
   2026-10-17 (e2e cases 13–23); laptop cases passed 2026-10-17; the
   terminal-only server cases still to run.
   - `--no-pinentry` (added 2026-10-17 at the user's request): no popups,
     terminal only. Makes the terminal cases testable on a desktop, and
     suits anyone who'd rather not have a popup holding the keyboard.
   - `--pinentry <PROGRAM>` (default `pinentry`) and a 60 s pinentry
     timeout; available only with `DISPLAY`/`WAYLAND_DISPLAY`; the startup
     banner says which backends are in use, or why pinentry isn't.
   - Log lines name the backend that answered; repeated pinentry failures
     (e.g. a curses variant without a terminal) are logged once with a
     `--pinentry` hint, not on every request.
   - Docs: README, AGENTS.md, `docs/manual-e2e.md` cases.
   - Laptop checks: popup in the desktop session; Ctrl-C at the terminal
     prompt withdraws the popup; popup withdrawn on client hang-up and key
     expiry; `serve` over SSH without a display (curses fails cleanly, the
     terminal prompt still works); killing the daemon closes the popup
     (gnome3's window belongs to `gcr-prompter`). Then the server cases.
   - A daemon started by systemd needs `DISPLAY`/`WAYLAND_DISPLAY` and
     `DBUS_SESSION_BUS_ADDRESS` in its environment, and gets them only if
     the desktop imports them into the user manager before the service
     starts; that's step 3's problem (unit ordering or documented
     `import-environment`).
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
