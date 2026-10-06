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

- [ ] **No approval timeout**: an unanswered prompt waits forever, and
      later requests queue behind it. It should auto-deny after a while.
      Deferred on purpose: the right length is still undecided, and manual
      testing is easier without one.
- [ ] **Stale prompts**: if the client gives up (e.g. Ctrl-C on the remote
      `sudo`), its prompt stays on the terminal. Answering it is harmless
      (the signature goes nowhere), but it should be cancelled instead.
- [ ] **Ctrl-C at the agent's own prompt shuts the agent down** (cleanly
      now: keys dropped, socket removed, the waiting client gets a
      failure). Open question: should Ctrl-C at a prompt deny just that
      request instead? That needs cancellable prompts, the same mechanism as
      the timeout and stale-prompt items.
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
needs an answer. Design, agreed 2026-10-07:

- **Two sockets.**
  - `agent.sock` is the one that gets forwarded. It only lists identities
    and signs (approval-gated), plus at most a read-only status query.
  - `control.sock` is never forwarded. It speaks the full agent protocol
    (add/remove keys, lock) plus our own commands (status, stop, approve).

  Nothing on a server can add keys or answer approvals through forwarding.
  This also covers servers where forwarding the full agent is a concern.
- **Keys are added from a client, not at daemon startup.** The daemon has no
  terminal to ask for a passphrase, so `ssh-add` (or `sudo-agent add`)
  decrypts the key and sends it over `control.sock`. The daemon never prompts
  for passphrases. `ssh-add -t` lifetimes become the TTL, still tracked and
  enforced inside the agent (invariant 1), optionally capped by a configured
  maximum.
- **Approvals are answered by pinentry (desktop popup) or by
  `sudo-agent approve` in any terminal.** Those two are the focus. Today's
  foreground mode, with its prompt on the daemon's own terminal, stays as a
  backup as long as it causes no problems. Routing: an attached `approve`
  client is asked first; otherwise pinentry if a desktop session is
  available; otherwise deny and log.

Steps:

1. [ ] **Daemon + control socket + `ssh-add` + status.**
   - Split the binary into `sudo-agent serve` and client subcommands.
   - Add `control.sock`, which accepts `AddIdentity`/`AddIdConstrained`
     (lifetime → TTL), `RemoveIdentity`, `RemoveAllIdentities` and lock.
   - Keep `--key` on `serve` for foreground use. Until steps 2–3 land,
     approvals still use the foreground terminal prompt, so nothing
     regresses.
   - `~/.bashrc`'s `ssh-load` (`rbw` → `SSH_ASKPASS` → `ssh-add -t 240m`)
     should work against `control.sock` almost unchanged.
   - **`sudo-agent status`**: loaded keys and time left on each. It replaces
     `ssh-status` and its `.ssh_expiry` file, which only guess the TTL from
     outside the agent. Locally it goes over `control.sock`. On a server, a
     read-only vendor extension on `agent.sock` (`ssh-agent-lib` supports
     `extension()`) answers "how long is left" through the forwarded
     `SSH_AUTH_SOCK`, which is the "surface the TTL remotely" goal from
     invariant 1. Anyone who can reach that socket can already list the
     keys, so exposing the TTL there is acceptable.
2. [ ] **pinentry approvals.**
   - Spawn `pinentry` only when a request arrives and speak its Assuan
     protocol: `CONFIRM` for yes/no, `SETDESC`/`SETPROMPT` for the
     request details.
   - Talk to it directly, with no crate dependency; the `pinentry` package
     comes with GnuPG on most desktops.
   - `SETTIMEOUT` gives this backend the approval timeout, once a length
     is chosen.
   - Check before trusting it: whether a popup that grabs the keyboard
     while you're typing can be approved by a stray Enter or Space (the
     GUI version of the type-ahead problem the terminal prompt already
     handles).
   - A daemon started by systemd needs `DISPLAY`/`WAYLAND_DISPLAY` and
     `DBUS_SESSION_BUS_ADDRESS` in its environment. Most desktops import
     them into the user manager; Cinnamon on the laptop does.
3. [ ] **systemd user unit** (`sudo-agent.service`) and docs for
   `systemctl --user enable --now sudo-agent`.
   - Logs go to `journalctl --user -u sudo-agent` for free (stderr).
   - Restarting it drops all keys, which is intended.
   - `setsid -f sudo-agent serve` is the documented fallback for machines
     without systemd. No self-daemonizing (double fork).
4. [ ] **`sudo-agent approve`**: a terminal client that connects to
   `control.sock`, shows pending requests and takes `y/N`, with the same
   type-ahead flush as the foreground prompt.
   - This is the terminal backend from now on (invariant 3). It works from
     any terminal, including when SSH'd into the laptop with no desktop.

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
