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

- [ ] **Configuration file** covering at least:
  - Whether approval confirmation happens on the **local** machine or on the
    **remote** machine being `sudo`'d on.
  - Warning thresholds/behavior as a key's TTL approaches expiry.
  - Grows as other items below land (which secrets backend, which prompt
    backend).
- [ ] **Non-terminal pinentry backends** (GUI pinentry, desktop notification)
      layered onto the terminal-first prompt from "Now." A pinentry spawned
      only when a request arrives would leave the terminal free the rest of
      the time (see "Run in the background").
- [ ] **Run in the background.** Today the agent has to own a foreground
      terminal because that's where approvals are asked. Ways out, still
      undecided:
  - an on-demand pinentry for approvals (above): GUI pinentry needs a
    desktop session, `pinentry-curses`/`-tty` still need a terminal;
  - a systemd user service, with a GUI or notification prompt;
  - a small `sudo-agent approve` client that answers pending requests from
    whatever terminal you're in.

  The terminal backend must keep working either way (invariant 3).
- [ ] **`sudo-agent status`**: report the loaded keys and time left on each.
      This replaces `~/.bashrc`'s `ssh-status` and its `.ssh_expiry`
      timestamp file, which only guess the TTL from outside the agent.
  - Query the running agent through a vendor extension message over the
    same socket (`ssh-agent-lib` supports `extension()`). That way it also
    works on a server through the forwarded `SSH_AUTH_SOCK`, which is the
    "surface the TTL remotely" goal from invariant 1.
  - Anyone who can reach the socket could read the TTL that way; that's
    acceptable, since they can already list the keys.
- [ ] **Secrets-manager-backed passphrase fetch**, replacing manual entry.
      `~/.bashrc`'s `ssh-load`/`ssh-askpass-rbw` already does this today for
      stock `ssh-add`, via `rbw` (Bitwarden CLI) + `SSH_ASKPASS` — the goal
      is for `sudo-agent` to replace and improve on that workaround (native
      fetch tied to the same pinentry-style prompt used for approvals), not
      just reimplement it as-is.
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
