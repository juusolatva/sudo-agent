# sudo-agent

[![crates.io](https://img.shields.io/crates/v/sudo-agent.svg)](https://crates.io/crates/sudo-agent)
[![Build](https://github.com/juusolatva/sudo-agent/actions/workflows/build.yml/badge.svg)](https://github.com/juusolatva/sudo-agent/actions/workflows/build.yml)
[![Security](https://github.com/juusolatva/sudo-agent/actions/workflows/security.yml/badge.svg)](https://github.com/juusolatva/sudo-agent/actions/workflows/security.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=juusolatva_sudo-agent&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=juusolatva_sudo-agent)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=juusolatva_sudo-agent&metric=coverage)](https://sonarcloud.io/summary/new_code?id=juusolatva_sudo-agent)
[![License: MIT](https://img.shields.io/crates/l/sudo-agent.svg)](LICENSE)

A lightweight SSH agent for **time-bound, human-approved `sudo`**.

Instead of typing your password for every `sudo` on a remote server, or
trusting a long-lived key forever, `sudo` (via [`pam_ssh_agent_auth`]) asks
this agent to sign a challenge. The agent signs only if:

1. the key is still within its time-to-live (TTL), and
2. you approve that specific request with a yes/no prompt.

[`pam_ssh_agent_auth`]: https://github.com/jbeverly/pam_ssh_agent_auth

> [!WARNING]
> **Experimental.** This is early software that hasn't been audited.
> It works end to end, but expect rough edges and breaking changes.
> Keep password authentication as a fallback (see [Server setup](#server-setup)).
> Linux only.

## How it works

```
your machine                                       server
────────────                                       ──────
ssh-add ─► control.sock ─┐                         sudo
                         ▼                           └─ pam_ssh_agent_auth
              sudo-agent: holds keys until                │ "sign this challenge"
              their TTL ends, asks "Allow? [y/N]"         │
                         ▲                                │
                         └─ agent.sock ◄── forwarded ◄────┘
```

- **Passphrase once.** It's asked for once, when the key is loaded (by
  `ssh-add`, or by the agent for `--key`). After that, each signature only
  needs a `y`.
- **TTL inside the agent.** A key's TTL starts when it's loaded. Keys are
  dropped (and zeroized) when their time is up. The clock keeps counting
  while the machine is suspended. `ssh-add -l` shows the time left after
  each key's comment, e.g. `laptop (14m30s left)`, on a server you've
  forwarded the agent to as well as locally.
- **Every signature is approved**, in a pinentry popup, at the agent's
  terminal, or in [`sudo-agent approve`](#approving-from-any-terminal) in
  any terminal, whichever you answer first; the others close. The prompt
  shows which local process is asking and which key it wants, so a request
  you didn't start (for example from someone else with access to the
  forwarded socket) is visible rather than silent. In the popup, click
  Allow; Deny, Escape or closing it denies. At a terminal, approving
  takes `y` or `yes` plus Enter, and keys typed before the prompt appeared
  are discarded; anything else denies. With no answer anywhere in time, the
  request is denied.
- **Two sockets.** `agent.sock` is the one you forward: it can only list
  keys and ask for signatures. `control.sock` is for adding and removing
  keys (`ssh-add`) and is never forwarded; see [Security
  notes](#security-notes).
- **One request at a time.** Concurrent requests queue, and every approval
  and refusal is logged.

## Install

```sh
cargo install --locked sudo-agent
```

`--locked` builds with the dependency versions this release was tested and
audited with. Or from a checkout: `cargo build --release --locked`.

## Usage

Start the agent on the machine that holds your key:

```sh
sudo-agent serve
# 2026-10-20 14:03:12 Agent listening on /run/user/1000/sudo-agent/agent.sock
# 2026-10-20 14:03:12 Control socket on /run/user/1000/sudo-agent/control.sock (for ssh-add; never forward it)
# 2026-10-20 14:03:12 Approvals: a pinentry popup, sudo-agent approve or this terminal, whichever answers first
# 2026-10-20 14:03:12 No keys loaded yet; add one with: SSH_AUTH_SOCK='/run/user/1000/sudo-agent/control.sock' ssh-add <key>
# 2026-10-20 14:03:12 Forward it with: ssh -o ForwardAgent='/run/user/1000/sudo-agent/agent.sock' <host>
```

Everything goes to stderr, each line starting with the local time (left out
when stderr is the systemd journal, which adds its own).

`serve` can be left out: `sudo-agent [OPTIONS]` does the same, as in 0.1.

### Adding keys

With `ssh-add` through the control socket, while the agent runs:

```sh
SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/sudo-agent/control.sock ssh-add -t 4h ~/.ssh/id_ed25519
```

- `-t` sets the key's TTL, cut down to `--max-ttl` if it's longer (the agent
  logs it). Without `-t` (or with `-t 0`) the key gets `--ttl`: a key never
  stays until removed.
- Adding a key that is already loaded replaces it and restarts its TTL;
  that's how you extend a session.
- `-l` lists keys with their time left, `-d` removes one, `-D` removes all.
- `-c` is accepted (every signature is approved anyway). `-h` (destination
  restrictions) and other constraints are refused rather than silently
  ignored, as are certificates and smartcard keys.

The passphrase is `ssh-add`'s business, so any way of supplying it works;
`sudo-agent` only receives the decrypted key. For example, an
`SSH_ASKPASS` helper that reads it from a password manager (here `rbw`,
a Bitwarden client):

```sh
#!/bin/sh
# ~/.local/bin/askpass-rbw: $1 is ssh-add's prompt, which names the key.
case "$1" in
    *id_ed25519*) exec rbw get ssh-passphrase-id_ed25519 ;;
    *) exit 1 ;;
esac
```

```sh
SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/sudo-agent/control.sock \
    SSH_ASKPASS=$HOME/.local/bin/askpass-rbw SSH_ASKPASS_REQUIRE=force \
    ssh-add -t 4h ~/.ssh/id_ed25519
```

Or load keys at startup, with the passphrase asked in the agent's terminal:
`sudo-agent serve --key ~/.ssh/id_ed25519` (repeatable).

### Options

| Option | Default | |
|--------|---------|-|
| `--key <PATH>` | none | OpenSSH private key to load at startup; repeatable |
| `--ttl <DURATION>` | `15m` | TTL for `--key` keys and for `ssh-add` without `-t` (`90s`, `15m`, `8h`) |
| `--max-ttl <DURATION>` | `8h` | Longest TTL a key may have: a longer `--ttl` is an error, a longer `ssh-add -t` is cut down |
| `--approval-timeout <DURATION>` | `2m` | How long the agent's terminal prompt and [`sudo-agent approve`](#approving-from-any-terminal) wait for an answer |
| `--pinentry <PROGRAM>` | `pinentry` | Program for approval popups; see [Approval popups](#approval-popups) |
| `--pinentry-timeout <DURATION>` | `15s` | How long a popup waits for an answer |
| `--no-pinentry` | | No popups: approve at the agent's terminal or with `sudo-agent approve` |
| `--agent-socket <PATH>` | `$XDG_RUNTIME_DIR/sudo-agent/agent.sock` | The socket to forward. Also `SUDO_AGENT_SOCKET`; the flag wins. `--socket` still works |
| `--control-socket <PATH>` | `$XDG_RUNTIME_DIR/sudo-agent/control.sock` | The socket for `ssh-add`; never forward it. Also `SUDO_AGENT_CONTROL_SOCKET`; the flag wins |

Without `$XDG_RUNTIME_DIR`, the sockets go to
`~/.cache/sudo-agent/agent-<hostname>.sock` and `control-<hostname>.sock`.
Only one agent runs per user: `serve` refuses to start while another agent
answers on either socket.

`serve` runs in the foreground (or [as a service](#running-in-the-background)),
and approval prompts appear in its terminal, as popups when there's a
display, and in every running `sudo-agent approve`. Ctrl-C at a prompt
denies that request; Ctrl-C otherwise (or twice within two seconds, or
closing the terminal) stops the agent, drops the keys and removes the
sockets. A prompt or popup is withdrawn if its client goes away (e.g. the
SSH connection closes) or its key expires.

### Running in the background

As a systemd user service, started with your desktop session and stopped at
logout. Copy [`contrib/systemd/sudo-agent.service`](contrib/systemd/sudo-agent.service)
into place and enable it:

```sh
mkdir -p ~/.config/systemd/user
cp contrib/systemd/sudo-agent.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now sudo-agent
journalctl --user -u sudo-agent    # its log
```

- It runs `~/.cargo/bin/sudo-agent serve`, where `cargo install` puts it.
  For another path or other options, `systemctl --user edit sudo-agent`
  and replace the command (the empty `ExecStart=` clears the old one):
  ```
  [Service]
  ExecStart=
  ExecStart=/usr/local/bin/sudo-agent serve --ttl 30m
  ```
- The sockets are the usual ones, so add keys with `ssh-add` and forward
  `agent.sock` as shown here. The service has no terminal: approvals come
  as [popups](#approval-popups) and through [`sudo-agent
  approve`](#approving-from-any-terminal). Without a display,
  `sudo-agent approve` is the only way, and requests are refused while none
  is running (its first log lines say so).
- Stopping or restarting it (`systemctl --user restart sudo-agent`), or
  logging out, drops all keys.
- It isn't started when you're only logged in over SSH, with no desktop
  session; `systemctl --user start sudo-agent` starts it by hand.
- It needs a desktop that starts `graphical-session.target` and passes its
  display to systemd (GNOME, KDE Plasma and Cinnamon do). Without one,
  e.g. a bare window manager, it never starts by itself and may get no
  popups. Run this from the session's startup instead of enabling it, or use
  `setsid -f` below:
  ```sh
  systemctl --user import-environment DISPLAY WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS
  systemctl --user start sudo-agent
  ```

Without systemd, detach it from the terminal and log to a file; stop it
with `pkill -x sudo-agent`:

```sh
setsid -f sudo-agent serve >>~/.cache/sudo-agent.log 2>&1
```

### Approval popups

When `DISPLAY` or `WAYLAND_DISPLAY` is set, each request also opens a
[pinentry](https://gnupg.org/related_software/pinentry/) popup (it comes
with GnuPG on most desktops), unless `--no-pinentry` is given. The startup
line `Approvals: …` says whether popups are used.

- The default `pinentry` is the one GnuPG uses: on Fedora, openSUSE and
  Arch a script that picks a variant, on Debian and Ubuntu whichever
  variant `update-alternatives` chose. `--pinentry` names another, e.g.
  `--pinentry pinentry-qt` (or on NixOS, where there is no default).
- It needs a graphical variant (`pinentry-gnome3`, `-qt`, `-gtk`). A
  terminal one (`pinentry-curses`, `-tty`) can't work for the agent: it
  fails without touching the agent's terminal, the failure is logged once,
  and the other prompts still work.
- A popup that fails or times out doesn't deny the request while the
  terminal prompt or a `sudo-agent approve` is still waiting.
- `pinentry-gnome3` holds the keyboard and mouse while it's open, so the
  terminal can't be reached until you answer the popup or it times out
  (`--pinentry-timeout`); the terminal prompt then still waits.
  `pinentry-qt` doesn't, so with it the terminal can be answered (or
  Ctrl-C pressed) while the popup is open.
- With neither a terminal nor a display, only `sudo-agent approve` can
  approve requests, and while none is running every one is refused; the
  startup line says so.

### Approving from any terminal

`sudo-agent approve` shows a running agent's requests in the terminal you
start it in, and takes the same `y` or `yes` plus Enter. Use it when the
agent runs [as a service](#running-in-the-background), which has no
terminal of its own, or when you're logged in to the machine over SSH and
can't see its desktop:

```
$ sudo-agent approve
2026-10-21 03:54:09 Waiting for approval requests from /run/user/1000/sudo-agent/control.sock; Ctrl-C quits
Signature request from pid 188732, uid 1000: ssh server
  key: laptop (SHA256:…), 3h57m left
Allow? (closes in 2m00s) [y/N] y
2026-10-21 03:56:15 Allowed
```

- It runs on the machine with the agent, as the same user. It talks to
  `control.sock`, found like `serve` finds it (`--control-socket`, or
  `SUDO_AGENT_CONTROL_SOCKET`).
- The popup, the agent's own terminal and every running `sudo-agent
  approve` are asked at once. The first answer counts, and the others
  close: an `approve` then prints `Withdrawn: …` with the reason, e.g.
  `answered by approve client pid …` or `no answer within 2m`. One that
  answered too late prints `Too late: …`.
- An `approve` can answer a request for up to `--approval-timeout` (`2m`),
  counted from when the request arrives, as the popup's
  `--pinentry-timeout` is. Under the service, that is your limit once the
  popup has closed by itself. To give it longer, raise `--approval-timeout`
  with `systemctl --user edit sudo-agent`.
- It only counts while it runs: with none running, a request doesn't wait
  for one. If every `approve` quits while a request is open, it waits 5
  seconds for one to come back, then stops waiting; the request is then
  refused unless the popup or the agent's terminal is still asking.
- Ctrl-C at a prompt denies that request (a second one within two seconds
  quits); with no prompt open, Ctrl-C quits.
- If the agent stops (restarted, or you logged out), `approve` says so and
  attaches again when it's back. The keys are gone with the old agent, so
  add them again.

### Connecting to a server

Keep your normal agent for the login and forward only `sudo-agent`'s
`agent.sock`:

```sh
ssh -o ForwardAgent=/run/user/1000/sudo-agent/agent.sock server
```

Or set it per host in `~/.ssh/config`. `ForwardAgent` doesn't expand
`${XDG_RUNTIME_DIR}`, so use the literal path:

```
Host server
    ForwardAgent /run/user/1000/sudo-agent/agent.sock
```

`ssh` forwards an agent only if it has one of its own (`SSH_AUTH_SOCK` or
`IdentityAgent`). Without one, `ForwardAgent=<path>` silently does nothing.

Then `sudo` on the server makes the approval prompt appear on your machine:

```
Signature request from pid 402599, uid 1000: ssh server
  key: laptop (SHA256:…), 12m30s left
Allow? [y/N] y
Approved (terminal) signature request from pid 402599, uid 1000: ssh server
```

The popup shows the same text, says when it closes by itself
(`--pinentry-timeout`), and has Allow and Deny buttons.

The prompt names the local `ssh` process that carries the forwarded
request. It can't see which command runs on the server.

**Key types**: Ed25519 is recommended and the one tested end to end.
ECDSA should work but is untested, and its signing uses `crypto-bigint`
0.5, which has a timing advisory ([RUSTSEC-2026-0387]; our advisory:
[GHSA-rj9x-w6xp-x994]). RSA works only when
the requester asks for `rsa-sha2-512` signatures, which older
`pam_ssh_agent_auth` versions may not do. RSA signing also uses the
`rsa` crate, which has an unfixed timing side-channel advisory
([RUSTSEC-2023-0071]; our advisory: [GHSA-wwj9-h88v-6483]). Every
signature waits for your approval, which makes the timing hard to measure
from a server (ECDSA likewise), but prefer Ed25519. Security keys
(`ed25519-sk`, `ecdsa-sk`) and DSA keys aren't supported: `--key` and
`ssh-add` refuse them.

[RUSTSEC-2023-0071]: https://rustsec.org/advisories/RUSTSEC-2023-0071
[GHSA-wwj9-h88v-6483]: https://github.com/juusolatva/sudo-agent/security/advisories/GHSA-wwj9-h88v-6483
[RUSTSEC-2026-0387]: https://rustsec.org/advisories/RUSTSEC-2026-0387
[GHSA-rj9x-w6xp-x994]: https://github.com/juusolatva/sudo-agent/security/advisories/GHSA-rj9x-w6xp-x994

## Server setup

Setup is manual on purpose: a broken PAM config can lock you out of root,
and distributions differ. `sudo-agent` never edits system configuration.
Keep a root shell open while you change any of this.

1. Install `pam_ssh_agent_auth`: `libpam-ssh-agent-auth` on Debian/Ubuntu,
   `pam_ssh_agent_auth` on openSUSE. Tested with 0.10.4 (openSUSE) and
   0.10.3 (Debian).
2. Put your public key in a root-owned file that you can't write to, e.g.
   `/etc/security/authorized_keys`. If the file is user-writable, anyone
   who gets your account can add a key and become root.
3. Let `sudo` keep the agent socket (`visudo`):
   ```
   Defaults env_keep += "SSH_AUTH_SOCK"
   ```
4. Put the module in front of the password stack in `/etc/pam.d/sudo`, as
   `sufficient` so a refusal falls back to the password:
   ```
   auth sufficient pam_ssh_agent_auth.so file=/etc/security/authorized_keys
   ```

To check it: `ssh-add -l` on the server should list your key with its
time left, and `sudo -k; sudo -v` should prompt on your machine instead of
asking for a password.

## Security notes

- The approval prompt is a sanity check and a tripwire, not a vault. Root
  on the machine running the agent can read keys from its memory.
- Anyone with root on a server you're connected to can send requests
  through the forwarded socket, but each one needs your approval, and you
  see it happen. They can't add, remove or lock keys through it: the agent
  refuses that on `agent.sock` and logs the attempt.
- `control.sock` must never be forwarded, and the agent makes sure a
  mistake there (say, a copy-pasted `ForwardAgent` line) doesn't hand a
  server control over your keys. It accepts only your own user, and
  refuses connections that come through `ssh`: OpenSSH 8.9 and later
  announce those with a `session-bind@openssh.com` message, and as a
  further tripwire the agent refuses any client whose executable is named
  `ssh`. Every refusal is logged.
- Any process running as you can answer requests through `control.sock`,
  as it could run `sudo-agent approve` itself; that's the same trust as
  adding keys with `ssh-add` there. It doesn't go unseen: the popup and
  every `approve` show the request until it's answered, the answer is
  logged with the answering process (`Allowed by approve client pid …`),
  and other `approve`s are told who answered.
- The terminal prompts need `y` plus Enter and ignore type-ahead. A popup
  can be approved with a click or Enter, so a keystroke meant for another
  window could approve one that appears while you type. You still see the
  popup, and you expect one for every `sudo` you run.
- Peer details in the prompt come from the requesting process and are
  informational. They are escaped so they can't rewrite the prompt.

## Roadmap

Planned, roughly in order:

- `sudo-agent stop`, lock/unlock, and `sudo-agent status`;
- showing the forwarding chain (which host a request came through) in the
  prompt.

## License

MIT
