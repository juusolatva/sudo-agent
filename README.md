# sudo-agent

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
- **Every signature is approved.** The prompt shows which local process is
  asking and which key it wants, so a request you didn't start (for example
  from someone else with access to the forwarded socket) is visible rather
  than silent. Approving takes `y` or `yes` plus Enter. Keys typed before
  the prompt appeared are discarded. Anything else, or no answer within
  `--approval-timeout`, denies the request.
- **Two sockets.** `agent.sock` is the one you forward: it can only list
  keys and ask for signatures. `control.sock` is for adding and removing
  keys (`ssh-add`) and is never forwarded; see [Security
  notes](#security-notes).
- **One request at a time.** Concurrent requests queue, and every approval
  and refusal is logged.

## Install

```sh
cargo install sudo-agent
```

Or from a checkout: `cargo build --release`.

## Usage

Start the agent on the machine that holds your key:

```sh
sudo-agent serve
# Agent listening on /run/user/1000/sudo-agent/agent.sock
# Control socket on /run/user/1000/sudo-agent/control.sock (for ssh-add; never forward it)
# No keys loaded yet; add one with: SSH_AUTH_SOCK='/run/user/1000/sudo-agent/control.sock' ssh-add <key>
# export SSH_AUTH_SOCK='/run/user/1000/sudo-agent/agent.sock'
```

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

Or load keys at startup, with the passphrase asked in the agent's terminal:
`sudo-agent serve --key ~/.ssh/id_ed25519` (repeatable).

### Options

| Option | Default | |
|--------|---------|-|
| `--key <PATH>` | none | OpenSSH private key to load at startup; repeatable |
| `--ttl <DURATION>` | `15m` | TTL for `--key` keys and for `ssh-add` without `-t` (`90s`, `15m`, `8h`) |
| `--max-ttl <DURATION>` | `8h` | Longest TTL a key may have: a longer `--ttl` is an error, a longer `ssh-add -t` is cut down |
| `--approval-timeout <DURATION>` | `2m` | How long a prompt waits before denying |
| `--agent-socket <PATH>` | `$XDG_RUNTIME_DIR/sudo-agent/agent.sock` | The socket to forward. Also `SUDO_AGENT_SOCKET`; the flag wins. `--socket` still works |
| `--control-socket <PATH>` | `$XDG_RUNTIME_DIR/sudo-agent/control.sock` | The socket for `ssh-add`; never forward it. Also `SUDO_AGENT_CONTROL_SOCKET`; the flag wins |

Without `$XDG_RUNTIME_DIR`, the sockets go to
`~/.cache/sudo-agent/agent-<hostname>.sock` and `control-<hostname>.sock`.
Only one agent runs per user: `serve` refuses to start while another agent
answers on either socket.

The agent runs in the foreground, and approval prompts appear in its
terminal. Ctrl-C at a prompt denies that request; Ctrl-C otherwise (or twice
within two seconds, or closing the terminal) stops the agent, drops the keys
and removes the sockets. A prompt is withdrawn if its client goes away (e.g.
the SSH connection closes) or its key expires.

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
  key: laptop (SHA256:…), expires in 12m30s
Allow? [y/N] y
Approved signature request from pid 402599, uid 1000: ssh server
```

The prompt names the local `ssh` process that carries the forwarded
request. It can't see which command runs on the server.

**Key types**: Ed25519 is recommended and the one tested end to end.
ECDSA should work but is untested. RSA works only when
the requester asks for `rsa-sha2-512` signatures, which older
`pam_ssh_agent_auth` versions may not do.

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
- Peer details in the prompt come from the requesting process and are
  informational. They are escaped so they can't rewrite the prompt.

## Roadmap

Planned, roughly in order:

- approvals through pinentry popups or a `sudo-agent approve` command in
  any terminal;
- running as a background service (a systemd user unit);
- later: `sudo-agent stop`, lock/unlock, and `sudo-agent status`;
- showing the forwarding chain (which host a request came through) in the
  prompt.

## License

MIT
