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
your machine                                     server
────────────                                     ──────
sudo-agent ── holds the decrypted key     sudo
   │          for --ttl, then forgets it     └─ pam_ssh_agent_auth
   │                                               │ "sign this challenge"
   └─ "Allow? [y/N]"  ◄── forwarded agent ◄────────┘
```

- **Passphrase once.** It's asked for once, when the key is loaded. After
  that, each signature only needs a `y`.
- **TTL inside the agent.** Keys are dropped (and zeroized) when their time
  is up. The clock keeps counting while the machine is suspended.
- **Every signature is approved.** The prompt shows which local process is
  asking and which key it wants, so a request you didn't start (for example
  from someone else with access to the forwarded socket) is visible rather
  than silent. Approving takes `y` or `yes` plus Enter. Keys typed before
  the prompt appeared are discarded. Anything else, or no answer within
  `--approval-timeout`, denies the request.
- **One request at a time.** Concurrent requests queue, and every approval
  and refusal is logged.

## Install

```sh
cargo install sudo-agent
```

Or from a checkout: `cargo build --release`.

## Usage

On the machine that holds your key:

```sh
sudo-agent --key ~/.ssh/id_ed25519
# Passphrase for /home/you/.ssh/id_ed25519:
# Loaded /home/you/.ssh/id_ed25519 (SHA256:…), usable for 15m
# Agent listening on /run/user/1000/sudo-agent/agent.sock
```

| Option | Default | |
|--------|---------|-|
| `--key <PATH>` | (required) | OpenSSH private key to load; repeatable |
| `--ttl <DURATION>` | `15m` | How long loaded keys stay usable (`90s`, `15m`, `8h`) |
| `--approval-timeout <DURATION>` | `2m` | How long a prompt waits before denying |
| `--socket <PATH>` | `$XDG_RUNTIME_DIR/sudo-agent/agent.sock` | Falls back to `~/.cache/sudo-agent/agent-<hostname>.sock` |

The agent runs in the foreground, and approval prompts appear in its
terminal. Ctrl-C (or closing the terminal) stops it, drops the keys and
removes the socket.

Connect to a server, keeping your normal agent for the login and forwarding
only `sudo-agent`:

```sh
ssh -o ForwardAgent=/run/user/1000/sudo-agent/agent.sock server
```

Or set it per host in `~/.ssh/config`. `ForwardAgent` doesn't expand
`${XDG_RUNTIME_DIR}`, so use the literal path:

```
Host server
    ForwardAgent /run/user/1000/sudo-agent/agent.sock
```

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
   `pam_ssh_agent_auth` on openSUSE. Tested with 0.10.4.
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

To check it: `ssh-add -l` on the server should list your key, and
`sudo -k; sudo -v` should prompt on your machine instead of asking for a
password.

## Security notes

- The approval prompt is a sanity check and a tripwire, not a vault. Root
  on the machine running the agent can read keys from its memory.
- Anyone with root on a server you're connected to can send requests
  through the forwarded socket, but each one needs your approval, and you
  see it happen.
- Peer details in the prompt come from the requesting process and are
  informational. They are escaped so they can't rewrite the prompt.

## Roadmap

Planned, roughly in order:

- running as a background service, with keys added through a separate
  control socket (so `ssh-add` works);
- approvals through pinentry popups or a `sudo-agent approve` command in
  any terminal;
- `sudo-agent status` for time left, also on the server;
- showing the forwarding chain (which host a request came through) in the
  prompt.

## License

MIT
