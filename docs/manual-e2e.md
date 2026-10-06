# Manual end-to-end test: `sudo` via `pam_ssh_agent_auth`

The last "Now" item in `TODO.md`: confirm a full elevate-with-approval cycle
against a real `pam_ssh_agent_auth`. Nothing here is automated, and nothing
here edits PAM or sudoers. Any config change is shown to the user, who
applies it.

## Topology

```
laptop (agent host)                             server (sudo host)
───────────────────                             ──────────────────
sudo-agent --key ~/.ssh/id_ed25519              sudo
  └─ approval prompt on this terminal  ◄──┐       └─ pam_ssh_agent_auth
                                          │            └─ $SSH_AUTH_SOCK (forwarded)
ssh -o ForwardAgent=<sudo-agent socket> ──┴───────────────┘
```

- The **laptop** holds the private key and runs `sudo-agent`. It has no
  `pam_ssh_agent_auth` (Fedora 44 doesn't package it, and `pam_rssh` isn't
  packaged either).
- The **servers** already have `pam_ssh_agent_auth` set up for `sudo`. They
  hold **no private keys**: the key reaches them only through the forwarded
  agent socket. Do not try to run `sudo-agent` on a server.
- Approval prompts appear on the **laptop terminal running `sudo-agent`**, not
  in the SSH session. An AI agent working on a server can neither see nor
  answer them; the user does, and relays what they saw.
- The prompt names the *local* process (the laptop's `ssh` command), not the
  remote `sudo`. That is expected; see the forwarding-chain item in
  `TODO.md`.

## 1. Laptop: start the agent and connect

```sh
cargo build --release
./target/release/sudo-agent --key ~/.ssh/id_ed25519 --ttl 15m
# prints: export SSH_AUTH_SOCK='/run/user/1000/sudo-agent/agent.sock'
```

In a second terminal, log in with your normal agent but forward only
`sudo-agent` (OpenSSH ≥ 8.2 accepts a socket path for `ForwardAgent`):

```sh
ssh -o ForwardAgent="$XDG_RUNTIME_DIR/sudo-agent/agent.sock" <server>
```

There is an alternative: `SSH_AUTH_SOCK=<sudo-agent socket> ssh -A <server>`.
It also works, but then the SSH login itself asks `sudo-agent` for a signature,
so you'll get one approval prompt for the login as well.

## 2. Server: read-only checks

Run these in the forwarded session. None of them changes anything.

```sh
echo "$SSH_AUTH_SOCK"          # set, e.g. /tmp/ssh-XXXX/agent.NNNN
ssh-add -l                     # lists the key with sudo-agent's fingerprint;
                               # listing never prompts
grep -n pam_ssh_agent_auth /etc/pam.d/sudo   # note the file= argument
ssh-keygen -lf <that file>     # must include the same fingerprint
dpkg -l | grep -i ssh-agent-auth || rpm -q pam_ssh_agent_auth   # record version
```

Some things need root, so the user must check them:

- `/etc/sudoers` (or `/etc/sudoers.d/*`) keeps the socket variable:
  `Defaults env_keep += "SSH_AUTH_SOCK"`.
- The PAM line comes before the password stack and is `sufficient`, so a
  failure falls back to the password, e.g.
  `auth sufficient pam_ssh_agent_auth.so file=/etc/security/authorized_keys`.

Record the key type. Ed25519 is what this test expects. With an RSA key,
`pam_ssh_agent_auth` 0.10.x may request SHA-1 or SHA-256 signatures, and
`sudo-agent` refuses those (it can only sign RSA with SHA-512).

## 3. Test cases

The user runs these in the server SSH session (sudo may need a tty). Start
each one with `sudo -k` so a cached sudo timestamp can't skip authentication.

| # | Action | Expected on laptop | Expected on server |
|---|--------|--------------------|--------------------|
| 1 | `sudo -k; sudo -v`, answer **y** | Prompt names the `ssh … <server>` process, the key, and time left; then `Approved signature request …` | Succeeds with **no password prompt** |
| 2 | `sudo -k; sudo -v`, answer **n** (or Enter) | `Refused signature request …: denied` | Falls back to the password prompt (or fails if there's no fallback) |
| 3 | Restart the agent with `--ttl 1m`, reconnect, wait > 1 min, then `sudo -k; sudo -v` | `Key expired and was removed: …`, **no** prompt | `ssh-add -l` shows no identities; sudo falls back to the password |
| 4 | Two sessions run `sudo -k; sudo -v` at the same time | Prompts appear one after another, never interleaved | Each succeeds once approved |
| 5 | Reconnect with `ssh -o ForwardAgent=no <server>`, then `sudo -k; sudo -v` | Nothing | Password prompt: proves the PAM path really goes through the agent (and not through your normal agent if it's forwarded by `~/.ssh/config`) |

Report: the pam_ssh_agent_auth version, key type, the exact prompt text, and
any `Refused …` lines from the laptop.

## Troubleshooting

- **No prompt on the laptop, and sudo asks for a password**:
  - Check `ssh-add -l` on the server. If it fails, forwarding isn't active.
  - Check that `env_keep` includes `SSH_AUTH_SOCK`.
  - Check that the key's fingerprint is in the PAM `file=`.
  - Check the key hasn't expired.
- **Laptop logs `Refused …: key not loaded or expired`**: the server asked
  for a key that `sudo-agent` doesn't hold. Usually the `file=` list has a
  different key than the one passed to `--key`.
- **Laptop logs `Refused …: RSA signature requested without rsa-sha2-512`**:
  the key is RSA. Use an Ed25519 key.
- **More detail**:
  - Server: the user can add `debug` to the `pam_ssh_agent_auth` line, then
    read `journalctl -t sudo --since -5min`, or `/var/log/auth.log` on Debian.
  - Laptop: the agent logs every approval and refusal to stderr.
- **Before any PAM change**, the user should keep a root shell open on the
  server (`sudo -s` in another session) until `sudo` is confirmed working.
