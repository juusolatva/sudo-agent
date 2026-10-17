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
./target/release/sudo-agent serve
# prints: export SSH_AUTH_SOCK='/run/user/1000/sudo-agent/agent.sock'
```

Add the key from a second terminal, through the control socket (`ssh-add`
asks for the passphrase):

```sh
SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/sudo-agent/control.sock ssh-add -t 15m ~/.ssh/id_ed25519
```

(Or load it at startup instead: `sudo-agent serve --key ~/.ssh/id_ed25519
--ttl 15m`, with the passphrase asked in the agent's terminal.)

In a second terminal, log in with your normal agent but forward only
`sudo-agent` (OpenSSH ≥ 8.2 accepts a socket path for `ForwardAgent`):

```sh
ssh -o ForwardAgent="$XDG_RUNTIME_DIR/sudo-agent/agent.sock" <server>
```

There is an alternative: `SSH_AUTH_SOCK=<sudo-agent socket> ssh -A <server>`.
It also works, but then the SSH login itself asks `sudo-agent` for a signature,
so you'll get one approval prompt for the login as well.

Forward `agent.sock` only, never `control.sock`. `ssh` forwards an agent only
if it has one of its own (`SSH_AUTH_SOCK` or `IdentityAgent` set); without
one, `ForwardAgent=<path>` silently does nothing.

## 2. Server: read-only checks

Run these in the forwarded session. None of them changes anything.

```sh
echo "$SSH_AUTH_SOCK"          # set: ~/.ssh/agent/s.*.sshd.* on recent
                               # OpenSSH, /tmp/ssh-XXXX/agent.NNNN on older
ssh-add -l                     # lists the key with sudo-agent's fingerprint
                               # and its time left; listing never prompts
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
(On hosts with a zero sudo timestamp timeout, like the servers used here,
every `sudo` authenticates anyway.)

| # | Action | Expected on laptop | Expected on server |
|---|--------|--------------------|--------------------|
| 1 | `sudo -k; sudo -v`, answer **y** | Prompt names the `ssh … <server>` process, the key, and time left; then `Approved signature request …` | Succeeds with **no password prompt** |
| 2 | `sudo -k; sudo -v`, answer **n** (or Enter) | `Refused signature request …: denied` | Falls back to the password prompt (or fails if there's no fallback) |
| 3 | Restart the agent with `--ttl 1m` (no need to reconnect: the forwarded channel reconnects to the socket path for every request), wait > 1 min, then `sudo -k; sudo -v` | `Key expired and was removed: …`, **no** prompt | `ssh-add -l` shows no identities; sudo falls back to the password |
| 4 | Two sessions run `sudo -k; sudo -v` at the same time | Prompts appear one after another; each request's `Approved`/`Refused` line comes before the next prompt, nothing interleaved | Each succeeds once approved |
| 6 | `sudo -k; sudo -v`, then, while the laptop prompt is open, end the SSH connection with the `~.` escape (Enter, `~`, `.`) in the server session | The prompt line ends and `Refused …: client disconnected` follows at once; after reconnecting, the next prompt works normally | Connection closed (Ctrl-C would not do: `sudo` ignores it while `pam_ssh_agent_auth` waits) |
| 7 | `sudo -k; sudo -v`, press Ctrl-C at the **laptop** prompt | `^C`, then `Refused …: denied` (before 2a: `not approved: cancelled with Ctrl-C`); the agent keeps running (a second Ctrl-C within 2 s would stop it) | Falls back to the password prompt |
| 8 | Restart the agent with `--ttl 1m`, run `sudo -k; sudo -v` when ~10 s are left and don't answer | At expiry the prompt line ends, then `Refused …: key expired while waiting for approval`, then `Key expired and was removed: …`, each on its own line | Falls back to the password prompt |
| 9 | With the key added by `ssh-add` over `control.sock` (step 1), `sudo -k; sudo -v`, answer **y** | As case 1; the agent logged `Added key … from ssh-add …, usable for …` when it was added | Succeeds with no password prompt |
| 10 | `ssh -o ForwardAgent=$XDG_RUNTIME_DIR/sudo-agent/control.sock <server>`, then `ssh-add -l` | `Refused control connection from … ssh …` | `error fetching identities: agent refused operation` |
| 11 | In a session forwarding `agent.sock`, `ssh-add <some key file>` and `ssh-add -D` on the server | `Refused adding a key …` / `Refused removing all keys …: agent.sock only lists and signs` | Both refused; `ssh-add -l` still lists the key |
| 12 | `ssh-add -l` on the server, then again a minute later | Nothing (listing never prompts) | Each key's comment ends in its time left, e.g. `laptop (14m30s left)`, about a minute less the second time; it matches `ssh-add -l` on the laptop against `control.sock` |
| 5 | Stop the agent (Ctrl-C with no prompt open), then `sudo -k; sudo -v` | Nothing (agent is gone) | Password prompt: proves `sudo` really authenticates through `sudo-agent`, not some other forwarded agent |

Report: the pam_ssh_agent_auth version, key type, the exact prompt text, and
any `Refused …` lines from the laptop.

## Results

**2026-10-07, `server-a`** (openSUSE Tumbleweed, `pam_ssh_agent_auth`
0.10.4, Ed25519 key, OpenSSH 10.2 on the laptop):

- The connection used `SSH_AUTH_SOCK=<sudo-agent socket> ssh server-a`, with
  forwarding from `~/.ssh/config`. The login itself was approved through the
  prompt, as expected for that variant.
- The forwarded socket was `~/.ssh/agent/s.*.sshd.*`; `ssh-add -l` on the
  server showed the laptop key's fingerprint.
- Cases 1, 2, 3 and 5 passed. `sudo -v` succeeded with no password after
  approval, and fell back to the password after denial, after expiry, and
  with the agent stopped.
- Case 4 worked, but the laptop terminal was garbled: request 1's
  `Refused …` line was printed in pieces interleaved with request 2's
  prompt, and request 2's "expires in" was computed before it queued.
  - The fix serves requests one at a time, from lookup to logged outcome
    (`SudoAgent::requests`), and writes each log line and each prompt in a
    single `write()` (`log!`).
  - Rechecked on a pty with two concurrent `ssh-keygen -Y sign` requests;
    still to be re-run against a server.

**2026-10-11, `server-a` and `server-b`** (`pam_ssh_agent_auth` 0.10.4-3.7
on openSUSE Tumbleweed, `libpam-ssh-agent-auth` 0.10.3-11 on Debian; build
with prompt cancellation and `--max-ttl`):

- Cases 1, 2, 3, 4, 5 and 7 passed on both, as did stopping and restarting
  the agent. Case 4's output is no longer garbled.
- Case 6 as first written (Ctrl-C on the remote `sudo`) can't happen: `sudo`
  ignores Ctrl-C while `pam_ssh_agent_auth` waits for the agent; only the
  password prompt after a denial can be interrupted. Rewritten to close the
  connection with `~.` instead.
- A prompt shown just before its key expired stayed up until answered, and
  the reaper's `Key expired and was removed` landed inside its line. Fixed:
  the prompt is now withdrawn at expiry (case 8).
- Re-test after those fixes: case 6 (closing the SSH connection) logged
  `client disconnected` at once; case 8 withdrew the prompt at expiry and
  `sudo` fell back to the password prompt by itself. Passed.

**2026-10-12, laptop only: `control.sock` against real OpenSSH 10.2**
(`ssh-add` and `ssh`; a private `sshd` run as the user on `127.0.0.1:2222`
with a throwaway config and keys, stopped afterwards; no `sudo`):

- `ssh-add` over `control.sock`: add, `-t 12h` capped to 8h and logged,
  re-add replacing the key, `-c` accepted, `-h` refused (needs the host in
  `known_hosts`, else `ssh-add` fails before asking the agent), `-x`
  refused as not supported, `-d`/`-D`. `ssh-add` / `-D` against
  `agent.sock` refused and logged.
- Forwarding `control.sock` (cases 10–11 locally): with the real `ssh`, the
  executable-name tripwire refused it; with a renamed copy of `ssh`, the
  `session-bind@openssh.com` check refused it. Logging in with
  `IdentityAgent=control.sock` was refused both ways (the agent held a key
  the server accepted). Forwarding `agent.sock` listed the key, and adding
  or removing keys from the server side was refused and logged.
- Pitfall found on the way: `ssh` with no agent of its own (`SSH_AUTH_SOCK`
  unset or `IdentityAgent=none`) skips agent forwarding silently, even
  with `ForwardAgent=<path>`.

**2026-10-12, server `palvelin`** (0.2.0 candidate, release build): the key
added with `ssh-add -t 240m` over `control.sock` (the `ssh-load` flow; logged
`usable for 4h`), then `sudo` through the forwarded `agent.sock`:

- Case 9 (approve), case 2 (deny), case 7 (Ctrl-C at the laptop prompt:
  denied, agent kept running) and case 6 (closing the SSH connection: the
  prompt line ended, `client disconnected`) passed.

**2026-10-17, server `palvelin`** (0.2.1, Ed25519 key added over
`control.sock`, forwarded `agent.sock`):

- Case 12: `ssh-add -l` on the server listed the key as
  `licepad (14m14s left) (ED25519)`, i.e. with the time left after its
  comment. Passed. Only one listing was taken; the "a minute later"
  re-check wasn't part of this run.

## Troubleshooting

- **No prompt on the laptop, and sudo asks for a password**:
  - Check `ssh-add -l` on the server. If it fails, forwarding isn't active.
    On the laptop, `ssh` needs an agent of its own (`SSH_AUTH_SOCK`) to
    forward one, and the forwarded path must be `agent.sock`, not
    `control.sock` (which refuses `ssh` and logs it).
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
