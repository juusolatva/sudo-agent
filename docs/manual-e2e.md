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
- Approval prompts appear on the **laptop**: on the terminal running
  `sudo-agent`, as popups, and in any `sudo-agent approve` there, not in the
  server session. An AI agent working on a server can neither see nor
  answer them; the user does, and relays what they saw.
- The prompt names the *local* process (the laptop's `ssh` command), not the
  remote `sudo`. That is expected; see the forwarding-chain item in
  `TODO.md`.

## 1. Laptop: start the agent and connect

```sh
cargo build --release
./target/release/sudo-agent serve
# prints, among others: … Forward it with: ssh -o ForwardAgent='/run/user/1000/sudo-agent/agent.sock' <host>
```

Add the key from a second terminal, through the control socket (`ssh-add`
asks for the passphrase):

```sh
SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/sudo-agent/control.sock ssh-add -t 15m ~/.ssh/id_ed25519
```

(Or load it at startup instead: `sudo-agent serve --key ~/.ssh/id_ed25519
--ttl 15m`, with the passphrase asked in the agent's terminal.)

Cases 24–27 and 28–38 run it as the systemd user service instead (README →
Running in the background), which needs `cargo install --path . --locked`
(the unit runs `~/.cargo/bin/sudo-agent`; an older install refuses
`sudo-agent approve`). Stop the service before running the agent by hand:
only one may run.

In a second terminal, log in with your normal agent but forward only
`sudo-agent` (OpenSSH ≥ 8.2 accepts a socket path for `ForwardAgent`):

```sh
ssh -o ForwardAgent="$XDG_RUNTIME_DIR/sudo-agent/agent.sock" <server>
```

There is an alternative: `SSH_AUTH_SOCK=<agent.sock> ssh -A <server>`.
It also works, but then the SSH login itself asks `sudo-agent` for a
signature, so you'll get one approval prompt for the login as well
(`signing: an SSH login as user …`). Logins onwards from the server
(`ssh`, `scp`, `git push`) prompt the same way.

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
| 1 | `sudo -k; sudo -v`, answer **y** | Prompt names the `ssh … <server>` process, the key, and time left, and says `signing: a sudo challenge for user <you>`; then `Approved (terminal) signature request …` | Succeeds with **no password prompt** |
| 2 | `sudo -k; sudo -v`, answer **n** (or Enter) | `Refused signature request …: denied (terminal)` | Falls back to the password prompt (or fails if there's no fallback) |
| 3 | Restart the agent with `--ttl 1m` (no need to reconnect: the forwarded channel reconnects to the socket path for every request), wait > 1 min, then `sudo -k; sudo -v` | `Key expired and was removed: …`, **no** prompt | `ssh-add -l` shows no identities; sudo falls back to the password |
| 4 | Two sessions run `sudo -k; sudo -v` at the same time | Prompts appear one after another; each request's `Approved`/`Refused` line comes before the next prompt, nothing interleaved | Each succeeds once approved |
| 6 | `sudo -k; sudo -v`, then, while the laptop prompt is open, end the SSH connection with the `~.` escape (Enter, `~`, `.`) in the server session | The prompt line ends and `Refused …: client disconnected` follows at once; after reconnecting, the next prompt works normally | Connection closed (Ctrl-C would not do: `sudo` ignores it while `pam_ssh_agent_auth` waits) |
| 7 | `sudo -k; sudo -v`, press Ctrl-C at the **laptop** prompt | `^C`, then `Refused …: denied (terminal)` (before 2a: `not approved: cancelled with Ctrl-C`); the agent keeps running (a second Ctrl-C within 2 s would stop it) | Falls back to the password prompt |
| 8 | Restart the agent with `--ttl 1m`, run `sudo -k; sudo -v` when ~10 s are left and don't answer | At expiry the prompt line ends, then `Refused …: key expired while waiting for approval`, then `Key expired and was removed: …`, each on its own line | Falls back to the password prompt |
| 9 | With the key added by `ssh-add` over `control.sock` (step 1), `sudo -k; sudo -v`, answer **y** | As case 1; the agent logged `Added key … from ssh-add …, usable for …` when it was added | Succeeds with no password prompt |
| 10 | `ssh -o ForwardAgent=$XDG_RUNTIME_DIR/sudo-agent/control.sock <server>`, then `ssh-add -l` | `Refused control connection from … ssh …` | `error fetching identities: agent refused operation` |
| 11 | In a session forwarding `agent.sock`, `ssh-add <some key file>` and `ssh-add -D` on the server | `Refused adding a key …` / `Refused removing all keys …: agent.sock only lists and signs` | Both refused; `ssh-add -l` still lists the key |
| 12 | `ssh-add -l` on the server, then again a minute later | Nothing (listing never prompts) | Each key's comment ends in its time left, e.g. `laptop (14m30s left)`, about a minute less the second time; it matches `ssh-add -l` on the laptop against `control.sock` |
| 13 | In the desktop session, `sudo -k; sudo -v`, click **Allow** in the popup | Startup said `Approvals: a pinentry popup, sudo-agent approve or this terminal …`; popup (headed `sudo-agent`, text ending in `This popup closes in 15s without an answer.`) and terminal prompt appear together; the terminal prompt line ends, then `Approved (pinentry) …` | Succeeds |
| 14 | As 13, but **Deny** (then again with Escape, and with closing the window) | Terminal prompt line ends, then `Refused …: denied (pinentry)` | Falls back to the password prompt |
| 15 | Agent run in tmux (`tmux new -s sa sudo-agent serve`); in another laptop terminal `(sleep 15; tmux send-keys -t sa y Enter) &`, then within 15 s `sudo -k; sudo -v` and leave the popup alone | At 15 s the terminal answers: the popup disappears; `Approved (terminal) …` | Succeeds |
| 16 | In another laptop terminal `(sleep 15; pkill -INT -x sudo-agent) &` (what Ctrl-C sends), then within 15 s `sudo -k; sudo -v` and leave the popup alone | At 15 s the popup disappears; `Refused …: denied (terminal)`; the agent keeps running | Falls back to the password prompt |
| 17 | As 13, answer nothing anywhere | After 15 s the popup closes by itself and the terminal prompt keeps waiting (answering it then works); left alone, at 2 min `Refused …: not approved: pinentry: no answer within 15s; terminal: no answer within 2m` | Falls back to the password prompt |
| 18 | In another laptop terminal `(sleep 15; pkill -x -n ssh) &` (the newest `ssh`: the server session), then within 15 s `sudo -k; sudo -v` and leave the popup alone | At 15 s popup and terminal prompt are withdrawn; `Refused …: client disconnected` | Connection closed |
| 19 | As case 8 (`--ttl 1m`, ~10 s left), with the popup open | At expiry the popup and the terminal prompt are withdrawn; `Refused …: key expired while waiting for approval` | Falls back to the password prompt |
| 20 | Restart with `--pinentry pinentry-curses`, then `sudo -k; sudo -v` twice, answering at the terminal | The terminal prompt works and isn't disturbed; after the first answer `Approval backend failed (logged only once): pinentry: pinentry failed: Inappropriate ioctl for device …`; not repeated the second time | Both as answered |
| 21 | Laptop only: SSH into the laptop (no `DISPLAY`) and run `sudo-agent serve` there | Startup says `Approvals: sudo-agent approve or this terminal, whichever answers first (no pinentry popups: …)`; requests prompt in that terminal only | — |
| 22 | In another laptop terminal `(sleep 15; pkill -KILL -x sudo-agent) &`, then within 15 s `sudo -k; sudo -v` | The popup closes (pinentry is killed with the agent) | Falls back to the password prompt |
| 23 | Run the agent without a terminal in the desktop session: `setsid -f sudo-agent serve > /tmp/sudo-agent.log 2>&1`, add the key, `sudo -k; sudo -v`, click **Allow** | The log says `Approvals: a pinentry popup or sudo-agent approve, whichever answers first (no terminal)`, then `Approved (pinentry) …` | Succeeds |
| 24 | Laptop only: the service without a display: a drop-in `~/.config/systemd/user/sudo-agent.service.d/headless.conf` with `[Service]` `UnsetEnvironment=DISPLAY WAYLAND_DISPLAY`, `daemon-reload`, `systemctl --user start sudo-agent`; add the key, `ssh-add -l` against `control.sock`, then `ssh-keygen -Y sign` against `control.sock` (`agent.sock` refuses it before asking). Remove the drop-in afterwards | `journalctl --user -u sudo-agent`: lines carry only the journal's timestamp; startup says `Approvals: sudo-agent approve only (there's no terminal, and no pinentry popups: …); signature requests are refused while none is running`; then `Added key …` and `Refused …: not approved: no approval backend is available` | — |
| 25 | The service in the desktop session (no drop-in): add the key, `sudo -k; sudo -v`, click **Allow** | Journal: `Approvals: a pinentry popup or sudo-agent approve, whichever answers first (no terminal)`, then `Approved (pinentry) …`; `systemctl --user stop sudo-agent` logs `Received SIGTERM, shutting down` | Succeeds |
| 26 | Laptop only: with the service enabled, reboot (or log out and in) and log in to the desktop | `systemctl --user status sudo-agent` is active; the journal's startup already says `Approvals: a pinentry popup or sudo-agent approve, whichever answers first (no terminal)` (the display reached the service) | — |
| 27 | Laptop only: with the service running, add the key, log out of the desktop and back in (no reboot) | Journal: `Received SIGTERM, shutting down` at logout (same user manager pid in `systemd[…]`), then a fresh start with `No keys loaded yet` | — |
| 28 | Headless service (case 24's drop-in), `sudo-agent approve` in a laptop terminal; `sudo -k; sudo -v`, answer **y** in the client | Journal: `Approve client attached: pid …`; the client shows the request ending in `Allow? (closes in 2m00s) [y/N]`, then `Allowed`; journal: `Allowed by approve client pid …`, then `Approved (approve) …` | Succeeds |
| 29 | As 28, answer **n** | Client: `Denied`; journal: `Denied by approve client pid …`, then `Refused …: denied (approve)` | Falls back to the password prompt |
| 30 | As 28, Ctrl-C at the client's prompt; more than 2 s later, Ctrl-C again (no prompt open) | `^C`, then `Denied`, and the client keeps running; journal: `Refused …: denied (approve)`. The second Ctrl-C quits the client; journal: `Approve client detached: …` | Falls back to the password prompt |
| 31 | As 28 with two clients in two laptop terminals; answer **y** in one | Both show the request; the other one's prompt line ends, then `Withdrawn: answered by approve client pid <the first's pid> …` | Succeeds |
| 32 | The service with the display (no drop-in) and a client; click **Allow** in the popup; then again with **Deny** | Both ask at once. The client's prompt line ends, then `Withdrawn: answered elsewhere, or no longer needed`; journal: `Approved (pinentry) …` / `Refused …: denied (pinentry)` | Succeeds / falls back to the password prompt |
| 33 | As 32, leave the popup alone and answer **y** in the client after the popup closed by itself | The popup closes at 15 s, the client's prompt stays open; then `Allowed`, journal `Approved (approve) …` | Succeeds |
| 34 | As 28, answer nothing | At 2 min the client's prompt line ends, then `Withdrawn: no answer within 2m`; journal: `Refused …: not approved: no answer within 2m` | Falls back to the password prompt |
| 35 | As 28, then end the SSH connection with `~.` while the client's prompt is open | Client: `Withdrawn: answered elsewhere, or no longer needed`; journal: `Refused …: client disconnected` | Connection closed |
| 36 | Headless service with **no** client: `sudo -k; sudo -v`. Then start a client, `sudo -k; sudo -v`, and with its prompt open stop it from another laptop terminal with `pkill -f 'sudo-agent approve'` (Ctrl-C there would deny) | Without a client: refused at once, `not approved: no approval backend is available`. Stopping it mid-request: its prompt line ends and it exits; `Approve client detached: …`, and 5 s later `Refused …: not approved: every sudo-agent approve detached` | Falls back to the password prompt both times, the second after ~5 s |
| 37 | A client running: `systemctl --user restart sudo-agent`. Add the key again, `sudo -k; sudo -v`, and with the client's prompt open restart it again; add the key once more and `sudo -k; sudo -v` | Each restart, in the client: `sudo-agent went away; waiting for it to start again (Ctrl-C quits)`, then `sudo-agent is back; waiting for approval requests` (the second time, the prompt line ends first); journal: `Approve client attached` in each new agent. The last `sudo` prompts in the client | With the prompt open: falls back to the password prompt; after re-adding the key, succeeds |
| 38 | Laptop over SSH: the service runs in the desktop session; from another machine, SSH into the laptop and run `sudo-agent approve` there; `sudo -k; sudo -v` on a server as usual, answer **y** in that SSH session | The request shows in the SSH session (and as the popup on the desktop); `Approved (approve) …` | Succeeds |
| 39 | Two keys loaded: add a second one with a different lifetime (`ssh-add -t 5m <other key>` against `control.sock`). Best is a dedicated sudo key, listed only in the server's `pam_ssh_agent_auth` keys file (`file=`), next to the key you log in with. `ssh-add -l` on both sides; `sudo -k; sudo -v`, answer **y**; then from the server `ssh <another host>` (or `git push`), answer **y**; wait for the shorter lifetime to run out and repeat both | Two `Added key …` lines. The `sudo` prompt names the key from the `file=` list and says `signing: a sudo challenge …`; the login prompt names the login key and says `signing: an SSH login as user …`. One prompt per operation: a prompt for a key the operation doesn't use means the client (or `pam_ssh_agent_auth`) asks every key in turn, so note it. When the short-lived key expires, only it is removed (`Key expired …`) and the other keeps working | `ssh-add -l` lists both, each with its own time left; `sudo` and the onward login succeed; after the expiry, one key is listed, and whatever uses it still succeeds |
| 5 | Stop the agent (Ctrl-C with no prompt open), then `sudo -k; sudo -v` | Nothing (agent is gone) | Password prompt: proves `sudo` really authenticates through `sudo-agent`, not some other forwarded agent |

Cases 1, 2 and 6–9 test the terminal prompt: since step 2c, start the agent
with `--no-pinentry` for them (startup says `Approvals: sudo-agent approve
or this terminal, whichever answers first (pinentry popups are off with
--no-pinentry)`), or they're answered in the popup instead, which cases
13–19 cover. Run no `sudo-agent approve` during them.

`pinentry-gnome3` holds the keyboard and mouse while its popup is open (seen
on Cinnamon), so the terminal can't be reached then. Cases 15, 16, 18 and
22 therefore act on the agent from a timer started beforehand.
`pinentry-qt` (`--pinentry pinentry-qt`) doesn't: Alt+Tab reaches the
terminal, so with it cases 15 and 16 can be answered there directly.

Cases 24–27 run the agent as the systemd user service; read its log with
`journalctl --user -u sudo-agent -b`.

Cases 28–38 test `sudo-agent approve` (step 4), against the service. With
case 24's headless drop-in (28–31, 34–36), the client is the only backend,
so nothing else answers first; 32, 33, 37 and 38 run without it, popup
included. The client's own lines go to its terminal; the agent's go to the
journal.

Case 39 tests several keys at once: each prompt names the right key and
what it signs, and each key expires on its own.

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

**2026-10-17, laptop + server `palvelin`** (step 2c, `pinentry-gnome3` on
Fedora 44 Cinnamon through the `pinentry` wrapper):

- Case 13 (Allow) and case 14 (Deny, Escape; this popup has no close
  button) passed. The first popup was headed "Message" and its key line
  ("expires in …") read like the popup's own deadline; fixed with
  `SETPROMPT sudo-agent`, a closing line with the popup's timeout, and the
  key line as `12m30s left`.
- The popup holds keyboard and mouse, so cases 15, 16, 18 and 22 were run
  from timers (tmux `send-keys`, `pkill -INT`, `pkill ssh`, `pkill -KILL`):
  all passed, each withdrawing the popup. Case 17 passed: after the
  popup's 60 s the terminal still answered both ways, and with no answer
  anywhere the request was refused at 2 min.
- Case 19 (key expiring with the popup open), 20 (`pinentry-curses`: went
  straight to the terminal prompt, and the `Approval backend failed (logged
  only once)` line appeared once), 21 (`serve` over SSH without a display)
  and 23 (`setsid -f`, popup only) passed.
- With `--no-pinentry`, the terminal cases 1, 2 and 6–9 passed on the
  server as before, now logged as `(terminal)`. Released as 0.3.0.

**2026-10-20, laptop + server `palvelin`** (steps 3a–3c: log timestamps,
the systemd user service, Fedora 44 Cinnamon, systemd 259):

- Timestamps: a foreground `serve` and `setsid -f sudo-agent serve > log`
  stamp every line; the popup's timeout is now 15 s.
- Case 24 (no display) passed: one timestamp per journal line, the
  no-backend startup line, the key added with `ssh-add -t 240m` (`usable
  for 4h`), and every `ssh-keygen -Y sign` refused.
- Case 25 passed: the popup appeared through the forwarded `agent.sock`
  and **Allow** approved it; stopping and restarting logged `Received
  SIGTERM` and ended cleanly.
- Case 26 passed after a reboot, and case 27 twice (the second time with a
  key loaded): the user manager kept running across the logouts, so
  `PartOf=graphical-session.target` stopped the agent; each login started a
  fresh one with no keys and the display. Released as 0.4.0.

**2026-10-21, laptop + server `palvelin`** (0.4.0 with `--pinentry
pinentry-qt`: `pinentry-qt` 1.3.2 on Qt 6, Fedora 44 Cinnamon on X11, a
foreground `serve`):

- Startup said `Approvals: a pinentry-qt popup or this terminal, whichever
  answers first`.
- Cases 13 (Allow) and 14 (Deny) passed, twice each. The popup's window
  title was `sudo-agent`, above the same text as the terminal prompt and
  its closing line; no heading (qt doesn't show `SETPROMPT`).
- Case 17 passed: the popup closed by itself after 15 s with no `Approval
  backend failed` line (so `pinentry-qt` reports its timeout as a timeout,
  not as Deny or a failure), and `y` at the terminal then approved it.
- Unlike `pinentry-gnome3`, the popup doesn't hold the keyboard: with it
  open, Alt+Tab reached the terminal and Ctrl-C there logged `denied
  (terminal)`, withdrawing the popup (case 16 without the timer).

**2026-10-21, laptop + server `vakoilu`** (step 4b: the service built from
the 4b tree, `pinentry-gnome3`, a release-build `sudo-agent approve` in a
laptop terminal; five requests through one `ssh -o
ForwardAgent=…/agent.sock vakoilu` session):

- Popup **Allow**, then **Deny**, each with the client's prompt open: the
  client printed `Withdrawn: answered elsewhere, or no longer needed`, the
  journal `Approved (pinentry)` / `denied (pinentry)` (case 32).
- **y** and **n** in the client: `Allowed` / `Denied`, journal `Allowed by
  approve client pid …` / `Denied by approve client pid …` and `(approve)`
  outcomes (cases 28, 29). Ctrl-C at its prompt denied, and Ctrl-C with no
  prompt quit it, logged `Approve client detached` (case 30).
- Found: after a popup answer, the client can't say whether it allowed or
  denied (the router withdraws other backends without a reason). Noted in
  `TODO.md` → Later.
- On the way: the first try printed `refused to send approval requests (too
  old for sudo-agent approve? …)`. The service still ran an older install
  (`~/.cargo/bin/sudo-agent`); `cargo install --path . --locked` and a
  restart fixed it.

Before that, the same day, on the laptop only (driven from a script in a
pty, `serve --no-pinentry` under `setsid`, `ssh-keygen -Y sign` against
`agent.sock`, which now refuses it: a re-run uses `control.sock`): y, n,
Ctrl-C, a timeout (`--approval-timeout 4s`:
`Withdrawn: no answer within 4s`), an agent restart with the prompt open,
two clients, and the startup errors (no terminal, no
agent, `agent.sock` given as the control socket) behaved as described.
That run stood in for cases 31 and 37 against `serve` rather than the
service.

Later the same day the user ran cases 31, 33, 34, 35 and 37 as written,
against the service: all passed. Case 36 passed on 2026-10-26 (below);
case 38 is still to be run.

**2026-10-26, the security fixes for 0.4.3** (payload labels, `agent.sock`
signing only `sudo` challenges and SSH logins, escaped log lines), on
`server-a` and `server-b`, the service with pinentry popups:

- Case 1 on both servers: the popup said `signing: a sudo challenge for
  user alice`, and `sudo` succeeded once allowed. So the parser reads real
  0.10.3 and 0.10.4 challenges. Denying (case 2) logged `denied
  (pinentry)`.
- An onward login from `server-b` through the forwarded `agent.sock`: the
  popup said `signing: an SSH login as user alice`; allowing let it
  through, denying refused it.
- Case 24, with `ssh-keygen -Y sign` against `control.sock`: headless, it
  was refused only for lack of an approval backend. In the desktop
  session it was allowed in the popup, and `ssh-keygen -Y
  check-novalidate` said `Good "test" signature`. Against `agent.sock` it
  was refused before any prompt.
- Case 36 passed as written. Killing the client also logs `Connection
  ended: … Broken pipe`: the agent answering the client's connection after
  it's gone. Harmless.
- Case 39 on `server-a`: a sudo-only key (in the `file=` list, `-t 5m`)
  next to the login key. Each popup named the right key and what it
  signed, with one prompt per operation. When the sudo key expired, only
  it was removed, and logins with the other key kept working.
- Not run: case 38 (no second machine to SSH into the laptop from), and
  adding a security key (no FIDO key at hand; the socket tests cover the
  refusal).

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
- **The login fails with `signing failed … agent refused operation`, and
  `sudo-agent` logs nothing**: the login uses your normal agent
  (`SSH_AUTH_SOCK`), not the forwarded one, and that agent doesn't have the
  key decrypted (e.g. it was only added to `sudo-agent`). Add it to your
  normal agent too, or log in through `sudo-agent` (see step 1).
- **`sudo-agent approve` says `refused to send approval requests (too old
  for sudo-agent approve? …)`**: usually the agent running is an older
  version (often the service's `~/.cargo/bin/sudo-agent`): install the new
  one and restart the service. Otherwise the agent refused the connection
  (its log says why), or `--control-socket` / `SUDO_AGENT_CONTROL_SOCKET`
  names `agent.sock`.
- **More detail**:
  - Server: the user can add `debug` to the `pam_ssh_agent_auth` line, then
    read `journalctl -t sudo --since -5min`, or `/var/log/auth.log` on Debian.
  - Laptop: the agent logs every approval and refusal to stderr.
- **Before any PAM change**, the user should keep a root shell open on the
  server (`sudo -s` in another session) until `sudo` is confirmed working.
