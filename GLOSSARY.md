# sudo-agent Glossary

The language of time-bound, human-approved signing in sudo-agent.

## Keys and expiry

**Loaded key**:
A private SSH key held by the agent with a finite expiry, available for
approval-gated signing while unexpired.
_Avoid_: unlocked key, trusted key

**Time-to-live (TTL)**:
The duration a loaded key may remain usable, measured from loading and
including time spent suspended; loading the same key again starts a new TTL.
_Avoid_: approval lifetime, session timeout

**Default TTL**:
The TTL given to a key added without a requested lifetime (or with `-t 0`)
and to keys loaded with `--key` (`--ttl`, default `15m`).
_Avoid_: maximum TTL

**Maximum TTL**:
The longest TTL the agent grants (`--max-ttl`, default `8h`); a longer
requested lifetime is clamped to it and logged, and a longer default TTL is a
startup error.
_Avoid_: default TTL

**Requested lifetime**:
The duration requested when adding a key (`ssh-add -t`), before the agent
applies its default TTL and maximum TTL.
_Avoid_: TTL (when referring to the requested rather than effective duration)

**Time left**:
The remaining duration before a loaded key expires.
_Avoid_: TTL (when referring to the remaining rather than original duration)

**Key expiry**:
The point at which a loaded key's TTL ends and it becomes unusable, including
for a request already awaiting approval.
_Avoid_: key removal, approval timeout

**Key removal**:
The deletion of a loaded key before its expiry, through `ssh-add -d` or `-D`
on the control socket; like key expiry, it withdraws approval prompts pending
for that key.
_Avoid_: key expiry

## Requests and decisions

**Signature request**:
A requesting client's request for the agent to sign particular data with a
particular key; an approval applies only to that request.
_Avoid_: sudo request (when the data may represent another purpose)

**Approval request**:
The yes/no question about a signature request, shared by the available
approval backends; the first approve or deny answer decides it.
_Avoid_: signature request (when referring specifically to the question)

**Sudo challenge**:
Authentication data identifying the `pam_ssh_agent_auth` service, presented for
signing as part of `sudo` authentication.
_Avoid_: sudo command (the challenge does not identify the command to run)

**SSH login**:
SSH public-key authentication presented for signing, including an onward
login from a host to which the agent is forwarded.
_Avoid_: sudo challenge

**Namespace signature (SSHSIG)**:
A signature request for arbitrary data within a specified namespace (e.g.
namespace `git` for commit signing, or `file`, via `ssh-keygen -Y sign`);
signed on `control.sock` but refused on `agent.sock`.
_Avoid_: sudo challenge, SSH login

**Approval**:
A person's affirmative answer accepted for one approval request, permitting
signing only while the key remains loaded and unexpired.
_Avoid_: key unlock, authentication success, remembered permission

**Denial**:
A person's negative answer accepted for an approval request, ending that
signature request across all approval backends (including Deny, Escape or
closing the window in a pinentry popup, and Ctrl-C at the foreground prompt).
_Avoid_: timeout, withdrawal, backend failure

**No answer**:
The absence of an approve or deny answer from an approval backend, including
when it times out, fails, or withdraws its prompt; another backend may still answer.
_Avoid_: denial

**Approval timeout**:
The maximum duration an approval backend waits for an answer before returning
no answer; distinct from key expiry and the requesting client's disconnection.
_Avoid_: key expiry, denial

**Refusal**:
The agent's rejection of a signature request, whether due to denial, lack of
approval, an unusable key, or an unsupported request. The agent also refuses
key management on the agent socket and connections to the control socket
that fail its checks; name what was refused in those cases.
_Avoid_: denial (unless a person actually answered negatively)

**Withdrawal**:
The ending of an approval prompt because an answer is no longer needed or
accepted there; it does not by itself identify the signature request's outcome.
The agent withdraws a prompt by cancelling that backend's cancellation token.
_Avoid_: denial, cancellation (without identifying what is being withdrawn)

## Approval channels

**Approval backend**:
A channel for answering approval requests: the daemon's foreground terminal,
a pinentry popup, or the attached approval clients considered together.
_Avoid_: approval client (when referring to every kind of backend)

**Approval prompt**:
The presentation of an approval request in one terminal or popup.
_Avoid_: passphrase prompt

**Passphrase prompt**:
The prompt for a secret to decrypt a private key into memory, asked once per
load and never at signing; the daemon shows it only for `--key`, and
`ssh-add` asks its own.
_Avoid_: approval prompt

**Approval client**:
A terminal client (`sudo-agent approve`) through which a person answers the
agent's approval requests independently of the daemon's foreground terminal.
_Avoid_: client (without qualification)

## Hosts and access

**Agent host**:
The machine running the agent and holding its loaded private keys, where
approval prompts appear, even while the user works in a session on a sudo host.
_Avoid_: local machine (without identifying whose point of view)

**Sudo host**:
A machine where `sudo` uses `pam_ssh_agent_auth` to request signatures from the
forwarded agent on the agent host.
_Avoid_: agent host, server (when its role is unclear)

**Forwarded agent**:
The agent socket made reachable on a remote host through SSH agent forwarding
(`ssh -o ForwardAgent=<agent socket>`); requests arriving through it reach the
agent from the local SSH process.
_Avoid_: remote agent (no agent runs on the remote host)

**Requesting client**:
A client submitting a signature request to the agent, directly or through
forwarding.
_Avoid_: client (without qualification)

**Local peer**:
The process directly connected to the agent on the agent host; with
forwarding, this is the local SSH process, not the remote process requesting `sudo`.
_Avoid_: remote requester, forwarding chain

**Agent socket**:
The agent interface intended for forwarding (`agent.sock`), offering key listings and
approval-gated signatures for sudo challenges and SSH logins.
_Avoid_: control socket

**Control socket**:
The agent interface reserved for local key management, approval clients,
key listings and approval-gated signing of arbitrary data (`control.sock`); it
is not meant to be forwarded, and refuses connections that appear to come
through `ssh`.
_Avoid_: forwarded socket
