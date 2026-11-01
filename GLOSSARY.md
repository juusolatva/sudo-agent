# sudo-agent

The language of time-bound, human-approved signing in sudo-agent.

## Language

### Keys and expiry

**Loaded key**:
A private SSH key held by the agent with a finite expiry, available for
approval-gated signing while unexpired.
_Avoid_: unlocked key, trusted key

**Time-to-live (TTL)**:
The duration a loaded key may remain usable, measured from loading and
including time spent suspended; loading the same key again starts a new TTL.
_Avoid_: approval lifetime, session timeout

**Requested lifetime**:
The duration requested when adding a key, before the agent applies its
default TTL and maximum TTL.
_Avoid_: TTL (when referring to the requested rather than effective duration)

**Time left**:
The remaining duration before a loaded key expires.
_Avoid_: TTL (when referring to the remaining rather than original duration)

**Key expiry**:
The point at which a loaded key's TTL ends and it becomes unusable, including
for a request already awaiting approval.
_Avoid_: key removal, approval timeout

### Requests and decisions

**Signature request**:
A client's request for the agent to sign particular data with a particular
key; an approval applies only to that request.
_Avoid_: sudo request (when the data may represent another purpose)

**Approval request**:
The yes/no question about a signature request, shared by the available
approval backends; the first approve or deny answer decides it.
_Avoid_: signature request (when referring specifically to the question)

**Sudo challenge**:
Authentication data identifying the pam_ssh_agent_auth service, presented for
signing as part of sudo authentication.
_Avoid_: sudo command (the challenge does not identify the command to run)

**SSH login**:
SSH public-key authentication presented for signing, including an onward
login from a host to which the agent is forwarded.
_Avoid_: sudo challenge

**Approval**:
A person's affirmative answer accepted for one approval request, permitting
signing only while the key remains loaded and unexpired.
_Avoid_: key unlock, authentication success, remembered permission

**Denial**:
A person's negative answer accepted for an approval request, ending that
signature request across all approval backends.
_Avoid_: timeout, withdrawal, backend failure

**No answer**:
The absence of an approve or deny answer from an approval backend, including
when it times out, fails, or withdraws its prompt; another backend may still answer.
_Avoid_: denial

**Refusal**:
The agent's rejection of a signature request, whether due to denial, lack of
approval, an unusable key, or an unsupported request.
_Avoid_: denial (unless a person actually answered negatively)

**Withdrawal**:
The ending of an approval prompt because an answer is no longer needed or
accepted there; it does not by itself identify the signature request's outcome.
_Avoid_: denial, cancellation (without identifying what is being withdrawn)

### Approval channels

**Approval backend**:
A channel for answering approval requests: the daemon's foreground terminal,
a pinentry popup, or the attached approval clients considered together.
_Avoid_: approval client (when referring to every kind of backend)

**Approval prompt**:
The presentation of an approval request in one terminal or popup.
_Avoid_: passphrase prompt

**Approval client**:
A terminal client through which a person answers the agent's approval
requests independently of the daemon's foreground terminal.
_Avoid_: client (without qualification)

### Hosts and access

**Agent host**:
The machine running the agent and holding its loaded private keys, where
approval backends run even when a terminal is accessed remotely.
_Avoid_: local machine (without identifying whose point of view)

**Sudo host**:
A machine where sudo uses pam_ssh_agent_auth to request signatures from the
forwarded agent on the agent host.
_Avoid_: agent host, server (when its role is unclear)

**Requesting client**:
A client submitting a signature request to the agent, directly or through
forwarding.
_Avoid_: client (without qualification)

**Local peer**:
The process directly connected to the agent on the agent host; with
forwarding, this is the local SSH process, not the remote process requesting sudo.
_Avoid_: remote requester, forwarding chain

**Agent socket**:
The agent interface intended for forwarding, offering key listings and
approval-gated signatures for sudo challenges and SSH logins.
_Avoid_: control socket

**Control socket**:
The agent interface reserved for local key management, approval clients,
key listings and approval-gated signing of arbitrary data; it is never forwarded.
_Avoid_: forwarded socket
