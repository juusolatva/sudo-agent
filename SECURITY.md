# Security Policy

## Supported Versions

Only the latest release, or the default branch if there are no releases,
receives security fixes.

## Reporting a Vulnerability

Please do not report security vulnerabilities through public issues, pull
requests, or discussions.

Report them privately through GitHub's private vulnerability reporting:

1. Go to the repository's Security tab.
2. Click Report a vulnerability.

If that option is unavailable, please contact me using the email address
on my GitHub profile.

Please include:

- A description of the issue and its potential impact
- Steps to reproduce, or a proof of concept
- Affected version, commit, or configuration

## What to Expect

This is a personal project maintained on a best-effort basis. I aim to
acknowledge reports within 7 days and will keep you updated on progress.
Once a fix is released, you will be credited in the advisory unless you
prefer to remain anonymous.

## System and Scope

sudo-agent is a Linux SSH agent holding decrypted private keys for a
limited time. It asks for approval before signing requests, primarily
sudo authentication challenges received through SSH agent forwarding.
SSH login signatures are also supported on the forwarded socket.

Security review covers the daemon and approval client in `src/`, their
dependencies, deployment configuration, build and release workflows,
and security-relevant setup instructions.

The assets are private keys and passphrases, authority to sign with those
keys, the integrity of approval prompts and answers, and availability
of the agent. Server PAM configuration is managed manually.

## Threat Model and Trust Boundaries

- Treat remote servers, including their root users, as hostile. Anyone
  reaching a forwarded `agent.sock` may send arbitrary protocol data.
  This exposure matters even though the daemon listens on Unix sockets.
- Other local users are untrusted. Socket ownership and permissions
  must prevent their access.
- The agent host's root user and same-user processes able to access
  `control.sock` are trusted. Such processes can add or remove keys and
  answer approval requests. The agent is not a vault against host root
  or compromise of that user account.
- `agent.sock` permits key listing and approval-gated signing only.
  `control.sock` additionally permits key management and approval
  extensions. It must never be forwarded.
- The configured approval programs and local desktop or terminal session
  are trusted. Request payloads, key comments and peer-supplied text are
  untrusted display data.
- Payload labels describe the supplied bytes; they do not authenticate
  a remote host, user or command. Local peer details identify the local
  connection, not the process behind a forwarded connection.

## Security Invariants

- Every signature requires approval for that request. No available
  backend, all backends failing or timing out, or a winning denial must
  result in refusal. The first approval or denial wins; other prompts
  must be withdrawn. One backend failing must not override another
  backend's valid answer.
- Approvals must not transfer to another request. Late, unknown or
  withdrawn approval answers must not authorize signing. Client
  disconnection and key expiry or removal must withdraw pending prompts.
- Every loaded key has an agent-enforced TTL capped by policy. Suspend
  time counts. Key presence and expiry are checked again after approval,
  before signing; expired keys are not listed and are dropped.
- `agent.sock` must refuse key management and approval extensions.
  Signing there is restricted to recognized `pam_ssh_agent_auth`
  challenges and SSH login payloads. Signing arbitrary data through
  `control.sock` still requires approval.
- `control.sock` requires the agent's uid, rejects peers identified as
  `ssh`, and permanently refuses a connection after a session-bind
  message. These protections address accidental forwarding; the
  executable-name tripwire is not authentication of arbitrary relays.
- Socket directories must be private and owned by the agent's user,
  and sockets owner-only. Binding and cleanup must not remove a live
  socket or an unrelated replacement file.
- Attacker-controlled text must not rewrite prompts or forge log lines.
  Prompts must distinguish the requested signing purpose and key.
- Protocol handling must bound resource use, including connections,
  frame allocation and stalled reads or writes. Malformed requests must
  not terminate the daemon or bypass authorization.
- Private keys and passphrases must not appear in logs or protocol
  replies. Key material must be dropped and zeroized when removed.
  Unsupported key types and constraints must be refused.

## Reportable Findings and Severity Context

Report reachable violations of these boundaries, including unauthorized
signing, key disclosure, TTL bypass, approval confusion, access to control
operations through forwarding, and practical resource-exhaustion attacks.
Assess severity using the required attacker access, user interaction,
affected keys and resulting authority. A forwarded-server attack does
not require compromise of the agent host.

Host-root access and authorized same-user control operations are outside
the protection boundary. They do not excuse a path by which an untrusted
caller gains that access. External PAM or OpenSSH defects belong upstream,
but unsafe integration or instructions in this repository remain in scope.

## Known Limitations and Accepted Risk

SSH destinations are not bound to approvals. A hostile server can request
an SSH login instead of the sudo challenge the user expects; the prompt
must distinguish them. Popup approval can also receive Enter intended for
another window. These documented limitations do not exclude misleading
prompts or signatures produced without a valid approval.

Existing dependency exceptions are recorded in `.cargo/audit.toml` and
`osv-scanner.toml`: RUSTSEC-2023-0071 and RUSTSEC-2026-0387 rely on human
approval limiting signing-side-channel exposure; GHSA-qwgh-2vcv-g2f7 is
accepted on the recorded absence of a reachable panic-and-reuse path.
These are narrow accepted risks, not proof of safety. New reachability,
an effective attack despite approval, or changes weakening approval
require reassessment. Ed25519 is the recommended key type.

Tests and manual verification document intended controls; they do not
prove that a control cannot be bypassed.
