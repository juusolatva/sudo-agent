//! The SSH agent protocol side: listing identities and approving signatures.

use std::fmt;
use std::fs::File;
use std::future;
use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use signature::Signer;
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::message::Identity;
use ssh_agent_lib::proto::{
    AddIdentity, AddIdentityConstrained, AddSmartcardKeyConstrained, RemoveIdentity, SignRequest,
    SmartcardKey, signature::RSA_SHA2_512,
};
use ssh_agent_lib::ssh_encoding::Encode;
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, Signature};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::net::UnixStream;
use tokio_util::sync::CancellationToken;

use crate::keys::{self, KeyEntry};
use crate::routing::Router;
use crate::server::{Gate, Sessions};

// Message types of the requests a client can send (draft-miller-ssh-agent).
const REQUEST_IDENTITIES: u8 = 11;
const SIGN_REQUEST: u8 = 13;
const ADD_IDENTITY: u8 = 17;
const REMOVE_IDENTITY: u8 = 18;
const REMOVE_ALL_IDENTITIES: u8 = 19;
const ADD_SMARTCARD_KEY: u8 = 20;
const REMOVE_SMARTCARD_KEY: u8 = 21;
const LOCK: u8 = 22;
const UNLOCK: u8 = 23;
const ADD_ID_CONSTRAINED: u8 = 25;
const ADD_SMARTCARD_KEY_CONSTRAINED: u8 = 26;
const EXTENSION: u8 = 27;

/// Longest command line shown in an approval prompt, in characters.
const MAX_COMMAND_CHARS: usize = 200;

/// How much of `/proc/<pid>/cmdline` is read: plenty for
/// [`MAX_COMMAND_CHARS`], however long the argument list is.
const MAX_CMDLINE_BYTES: usize = 4096;

const KEY_EXPIRED_WHILE_WAITING: &str = "key expired while waiting for approval";
const KEY_REMOVED_WHILE_WAITING: &str = "key was removed or replaced while waiting for approval";

/// Longest key comment shown in an approval prompt, in characters (log lines
/// show it whole).
const MAX_COMMENT_CHARS: usize = 64;

/// Most `agent.sock` signature requests waiting or being served at once;
/// more are refused without waiting. Forwarded servers can open many
/// connections, and each queued request costs the user a prompt.
const MAX_FORWARDED_REQUESTS: usize = 16;

/// The method name of an OpenSSH 8.9+ login bound to the server's host key:
/// a [`publickey`] request with the host key appended.
const HOSTBOUND_METHOD: &[u8] = b"publickey-hostbound-v00@openssh.com";

/// `SSH_MSG_USERAUTH_REQUEST` (RFC 4252).
const USERAUTH_REQUEST: u8 = 50;

/// `SSH2_MSG_USERAUTH_TRUST_REQUEST`, the message type `pam_ssh_agent_auth`
/// defines for its challenges (as remembered from its `ssh2.h`; see
/// [`Payload::userauth`]).
const USERAUTH_TRUST_REQUEST: u8 = 54;

/// The service name in `pam_ssh_agent_auth`'s challenges.
const PAM_SERVICE: &[u8] = b"pam_ssh_agent_auth";

/// The service name in an SSH login's user authentication request.
const LOGIN_SERVICE: &[u8] = b"ssh-connection";

/// The start of the data `ssh-keygen -Y sign` (and so `git`) has signed.
const SSHSIG_MAGIC: &[u8] = b"SSHSIG";

/// Longest user name or namespace from a request's data shown in a prompt,
/// in characters.
const MAX_LABEL_CHARS: usize = 64;

/// Shared agent state; [`listen`](ssh_agent_lib::agent::listen) asks it for a
/// fresh [`Connection`] per accepted socket.
#[derive(Clone)]
pub struct SudoAgent {
    keys: Arc<Mutex<Vec<KeyEntry>>>,
    approvals: Arc<Router>,
    /// Serves signature requests one at a time, in arrival order (tokio's
    /// mutex is fair), from key lookup to logged outcome. Unlike `keys`, this
    /// is meant to be held while prompting: it guards the user's attention,
    /// not key material. It keeps a queued request's prompt from appearing
    /// before the previous outcome is logged, and its details from going
    /// stale while it waits.
    requests: Arc<tokio::sync::Mutex<()>>,
    /// Held by an `agent.sock` request for as long as
    /// [`requests`](Self::requests), and taken first, so those requests
    /// queue among themselves and at most one of them is in `requests` at a
    /// time: however many a server sends, a request from `control.sock`
    /// waits for at most two prompts (one before it, one forwarded request
    /// that got in line first).
    forwarded_lane: Arc<tokio::sync::Mutex<()>>,
    /// `agent.sock` signature requests waiting or being served.
    forwarded_requests: Arc<AtomicUsize>,
}

/// The key a request was approved for: the entry [`SudoAgent::describe`]
/// found, so that signing and withdrawing go by that entry, not just its
/// public key.
struct Described {
    /// For the prompt: comment, fingerprint and time left.
    text: String,
    id: u64,
    expires_at: Duration,
}

impl Described {
    /// Why the entry can no longer be used, once it can't: expired, or
    /// removed (or replaced by loading the key again) before then.
    fn gone(&self, now: Duration) -> &'static str {
        if now >= self.expires_at {
            KEY_EXPIRED_WHILE_WAITING
        } else {
            KEY_REMOVED_WHILE_WAITING
        }
    }
}

/// Counts one `agent.sock` signature request while it lives.
struct Counted(Arc<AtomicUsize>);

impl Counted {
    /// Counts a request in `count`, unless `max` are counted already.
    fn enter(count: &Arc<AtomicUsize>, max: usize) -> Option<Self> {
        let before = count.fetch_add(1, Ordering::AcqRel);
        // Dropped (and so uncounted again) if there are too many.
        let counted = Self(Arc::clone(count));
        (before < max).then_some(counted)
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl SudoAgent {
    pub fn new(keys: Arc<Mutex<Vec<KeyEntry>>>, approvals: Router) -> Self {
        Self {
            keys,
            approvals: Arc::new(approvals),
            requests: Arc::default(),
            forwarded_lane: Arc::default(),
            forwarded_requests: Arc::default(),
        }
    }

    /// Names the requested key for log lines: its comment and fingerprint,
    /// or just the fingerprint if it isn't loaded.
    fn key_name(&self, key_data: &KeyData) -> String {
        let fingerprint = key_data.fingerprint(HashAlg::Sha256);
        let keys = self.keys.lock().unwrap();
        match keys
            .iter()
            .find(|k| k.private_key.public_key().key_data() == key_data)
        {
            Some(entry) => format!("{} ({fingerprint})", sanitize(entry.private_key.comment())),
            None => fingerprint.to_string(),
        }
    }

    /// Describes the requested key for the approval prompt, or says why the
    /// request can't be served. Called before prompting so the user is never
    /// asked to approve something that would fail anyway.
    ///
    /// The fingerprint comes before the comment, which is cut short, so a
    /// long comment can't push the rest out of a popup.
    fn describe(&self, key_data: &KeyData, flags: u32) -> Result<Described, String> {
        let keys = self.keys.lock().unwrap();
        let now = keys::now();
        let entry = find(&keys, key_data, now).ok_or("key not loaded or expired")?;
        if let Some(reason) = unsupported(entry.private_key.algorithm(), flags) {
            return Err(reason.to_owned());
        }
        let comment = match entry.private_key.comment() {
            "" => String::new(),
            comment => format!(" ({})", shown(comment.as_bytes(), MAX_COMMENT_CHARS)),
        };
        Ok(Described {
            text: format!(
                "{}{comment}, {} left",
                entry.private_key.fingerprint(HashAlg::Sha256),
                keys::format_remaining(entry.expires_at - now)
            ),
            id: entry.id(),
            expires_at: entry.expires_at,
        })
    }

    /// Signs with the entry `key` was found in, if it is still loaded and
    /// unexpired. Looked up again because the lock isn't held while the user
    /// decides, and the TTL may run out meanwhile; by entry, so a key removed
    /// and loaded again needs a new approval.
    fn sign_with(&self, key: &Described, data: &[u8]) -> Result<Signature, String> {
        let keys = self.keys.lock().unwrap();
        let now = keys::now();
        let entry = keys
            .iter()
            .find(|k| k.id() == key.id && !k.is_expired(now))
            .ok_or_else(|| key.gone(now))?;
        entry
            .private_key
            .try_sign(data)
            .map_err(|e| format!("signing failed: {e}"))
    }

    /// Resolves once the entry `key` was found in can no longer be used,
    /// with why: expired, or no longer loaded (removed, or replaced).
    async fn key_gone(&self, key: &Described) -> &'static str {
        loop {
            let left = {
                let keys = self.keys.lock().unwrap();
                let now = keys::now();
                match keys.iter().find(|k| k.id() == key.id) {
                    Some(entry) if !entry.is_expired(now) => entry.expires_at - now,
                    _ => return key.gone(now),
                }
            };
            // `sleep` runs on CLOCK_MONOTONIC, which stops during suspend;
            // sleeping at most a second at a time re-checks the TTL on the
            // suspend-aware clock soon after waking.
            tokio::time::sleep(left.min(Duration::from_secs(1))).await;
        }
    }

    /// Loads `entry`. A loaded key with the same public key is replaced, which
    /// restarts its TTL; returns whether that happened.
    pub fn add(&self, entry: KeyEntry) -> bool {
        let mut keys = self.keys.lock().unwrap();
        let key_data = entry.private_key.public_key().key_data();
        let before = keys.len();
        keys.retain(|k| k.private_key.public_key().key_data() != key_data);
        let replaced = keys.len() != before;
        keys.push(entry);
        replaced
    }

    /// Removes (and so zeroizes) the key, returning its comment if it was
    /// loaded.
    pub fn remove(&self, key_data: &KeyData) -> Option<String> {
        let mut keys = self.keys.lock().unwrap();
        let index = keys
            .iter()
            .position(|k| k.private_key.public_key().key_data() == key_data)?;
        Some(keys.remove(index).private_key.comment().to_owned())
    }

    /// Removes (and so zeroizes) every key, returning how many there were.
    pub fn remove_all(&self) -> usize {
        let mut keys = self.keys.lock().unwrap();
        let count = keys.len();
        keys.clear();
        count
    }
}

impl Sessions for SudoAgent {
    type Session = Connection;

    fn session(&self, socket: &UnixStream) -> Connection {
        Connection::new(self.clone(), socket)
    }
}

/// One client connection, e.g. `pam_ssh_agent_auth` inside a `sudo` process.
/// Serves listing and approval-gated signing, on either socket.
pub struct Connection {
    agent: SudoAgent,
    peer: Peer,
    /// A duplicate of the client's socket, watched for the client hanging up
    /// while its request waits; see [`hung_up`]. `None` if it couldn't be
    /// duplicated, which just means a stale request waits until answered.
    client: Option<OwnedFd>,
    /// Signs only what a forwarded agent is for ([`Payload::forwardable`]),
    /// as on `agent.sock`, which servers reach through forwarding: anything
    /// else (a `git` signature, say) is refused before prompting.
    forwarded: bool,
}

impl Connection {
    /// A connection to `agent.sock`: signs only `sudo` challenges and SSH
    /// logins.
    pub fn new(agent: SudoAgent, socket: &UnixStream) -> Self {
        Self {
            agent,
            peer: Peer::of(socket),
            client: socket.as_fd().try_clone_to_owned().ok(),
            forwarded: true,
        }
    }

    /// A connection to `control.sock`: signs any data, still only once
    /// approved.
    pub fn control(agent: SudoAgent, socket: &UnixStream) -> Self {
        Self {
            forwarded: false,
            ..Self::new(agent, socket)
        }
    }

    pub fn agent(&self) -> &SudoAgent {
        &self.agent
    }

    pub fn peer(&self) -> &Peer {
        &self.peer
    }

    /// Resolves once the client has closed its end of the connection; see
    /// [`hung_up`].
    pub async fn hung_up(&self) {
        hung_up(self.client.as_ref()).await;
    }

    fn refuse_management(&self, what: &str) -> Result<(), AgentError> {
        log!(
            "Refused {what} from {}: agent.sock only lists and signs (keys are managed through control.sock)",
            self.peer
        );
        Err(AgentError::Failure)
    }

    /// Logs the refusal of a request for `subject` (what it signs, with which
    /// key).
    fn refuse(&self, subject: &str, reason: &str) -> Result<Signature, AgentError> {
        log!(
            "Refused signature request for {subject} from {}: {reason}",
            self.peer
        );
        Err(AgentError::Failure)
    }
}

impl Gate for Connection {
    /// On `agent.sock`, only listing, signing and extensions are decoded:
    /// anything else is refused (and logged) from its message type, so a
    /// server can't make us decode, say, a request to add a key with
    /// thousands of constraints.
    fn admit(&mut self, message_type: u8) -> bool {
        if !self.forwarded {
            return true;
        }
        let what = match message_type {
            REQUEST_IDENTITIES | SIGN_REQUEST | EXTENSION => return true,
            ADD_IDENTITY | ADD_ID_CONSTRAINED => "adding a key",
            REMOVE_IDENTITY => "removing a key",
            REMOVE_ALL_IDENTITIES => "removing all keys",
            ADD_SMARTCARD_KEY | ADD_SMARTCARD_KEY_CONSTRAINED => "adding a smartcard key",
            REMOVE_SMARTCARD_KEY => "removing a smartcard key",
            LOCK => "locking",
            UNLOCK => "unlocking",
            other => {
                log!("Refused request of unknown type {other} from {}", self.peer);
                return false;
            }
        };
        let _ = self.refuse_management(what);
        false
    }
}

#[async_trait]
impl Session for Connection {
    // Key management is refused here and logged: on the forwarded socket it
    // means a server tried it. (`control.sock` overrides these.)
    async fn add_identity(&mut self, _: AddIdentity) -> Result<(), AgentError> {
        self.refuse_management("adding a key")
    }

    async fn add_identity_constrained(
        &mut self,
        _: AddIdentityConstrained,
    ) -> Result<(), AgentError> {
        self.refuse_management("adding a key")
    }

    async fn remove_identity(&mut self, _: RemoveIdentity) -> Result<(), AgentError> {
        self.refuse_management("removing a key")
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        self.refuse_management("removing all keys")
    }

    async fn add_smartcard_key(&mut self, _: SmartcardKey) -> Result<(), AgentError> {
        self.refuse_management("adding a smartcard key")
    }

    async fn add_smartcard_key_constrained(
        &mut self,
        _: AddSmartcardKeyConstrained,
    ) -> Result<(), AgentError> {
        self.refuse_management("adding a smartcard key")
    }

    async fn remove_smartcard_key(&mut self, _: SmartcardKey) -> Result<(), AgentError> {
        self.refuse_management("removing a smartcard key")
    }

    async fn lock(&mut self, _: String) -> Result<(), AgentError> {
        self.refuse_management("locking")
    }

    async fn unlock(&mut self, _: String) -> Result<(), AgentError> {
        self.refuse_management("unlocking")
    }

    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let keys = self.agent.keys.lock().unwrap();
        let now = keys::now();

        // The reaper removes expired keys within a second; filter here too so
        // none is ever offered past its deadline.
        let valid_identities = keys
            .iter()
            .filter(|k| !k.is_expired(now))
            .map(|k| Identity {
                credential: k.private_key.public_key().key_data().clone().into(),
                comment: k.listed_comment(now),
            })
            .collect();

        Ok(valid_identities)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        // Named in the prompt; it and the key in every log line about the
        // request.
        let mut blob = Vec::new();
        let payload = match request.credential.encode(&mut blob) {
            Ok(()) => Payload::of(&request.data, &blob),
            Err(_) => Payload::Unknown,
        };
        let key_data = request.credential.key_data();
        let subject = format!("{payload} with key {}", self.agent.key_name(key_data));

        // What would be refused anyway is refused before it queues.
        if self.forwarded && !payload.forwardable() {
            return self.refuse(
                &subject,
                "agent.sock signs only sudo (pam_ssh_agent_auth) challenges and SSH logins",
            );
        }
        if let Err(reason) = self.agent.describe(key_data, request.flags) {
            return self.refuse(&subject, &reason);
        }

        // A client that goes away (e.g. its SSH connection closes) leaves the
        // queue, or has its prompt withdrawn.
        let hung_up = hung_up(self.client.as_ref());
        tokio::pin!(hung_up);

        let mut _counted = None;
        let mut _lane = None;
        if self.forwarded {
            let Some(counted) =
                Counted::enter(&self.agent.forwarded_requests, MAX_FORWARDED_REQUESTS)
            else {
                return self.refuse(&subject, "too many agent.sock requests waiting");
            };
            _counted = Some(counted);
            _lane = Some(tokio::select! {
                lane = self.agent.forwarded_lane.lock() => lane,
                () = &mut hung_up => return self.refuse(&subject, "client disconnected"),
            });
        }
        let _turn = tokio::select! {
            turn = self.agent.requests.lock() => turn,
            () = &mut hung_up => return self.refuse(&subject, "client disconnected"),
        };

        // Looked up again now that it's this request's turn: the key may
        // have gone, or been replaced, while it waited.
        let subject = format!("{payload} with key {}", self.agent.key_name(key_data));
        let key = match self.agent.describe(key_data, request.flags) {
            Ok(key) => key,
            Err(reason) => return self.refuse(&subject, &reason),
        };

        // What is signed comes first, then the key's fingerprint: a popup that
        // has to cut the text short cuts the peer's command line instead.
        let message = format!(
            "Signature request\n  signing: {payload}\n  key: {}\n  from: {}\nAllow?",
            key.text, self.peer
        );
        let cancel = CancellationToken::new();
        let confirm = self.agent.approvals.ask(&message, &cancel);
        tokio::pin!(confirm);
        let key_gone = self.agent.key_gone(&key);
        tokio::pin!(key_gone);
        let answer = tokio::select! {
            answer = &mut confirm => Ok(answer),
            () = &mut hung_up => Err("client disconnected"),
            reason = &mut key_gone => Err(reason),
        };
        let answer = match answer {
            Ok(answer) => answer,
            Err(reason) => {
                cancel.cancel();
                // Returns once the prompt is gone, so the log follows it.
                let _ = confirm.await;
                return self.refuse(&subject, reason);
            }
        };
        let answer = match answer {
            Ok(answer) => answer,
            // No backend answered: that counts as a denial.
            Err(e) => return self.refuse(&subject, &format!("not approved: {e}")),
        };
        for problem in &answer.problems {
            log!("Approval backend failed (logged only once): {problem}");
        }
        if let Some(from) = &answer.from {
            let verdict = if answer.approved { "Allowed" } else { "Denied" };
            log!("{verdict} by {from}");
        }
        if !answer.approved {
            return self.refuse(&subject, &format!("denied ({})", answer.by));
        }

        match self.agent.sign_with(&key, &request.data) {
            Ok(signature) => {
                log!(
                    "Approved ({}) signature request for {subject} from {}",
                    answer.by,
                    self.peer
                );
                Ok(signature)
            }
            Err(reason) => self.refuse(&subject, &reason),
        }
    }
}

fn find<'a>(keys: &'a [KeyEntry], key_data: &KeyData, now: Duration) -> Option<&'a KeyEntry> {
    keys.iter()
        .find(|k| !k.is_expired(now) && k.private_key.public_key().key_data() == key_data)
}

/// Resolves once the client has closed its end of the connection, or never if
/// that can't be watched. Anything it sends meanwhile (a pipelined request)
/// is left for the protocol loop to read.
async fn hung_up(client: Option<&OwnedFd>) {
    // Registered on our own duplicate of the socket, so the protocol loop's
    // registration of the original is left alone.
    // SAFETY: the `BorrowedFd` borrows `client` for as long as `socket` lives,
    // so the descriptor stays open and is the same one throughout.
    let Some(socket) = client.and_then(|fd| {
        unsafe { AsyncFd::register_with_interest(fd.as_fd(), Interest::READABLE) }.ok()
    }) else {
        return future::pending().await;
    };
    loop {
        let Ok(mut ready) = socket.readable().await else {
            return future::pending().await;
        };
        if ready.ready().is_read_closed() {
            return;
        }
        ready.clear_ready();
    }
}

/// Why a request for a key of type `algorithm` can't be served, if it
/// can't. Keys that can't sign at all are refused when loaded
/// ([`keys::unsignable`]); checked again here, before the prompt, in case
/// one gets in some other way.
///
/// `ssh-key` signs RSA only with SHA-512, so an RSA request must ask for
/// `rsa-sha2-512`; answering a SHA-1 or SHA-256 request with it would just
/// fail verification on the other end.
fn unsupported(algorithm: Algorithm, flags: u32) -> Option<&'static str> {
    keys::unsignable(&algorithm).or_else(|| {
        (algorithm.is_rsa() && flags & RSA_SHA2_512 == 0)
            .then_some("RSA signature requested without rsa-sha2-512 (use an Ed25519 key)")
    })
}

/// What a signature request asks to have signed, as far as its data tells.
/// Named in the prompt; `agent.sock` signs only the
/// [`forwardable`](Self::forwardable) kinds. The text held is from the
/// request, already made safe to show ([`shown`]).
#[derive(Debug, PartialEq)]
enum Payload {
    /// A `pam_ssh_agent_auth` challenge, from `sudo` run by `user`.
    Sudo { user: String },
    /// An SSH login as `user`.
    Login { user: String },
    /// `ssh-keygen -Y sign` data (`git` signs commits this way).
    Sshsig { namespace: Option<String> },
    /// Anything else.
    Unknown,
}

impl Payload {
    /// What `data` is, to be signed with the key whose blob (the request's
    /// credential, encoded) is `key`.
    fn of(data: &[u8], key: &[u8]) -> Self {
        if let Some(mut rest) = data.strip_prefix(SSHSIG_MAGIC) {
            let namespace = take_string(&mut rest).map(|ns| shown(ns, MAX_LABEL_CHARS));
            return Self::Sshsig { namespace };
        }
        Self::userauth(data, key).unwrap_or(Self::Unknown)
    }

    /// Whether `agent.sock` signs it: a `sudo` challenge, or an SSH login
    /// (onward `ssh`, `scp` or `git push` from the server). Both are still
    /// approved one by one, and the prompt says which it is, so a login
    /// swapped in for the `sudo` the user just ran stands out.
    fn forwardable(&self) -> bool {
        matches!(self, Self::Sudo { .. } | Self::Login { .. })
    }

    /// Reads an SSH public key user authentication request (RFC 4252 § 7),
    /// the layout `pam_ssh_agent_auth` also uses for its challenge (as
    /// remembered from its `userauth_pubkey_from_id.c`, 0.10.x):
    ///
    /// ```text
    /// string   session identifier (the module's own)
    /// byte     message type (the module's: SSH2_MSG_USERAUTH_TRUST_REQUEST)
    /// string   user name
    /// string   service name ("pam_ssh_agent_auth"; a login's: "ssh-connection")
    /// string   "publickey" (a login's may be "publickey-hostbound-v00@openssh.com")
    /// boolean  TRUE
    /// string   public key algorithm name
    /// string   public key blob
    /// string   server host key (only after the hostbound method)
    /// ```
    ///
    /// The service name is what makes it safe to sign, so it must match
    /// exactly: an SSH server checks a login signature over this data with
    /// its own service name, "ssh-connection" (OpenSSH treats any other as
    /// an invalid user), so a signature over a challenge can't be replayed
    /// as a login. The rest must be well formed too, so the prompt never
    /// names something else: the flag must be TRUE, the key blob the key
    /// asked to sign with, and nothing may follow. The message type may be
    /// 54 (the module's own, as remembered) or 50 (the standard one), and the
    /// algorithm name isn't checked (an RSA key signs as rsa-sha2-512 under
    /// the name ssh-rsa, say).
    fn userauth(mut data: &[u8], key: &[u8]) -> Option<Self> {
        take_string(&mut data)?; // session identifier
        let kind = take_byte(&mut data)?;
        let user = shown(take_string(&mut data)?, MAX_LABEL_CHARS);
        let service = take_string(&mut data)?;
        if service == PAM_SERVICE {
            let challenge = matches!(kind, USERAUTH_REQUEST | USERAUTH_TRUST_REQUEST)
                && publickey(data, key, false).is_some();
            return challenge.then_some(Self::Sudo { user });
        }
        let login = kind == USERAUTH_REQUEST
            && service == LOGIN_SERVICE
            && publickey(data, key, true).is_some();
        login.then_some(Self::Login { user })
    }
}

impl fmt::Display for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sudo { user } => write!(f, "a sudo challenge for user {user}"),
            Self::Login { user } => write!(f, "an SSH login as user {user}"),
            Self::Sshsig {
                namespace: Some(namespace),
            } => write!(f, "an ssh-keygen -Y sign signature, namespace {namespace}"),
            Self::Sshsig { namespace: None } => f.write_str("an ssh-keygen -Y sign signature"),
            Self::Unknown => f.write_str("unrecognized data"),
        }
    }
}

/// The rest of a public key user authentication request, after the
/// service name: the method name, has-signature flag (TRUE), algorithm name
/// and the blob of `key`, and with `hostbound` allowed, OpenSSH's
/// host-bound method, followed by the server's host key. Nothing may
/// follow.
fn publickey(mut data: &[u8], key: &[u8], hostbound: bool) -> Option<()> {
    let method = take_string(&mut data)?;
    let bound = match method {
        b"publickey" => false,
        HOSTBOUND_METHOD if hostbound => true,
        _ => return None,
    };
    (take_byte(&mut data)? != 0).then_some(())?;
    take_string(&mut data)?; // algorithm name
    (take_string(&mut data)? == key).then_some(())?;
    if bound {
        take_string(&mut data)?; // server host key
    }
    data.is_empty().then_some(())
}

/// Takes an SSH `string` (a big-endian `u32` length, then that many bytes)
/// off the front of `data`.
fn take_string<'a>(data: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (length, rest) = data.split_first_chunk::<4>()?;
    let length = usize::try_from(u32::from_be_bytes(*length)).ok()?;
    let (string, rest) = rest.split_at_checked(length)?;
    *data = rest;
    Some(string)
}

fn take_byte(data: &mut &[u8]) -> Option<u8> {
    let (&byte, rest) = data.split_first()?;
    *data = rest;
    Some(byte)
}

/// Text from a request's data (or a key comment), made safe to print and
/// cut short at `max` characters.
fn shown(raw: &[u8], max: usize) -> String {
    let text = String::from_utf8_lossy(raw);
    if text.chars().count() > max {
        let truncated: String = text.chars().take(max).collect();
        format!("{}…", sanitize(&truncated))
    } else {
        sanitize(&text)
    }
}

/// The process on the other end of the socket, from `SO_PEERCRED` at connect
/// time. Informational only: the command line is whatever that process says.
#[derive(Default)]
pub struct Peer {
    pid: Option<i32>,
    uid: Option<u32>,
    command: Option<String>,
}

impl Peer {
    fn of(socket: &UnixStream) -> Self {
        let Ok(cred) = socket.peer_cred() else {
            return Self::default();
        };
        Self {
            pid: cred.pid(),
            uid: Some(cred.uid()),
            command: cred.pid().and_then(command_line),
        }
    }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.pid {
            Some(pid) => write!(f, "pid {pid}")?,
            None => f.write_str("unknown process")?,
        }
        if let Some(uid) = self.uid {
            write!(f, ", uid {uid}")?;
        }
        if let Some(command) = &self.command {
            write!(f, ": {command}")?;
        }
        Ok(())
    }
}

/// Reads `/proc/<pid>/cmdline` (falling back to `comm`), made safe to print.
fn command_line(pid: i32) -> Option<String> {
    let mut raw = Vec::new();
    File::open(format!("/proc/{pid}/cmdline"))
        .ok()?
        .take(MAX_CMDLINE_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .ok()?;
    let cut = raw.len() > MAX_CMDLINE_BYTES;
    raw.truncate(MAX_CMDLINE_BYTES);
    let args: Vec<_> = raw
        .split(|&b| b == 0)
        .filter(|arg| !arg.is_empty())
        .map(String::from_utf8_lossy)
        .collect();
    let command = if args.is_empty() {
        std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?
    } else {
        args.join(" ")
    };
    let command = command.trim_end();
    if cut || command.chars().count() > MAX_COMMAND_CHARS {
        let truncated: String = command.chars().take(MAX_COMMAND_CHARS).collect();
        Some(format!("{}…", sanitize(&truncated)))
    } else {
        Some(sanitize(command))
    }
}

/// Escapes characters that could rewrite or disguise the prompt on a
/// terminal: control characters (including ANSI escape sequences) and
/// invisible or bidirectional-override formatting characters.
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        // Zero-width and bidirectional formatting, line and paragraph
        // separators (a line break in a popup), invisible operators and
        // tag characters.
        let disguising = matches!(
            c,
            '\u{061C}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
                | '\u{E0000}'..='\u{E007F}'
        );
        if c.is_control() || disguising {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::testing::entry;
    use crate::prompt::Prompter;
    use crate::prompt::testing::{ApprovesAfter, ScriptedPrompter};
    use signature::Verifier;
    use std::io;
    use tokio::io::AsyncWriteExt;

    /// `sh` with `args`, once its command line is in place. `spawn` can
    /// return while the child's `exec` is still under way: first it shows
    /// our own command line (the vfork parent is woken before the child's
    /// memory is switched), then an empty one.
    fn shell(args: &[&str]) -> (std::process::Child, i32) {
        let child = std::process::Command::new("sh").args(args).spawn().unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        while std::fs::read(format!("/proc/{pid}/cmdline"))
            .is_ok_and(|raw| !raw.starts_with(b"sh\0"))
        {
            std::thread::sleep(Duration::from_millis(1));
        }
        (child, pid)
    }

    #[test]
    fn long_command_lines_are_read_only_in_part() {
        // `; :` keeps the shell from replacing itself with `sleep`.
        let (mut child, pid) = shell(&["-c", "sleep 30; :", "sh", &"x".repeat(100_000)]);
        let command = command_line(pid);
        child.kill().unwrap();
        child.wait().unwrap();

        let command = command.unwrap();
        assert!(command.starts_with("sh -c sleep 30; : sh xxx"), "{command}");
        assert!(command.ends_with('…'), "{command}");
        assert_eq!(command.chars().count(), MAX_COMMAND_CHARS + 1);

        // Short once empty arguments are dropped, but cut off when read: the
        // rest isn't known, so it is marked.
        let mut args = vec!["-c", "sleep 30; :", "sh"];
        args.extend([""; MAX_CMDLINE_BYTES]);
        args.push("hidden");
        let (mut child, pid) = shell(&args);
        let command = command_line(pid);
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(command.as_deref(), Some("sh -c sleep 30; : sh…"));
    }

    /// A `sudo` challenge for `entry`'s key.
    fn request(entry: &KeyEntry) -> SignRequest {
        let key_data = entry.private_key.public_key().key_data();
        SignRequest {
            credential: key_data.clone().into(),
            data: testing::sudo_challenge(key_data, "alice"),
            flags: 0,
        }
    }

    fn connect(keys: Vec<KeyEntry>, prompter: Arc<dyn Prompter>) -> Connection {
        Connection {
            agent: SudoAgent::new(Arc::new(Mutex::new(keys)), Router::only(prompter)),
            peer: Peer::default(),
            client: None,
            forwarded: true,
        }
    }

    #[tokio::test]
    async fn approved_request_is_signed() {
        let key = entry("laptop", Duration::from_secs(60));
        let public = key.private_key.public_key().clone();
        let request = request(&key);
        let challenge = request.data.clone();
        let prompter = Arc::new(ScriptedPrompter::with_confirms([true]));
        let mut conn = connect(vec![key], prompter.clone());

        let signature = conn.sign(request).await.unwrap();
        public.key_data().verify(&challenge, &signature).unwrap();

        let asked = prompter.asked();
        assert_eq!(asked.len(), 1);
        assert!(asked[0].contains("(laptop)") && asked[0].ends_with("Allow?"));
        assert!(
            asked[0].contains("\n  signing: a sudo challenge for user alice\n"),
            "{asked:?}"
        );
    }

    #[test]
    fn log_lines_name_the_key() {
        let loaded = entry("laptop\x1b[2K", Duration::from_secs(60));
        let loaded_data = loaded.private_key.public_key().key_data().clone();
        let other = entry("other", Duration::from_secs(60));
        let other_data = other.private_key.public_key().key_data().clone();
        let agent = SudoAgent::new(
            Arc::new(Mutex::new(vec![loaded])),
            Router::only(Arc::new(ScriptedPrompter::with_confirms([true]))),
        );

        assert_eq!(
            agent.key_name(&loaded_data),
            format!(
                "laptop\\u{{1b}}[2K ({})",
                loaded_data.fingerprint(HashAlg::Sha256)
            )
        );
        // Not loaded: the fingerprint is all there is.
        assert_eq!(
            agent.key_name(&other_data),
            other_data.fingerprint(HashAlg::Sha256).to_string()
        );
    }

    /// On `agent.sock` a hostile server could otherwise have a `git`
    /// signature approved as if it were `sudo`. Logins are signed, saying
    /// so in the prompt.
    #[tokio::test]
    async fn agent_socket_signs_only_sudo_challenges_and_logins() {
        let key = entry("laptop", Duration::from_secs(60));
        let key_data = key.private_key.public_key().key_data().clone();
        let prompter = Arc::new(ScriptedPrompter::with_confirms([true; 4]));
        let mut conn = connect(vec![key], prompter.clone());

        let login = testing::ssh_login(&key_data, "alice");
        let request = SignRequest {
            credential: key_data.clone().into(),
            data: login.clone(),
            flags: 0,
        };
        let signature = conn.sign(request).await.unwrap();
        key_data.verify(&login, &signature).unwrap();
        let asked = prompter.asked();
        assert_eq!(asked.len(), 1);
        assert!(
            asked[0].contains("\n  signing: an SSH login as user alice\n"),
            "{asked:?}"
        );

        for data in [
            testing::sshsig("git"),
            b"pam_ssh_agent_auth challenge".to_vec(),
            Vec::new(),
        ] {
            let request = SignRequest {
                credential: key_data.clone().into(),
                data,
                flags: 0,
            };
            assert!(matches!(conn.sign(request).await, Err(AgentError::Failure)));
        }
        // Refused without asking.
        assert_eq!(prompter.asked().len(), 1);
    }

    #[tokio::test]
    async fn control_connections_sign_anything_once_approved() {
        let key = entry("laptop", Duration::from_secs(60));
        let key_data = key.private_key.public_key().key_data().clone();
        let prompter = Arc::new(ScriptedPrompter::with_confirms([true, false]));
        let mut conn = connect(vec![key], prompter.clone());
        conn.forwarded = false;

        let login = testing::ssh_login(&key_data, "alice");
        let request = |data: &[u8]| SignRequest {
            credential: key_data.clone().into(),
            data: data.to_vec(),
            flags: 0,
        };
        let signature = conn.sign(request(&login)).await.unwrap();
        key_data.verify(&login, &signature).unwrap();
        let sshsig = testing::sshsig("git");
        assert!(matches!(
            conn.sign(request(&sshsig)).await,
            Err(AgentError::Failure)
        ));

        let asked = prompter.asked();
        assert_eq!(asked.len(), 2);
        assert!(
            asked[0].contains("\n  signing: an SSH login as user alice\n"),
            "{asked:?}"
        );
        assert!(
            asked[1].contains("\n  signing: an ssh-keygen -Y sign signature, namespace git\n"),
            "{asked:?}"
        );
    }

    #[test]
    fn payload_kinds() {
        let laptop = entry("laptop", Duration::ZERO);
        let key = laptop.private_key.public_key().key_data();
        let blob = testing::blob(key);
        let of = |data: &[u8]| Payload::of(data, &blob);
        let sudo = || Payload::Sudo {
            user: "alice".into(),
        };
        let challenge = testing::sudo_challenge(key, "alice");
        assert_eq!(of(&challenge), sudo());
        // The standard message type, in case the module uses it.
        let standard = testing::userauth(USERAUTH_REQUEST, key, "alice", "pam_ssh_agent_auth");
        assert_eq!(of(&standard), sudo());
        // Nothing may follow the key blob.
        let mut longer = challenge.clone();
        longer.extend_from_slice(b"more");
        assert_eq!(of(&longer), Payload::Unknown);

        // Every field up to the key blob must be there.
        for cut in 0..challenge.len() {
            assert_ne!(of(&challenge[..cut]), sudo(), "cut at {cut}");
        }
        // The service name must match exactly, and the method be a public
        // key.
        for service in [
            "pam_ssh_agent_auth2",
            "PAM_SSH_AGENT_AUTH",
            "ssh-connection",
        ] {
            let other = testing::userauth(USERAUTH_TRUST_REQUEST, key, "alice", service);
            assert_ne!(of(&other), sudo(), "{service}");
        }
        let at = challenge
            .windows(9)
            .position(|w| w == b"publickey")
            .unwrap();
        let mut not_publickey = challenge.clone();
        not_publickey[at + 8] = b'z';
        assert_eq!(of(&not_publickey), Payload::Unknown);
        // The flag must be TRUE.
        let mut no_signature = challenge.clone();
        no_signature[at + 9] = 0;
        assert_eq!(of(&no_signature), Payload::Unknown);
        let other_type = testing::userauth(51, key, "alice", "pam_ssh_agent_auth");
        assert_eq!(of(&other_type), Payload::Unknown);
        // Only `ssh` logins may be host-bound.
        let hostbound_sudo = testing::userauth_with_method(
            USERAUTH_TRUST_REQUEST,
            key,
            "alice",
            "pam_ssh_agent_auth",
            "publickey-hostbound-v00@openssh.com",
        );
        assert_eq!(of(&hostbound_sudo), Payload::Unknown);
        // The key blob must be the key asked to sign with.
        let other_key = entry("other", Duration::ZERO);
        let other_blob = testing::blob(other_key.private_key.public_key().key_data());
        assert_eq!(Payload::of(&challenge, &other_blob), Payload::Unknown);
        assert_eq!(
            Payload::of(&testing::ssh_login(key, "alice"), &other_blob),
            Payload::Unknown
        );

        let login = || Payload::Login {
            user: "alice".into(),
        };
        let ssh_login = testing::ssh_login(key, "alice");
        assert_eq!(of(&ssh_login), login());
        let mut longer = ssh_login.clone();
        longer.push(0);
        assert_eq!(of(&longer), Payload::Unknown);
        for cut in 0..ssh_login.len() {
            assert_ne!(of(&ssh_login[..cut]), login(), "cut at {cut}");
        }
        // OpenSSH 8.9+ logs in with "publickey-hostbound-v00@openssh.com"
        // where the server supports it, with the server's host key last.
        let hostbound = testing::userauth_with_method(
            USERAUTH_REQUEST,
            key,
            "alice",
            "ssh-connection",
            "publickey-hostbound-v00@openssh.com",
        );
        assert_eq!(of(&hostbound), login());
        let mut no_host_key = hostbound.clone();
        no_host_key.truncate(hostbound.len() - blob.len() - 4);
        assert_eq!(of(&no_host_key), Payload::Unknown);
        assert_eq!(
            of(&testing::sshsig("git")),
            Payload::Sshsig {
                namespace: Some("git".into())
            }
        );
        assert_eq!(of(b"SSHSIG"), Payload::Sshsig { namespace: None });
        assert_eq!(of(b"pam_ssh_agent_auth challenge"), Payload::Unknown);
        assert_eq!(of(&[]), Payload::Unknown);
    }

    #[test]
    fn payload_labels_are_safe_to_show() {
        let laptop = entry("laptop", Duration::ZERO);
        let key = laptop.private_key.public_key().key_data();
        let blob = testing::blob(key);
        let label = |data: Vec<u8>| Payload::of(&data, &blob).to_string();

        assert_eq!(
            label(testing::sudo_challenge(key, "alice")),
            "a sudo challenge for user alice"
        );
        assert_eq!(
            label(testing::sudo_challenge(key, "root\x1b[2K\nok")),
            "a sudo challenge for user root\\u{1b}[2K\\u{a}ok"
        );
        let long = label(testing::ssh_login(key, &"x".repeat(1000)));
        assert_eq!(
            long,
            format!("an SSH login as user {}…", "x".repeat(MAX_LABEL_CHARS))
        );
        assert_eq!(
            label(testing::sshsig("file")),
            "an ssh-keygen -Y sign signature, namespace file"
        );
        assert_eq!(label(b"SSHSIG".to_vec()), "an ssh-keygen -Y sign signature");
        assert_eq!(label(b"anything".to_vec()), "unrecognized data");
    }

    #[tokio::test]
    async fn denied_request_is_refused() {
        let key = entry("laptop", Duration::from_secs(60));
        let request = request(&key);
        let prompter = Arc::new(ScriptedPrompter::with_confirms([false]));
        let mut conn = connect(vec![key], prompter.clone());

        assert!(matches!(conn.sign(request).await, Err(AgentError::Failure)));
        assert_eq!(prompter.asked().len(), 1);
    }

    #[tokio::test]
    async fn unknown_key_is_refused_without_prompting() {
        let loaded = entry("loaded", Duration::from_secs(60));
        let other = entry("other", Duration::from_secs(60));
        let prompter = Arc::new(ScriptedPrompter::with_confirms([true]));
        let mut conn = connect(vec![loaded], prompter.clone());

        assert!(conn.sign(request(&other)).await.is_err());
        assert!(prompter.asked().is_empty());
    }

    /// Loading refuses such keys; this is the backstop, should one get in.
    #[tokio::test]
    async fn key_that_cannot_sign_is_refused_without_prompting() {
        let key = KeyEntry::new(
            keys::testing::security_key("token"),
            keys::now() + Duration::from_secs(60),
        );
        let mut request = request(&key);
        request.flags = RSA_SHA2_512;
        let prompter = Arc::new(ScriptedPrompter::with_confirms([true]));
        let mut conn = connect(vec![key], prompter.clone());

        assert!(conn.sign(request).await.is_err());
        assert!(prompter.asked().is_empty());
    }

    #[tokio::test]
    async fn expired_key_is_refused_without_prompting() {
        let mut key = entry("old", Duration::ZERO);
        key.expires_at = keys::now();
        let request = request(&key);
        let prompter = Arc::new(ScriptedPrompter::with_confirms([true]));
        let mut conn = connect(vec![key], prompter.clone());

        assert!(conn.sign(request).await.is_err());
        assert!(prompter.asked().is_empty());
    }

    /// Approves, but lets the key's TTL run out while "the user" decides.
    struct ExpiresWhileAsking(Arc<Mutex<Vec<KeyEntry>>>);

    #[async_trait]
    impl Prompter for ExpiresWhileAsking {
        async fn passphrase(&self, _: &str) -> io::Result<zeroize::Zeroizing<String>> {
            unreachable!()
        }
        async fn confirm(&self, _: &str, _: &CancellationToken) -> io::Result<bool> {
            self.0.lock().unwrap()[0].expires_at = keys::now();
            Ok(true)
        }
    }

    #[tokio::test]
    async fn key_expiring_during_prompt_is_not_used() {
        let key = entry("racing", Duration::from_secs(60));
        let request = request(&key);
        let store = Arc::new(Mutex::new(vec![key]));
        let prompter = Arc::new(ExpiresWhileAsking(Arc::clone(&store)));
        let mut conn = Connection {
            agent: SudoAgent::new(store, Router::only(prompter)),
            peer: Peer::default(),
            client: None,
            forwarded: true,
        };

        assert!(matches!(conn.sign(request).await, Err(AgentError::Failure)));
    }

    /// Approves after a pause, recording the most prompts ever open at once.
    #[derive(Default)]
    struct SlowApprover {
        open: std::sync::atomic::AtomicUsize,
        max_open: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl Prompter for SlowApprover {
        async fn passphrase(&self, _: &str) -> io::Result<zeroize::Zeroizing<String>> {
            unreachable!()
        }
        async fn confirm(&self, _: &str, _: &CancellationToken) -> io::Result<bool> {
            use std::sync::atomic::Ordering::SeqCst;
            let open = self.open.fetch_add(1, SeqCst) + 1;
            self.max_open.fetch_max(open, SeqCst);
            tokio::time::sleep(Duration::from_millis(20)).await;
            self.open.fetch_sub(1, SeqCst);
            Ok(true)
        }
    }

    #[tokio::test]
    async fn concurrent_requests_are_served_one_at_a_time() {
        let key = entry("shared", Duration::from_secs(60));
        let (first, second) = (request(&key), request(&key));
        let prompter = Arc::new(SlowApprover::default());
        let agent = SudoAgent::new(
            Arc::new(Mutex::new(vec![key])),
            Router::only(prompter.clone()),
        );
        let mut a = Connection {
            agent: agent.clone(),
            peer: Peer::default(),
            client: None,
            forwarded: true,
        };
        let mut b = Connection {
            agent,
            peer: Peer::default(),
            client: None,
            forwarded: true,
        };

        let (a, b) = tokio::join!(a.sign(first), b.sign(second));
        assert!(a.is_ok() && b.is_ok());
        assert_eq!(
            prompter.max_open.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    /// A connection whose client end is returned, to hang up or write to.
    fn with_client(agent: SudoAgent) -> (Connection, UnixStream) {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let conn = Connection {
            agent,
            peer: Peer::default(),
            client: Some(ours.as_fd().try_clone_to_owned().unwrap()),
            forwarded: true,
        };
        (conn, theirs)
    }

    #[tokio::test]
    async fn hanging_up_withdraws_the_prompt() {
        let key = entry("laptop", Duration::from_secs(60));
        let request = request(&key);
        let prompter = Arc::new(ApprovesAfter::new(Duration::from_secs(60)));
        let agent = SudoAgent::new(
            Arc::new(Mutex::new(vec![key])),
            Router::only(prompter.clone()),
        );
        let (mut conn, client) = with_client(agent);

        let sign = tokio::spawn(async move { conn.sign(request).await });
        prompter.until_asked(1).await;
        drop(client);

        let result = tokio::time::timeout(Duration::from_secs(5), sign)
            .await
            .expect("prompt withdrawn")
            .unwrap();
        assert!(matches!(result, Err(AgentError::Failure)));
        assert_eq!(prompter.times_cancelled(), 1);
    }

    #[tokio::test]
    async fn key_expiring_withdraws_the_prompt() {
        let key = entry("short-lived", Duration::from_millis(100));
        let request = request(&key);
        let prompter = Arc::new(ApprovesAfter::new(Duration::from_secs(60)));
        let mut conn = connect(vec![key], prompter.clone());

        let result = tokio::time::timeout(Duration::from_secs(5), conn.sign(request))
            .await
            .expect("prompt withdrawn");
        assert!(matches!(result, Err(AgentError::Failure)));
        assert_eq!(prompter.times_cancelled(), 1);
    }

    #[tokio::test]
    async fn hanging_up_while_queued_skips_the_prompt() {
        let key = entry("shared", Duration::from_secs(60));
        let (first_request, second_request) = (request(&key), request(&key));
        let prompter = Arc::new(ApprovesAfter::new(Duration::from_millis(500)));
        let agent = SudoAgent::new(
            Arc::new(Mutex::new(vec![key])),
            Router::only(prompter.clone()),
        );
        let mut first = Connection {
            agent: agent.clone(),
            peer: Peer::default(),
            client: None,
            forwarded: true,
        };
        let (mut second, client) = with_client(agent);

        let first = tokio::spawn(async move { first.sign(first_request).await });
        prompter.until_asked(1).await;
        let second = tokio::spawn(async move { second.sign(second_request).await });
        drop(client);

        // Leaves the queue while the first prompt is still open.
        let second = tokio::time::timeout(Duration::from_millis(250), second)
            .await
            .expect("left the queue")
            .unwrap();
        assert!(matches!(second, Err(AgentError::Failure)));
        assert!(first.await.unwrap().is_ok());
        assert_eq!(prompter.times_asked(), 1);
    }

    #[tokio::test]
    async fn pipelined_request_is_not_a_hang_up() {
        let key = entry("laptop", Duration::from_secs(60));
        let request = request(&key);
        let prompter = Arc::new(ApprovesAfter::new(Duration::from_millis(50)));
        let agent = SudoAgent::new(
            Arc::new(Mutex::new(vec![key])),
            Router::only(prompter.clone()),
        );
        let (mut conn, mut client) = with_client(agent);

        // A complete REQUEST_IDENTITIES message, sent before the answer.
        client.write_all(&[0, 0, 0, 1, 11]).await.unwrap();
        assert!(conn.sign(request).await.is_ok());
        assert_eq!(prompter.times_cancelled(), 0);
    }

    #[test]
    fn rsa_needs_sha512_flag() {
        let rsa = Algorithm::Rsa { hash: None };
        assert!(unsupported(rsa.clone(), 0).is_some());
        assert!(unsupported(rsa.clone(), 0x02).is_some()); // rsa-sha2-256
        assert!(unsupported(rsa, RSA_SHA2_512).is_none());
        assert!(unsupported(Algorithm::Ed25519, 0).is_none());
    }

    #[test]
    fn sanitize_escapes_terminal_tricks() {
        assert_eq!(sanitize("sudo apt upgrade"), "sudo apt upgrade");
        assert_eq!(sanitize("päivitä"), "päivitä");
        assert_eq!(sanitize("a\x1b[2Kb"), "a\\u{1b}[2Kb");
        assert_eq!(sanitize("x\ny"), "x\\u{a}y");
        assert_eq!(sanitize("evil\u{202E}txt"), "evil\\u{202e}txt");
        // Line breaks in a popup, invisible operators and tags.
        assert_eq!(sanitize("a\u{2028}b\u{2029}c"), "a\\u{2028}b\\u{2029}c");
        assert_eq!(sanitize("a\u{061C}b\u{2060}c"), "a\\u{61c}b\\u{2060}c");
        assert_eq!(sanitize("a\u{E0041}b"), "a\\u{e0041}b");
    }

    #[tokio::test]
    async fn key_loaded_again_needs_a_new_approval() {
        let key = entry("laptop", Duration::from_secs(60));
        let again = KeyEntry::new(key.private_key.clone(), key.expires_at);
        let key_data = key.private_key.public_key().key_data().clone();
        let request = request(&key);
        let prompter = Arc::new(ApprovesAfter::new(Duration::from_millis(300)));
        let agent = SudoAgent::new(
            Arc::new(Mutex::new(vec![key])),
            Router::only(prompter.clone()),
        );
        let mut conn = Connection {
            agent: agent.clone(),
            peer: Peer::default(),
            client: None,
            forwarded: true,
        };

        let sign = tokio::spawn(async move { conn.sign(request).await });
        prompter.until_asked(1).await;
        // Removed and loaded again before the prompt is answered.
        assert!(agent.remove(&key_data).is_some());
        assert!(!agent.add(again));
        let result = tokio::time::timeout(Duration::from_secs(5), sign)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(AgentError::Failure)));
    }

    #[test]
    fn a_gone_key_says_whether_it_expired() {
        let key = Described {
            text: String::new(),
            id: 0,
            expires_at: Duration::from_secs(100),
        };
        assert_eq!(key.gone(Duration::from_secs(99)), KEY_REMOVED_WHILE_WAITING);
        assert_eq!(
            key.gone(Duration::from_secs(100)),
            KEY_EXPIRED_WHILE_WAITING
        );
    }

    #[test]
    fn long_comments_are_cut_after_the_fingerprint() {
        let key = entry(&"c".repeat(1000), Duration::from_secs(60));
        let key_data = key.private_key.public_key().key_data().clone();
        let fingerprint = key.private_key.fingerprint(HashAlg::Sha256).to_string();
        let agent = SudoAgent::new(
            Arc::new(Mutex::new(vec![key])),
            Router::only(Arc::new(ScriptedPrompter::default())),
        );
        let text = agent.describe(&key_data, 0).unwrap().text;
        assert!(text.starts_with(&format!("{fingerprint} (")), "{text}");
        assert!(
            text.contains(&format!("({}…), ", "c".repeat(MAX_COMMENT_CHARS))),
            "{text}"
        );
    }

    #[test]
    fn forwarded_requests_are_counted_up_to_a_limit() {
        let count = Arc::new(AtomicUsize::new(0));
        let first = Counted::enter(&count, 2).unwrap();
        let second = Counted::enter(&count, 2).unwrap();
        assert!(Counted::enter(&count, 2).is_none());
        assert_eq!(count.load(Ordering::SeqCst), 2);
        drop(first);
        let third = Counted::enter(&count, 2).unwrap();
        drop((second, third));
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn forwarded_requests_queue_among_themselves() {
        let key = entry("laptop", Duration::from_secs(60));
        let prompter = Arc::new(ApprovesAfter::new(Duration::from_millis(150)));
        let agent = SudoAgent::new(
            Arc::new(Mutex::new(vec![key])),
            Router::only(prompter.clone()),
        );
        let key = agent.keys.lock().unwrap()[0].private_key.clone();
        let entry = KeyEntry::new(key, Duration::MAX);
        let done = Arc::new(Mutex::new(Vec::new()));
        let start = |name: &'static str, forwarded: bool| {
            let mut conn = Connection {
                agent: agent.clone(),
                peer: Peer::default(),
                client: None,
                forwarded,
            };
            let request = request(&entry);
            let done = Arc::clone(&done);
            tokio::spawn(async move {
                assert!(conn.sign(request).await.is_ok(), "{name}");
                done.lock().unwrap().push(name);
            })
        };

        let mut tasks = vec![start("forwarded 1", true)];
        prompter.until_asked(1).await;
        for (name, forwarded) in [
            ("forwarded 2", true),
            ("forwarded 3", true),
            ("control", false),
        ] {
            tasks.push(start(name, forwarded));
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        for task in tasks {
            task.await.unwrap();
        }
        // The control request waited only for the open prompt, not for the
        // forwarded ones queued behind it.
        assert_eq!(
            *done.lock().unwrap(),
            ["forwarded 1", "control", "forwarded 2", "forwarded 3"]
        );
    }

    #[test]
    fn peer_display() {
        assert_eq!(Peer::default().to_string(), "unknown process");
        let peer = Peer {
            pid: Some(42),
            uid: Some(1000),
            command: Some("sudo -v".into()),
        };
        assert_eq!(peer.to_string(), "pid 42, uid 1000: sudo -v");
    }
}

/// Signature request data for tests, as real clients send it.
#[cfg(test)]
pub mod testing {
    use super::*;

    /// What `pam_ssh_agent_auth` asks to sign when `user` runs `sudo` with
    /// `key` ([`Payload::userauth`]).
    pub fn sudo_challenge(key: &KeyData, user: &str) -> Vec<u8> {
        userauth(USERAUTH_TRUST_REQUEST, key, user, "pam_ssh_agent_auth")
    }

    /// What `ssh` asks to sign to log in as `user` with `key`.
    pub fn ssh_login(key: &KeyData, user: &str) -> Vec<u8> {
        userauth(USERAUTH_REQUEST, key, user, "ssh-connection")
    }

    /// What `ssh-keygen -Y sign -n <namespace>` asks to sign.
    pub fn sshsig(namespace: &str) -> Vec<u8> {
        ssh_key::SshSig::signed_data(namespace, HashAlg::Sha512, b"a commit").unwrap()
    }

    /// A public key user authentication request of message type `kind`.
    pub fn userauth(kind: u8, key: &KeyData, user: &str, service: &str) -> Vec<u8> {
        userauth_with_method(kind, key, user, service, "publickey")
    }

    /// [`userauth`] with another method name.
    pub fn userauth_with_method(
        kind: u8,
        key: &KeyData,
        user: &str,
        service: &str,
        method: &str,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        [7u8; 32].as_slice().encode(&mut data).unwrap(); // session identifier
        kind.encode(&mut data).unwrap();
        user.encode(&mut data).unwrap();
        service.encode(&mut data).unwrap();
        method.encode(&mut data).unwrap();
        1u8.encode(&mut data).unwrap();
        key.algorithm().as_str().encode(&mut data).unwrap();
        blob(key).encode(&mut data).unwrap();
        if method == "publickey-hostbound-v00@openssh.com" {
            // The server's host key; any key will do.
            blob(key).encode(&mut data).unwrap();
        }
        data
    }

    /// The encoded public key, as in a request's data and credential.
    pub fn blob(key: &KeyData) -> Vec<u8> {
        let mut blob = Vec::new();
        key.encode(&mut blob).unwrap();
        blob
    }
}
