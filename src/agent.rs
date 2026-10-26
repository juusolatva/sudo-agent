//! The SSH agent protocol side: listing identities and approving signatures.

use std::fmt;
use std::fs::File;
use std::future;
use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use signature::Signer;
use ssh_agent_lib::agent::{Agent, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::message::Identity;
use ssh_agent_lib::proto::{
    AddIdentity, AddIdentityConstrained, AddSmartcardKeyConstrained, RemoveIdentity, SignRequest,
    SmartcardKey, signature::RSA_SHA2_512,
};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, Signature};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;

use crate::keys::{self, KeyEntry};
use crate::routing::Router;

/// Longest command line shown in an approval prompt, in characters.
const MAX_COMMAND_CHARS: usize = 200;

/// How much of `/proc/<pid>/cmdline` is read: plenty for
/// [`MAX_COMMAND_CHARS`], however long the argument list is.
const MAX_CMDLINE_BYTES: usize = 4096;

const KEY_EXPIRED_WHILE_WAITING: &str = "key expired while waiting for approval";

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
}

impl SudoAgent {
    pub fn new(keys: Arc<Mutex<Vec<KeyEntry>>>, approvals: Router) -> Self {
        Self {
            keys,
            approvals: Arc::new(approvals),
            requests: Arc::default(),
        }
    }

    /// Describes the requested key for the approval prompt, or says why the
    /// request can't be served. Called before prompting so the user is never
    /// asked to approve something that would fail anyway.
    fn describe(&self, key_data: &KeyData, flags: u32) -> Result<String, String> {
        let keys = self.keys.lock().unwrap();
        let now = keys::now();
        let entry = find(&keys, key_data, now).ok_or("key not loaded or expired")?;
        if let Some(reason) = unsupported(entry.private_key.algorithm(), flags) {
            return Err(reason.to_owned());
        }
        Ok(format!(
            "{} ({}), {} left",
            sanitize(entry.private_key.comment()),
            entry.private_key.fingerprint(HashAlg::Sha256),
            keys::format_remaining(entry.expires_at - now)
        ))
    }

    /// Signs with the key if it is still loaded and unexpired. Looked up again
    /// (rather than kept from [`describe`](Self::describe)) because the lock
    /// isn't held while the user decides, and the TTL may run out meanwhile.
    fn sign_with(&self, key_data: &KeyData, data: &[u8]) -> Result<Signature, String> {
        let keys = self.keys.lock().unwrap();
        let entry = find(&keys, key_data, keys::now()).ok_or(KEY_EXPIRED_WHILE_WAITING)?;
        entry
            .private_key
            .try_sign(data)
            .map_err(|e| format!("signing failed: {e}"))
    }

    /// Resolves once the key can no longer be used: expired, or no longer
    /// loaded.
    async fn key_gone(&self, key_data: &KeyData) {
        loop {
            let left = {
                let keys = self.keys.lock().unwrap();
                let now = keys::now();
                match find(&keys, key_data, now) {
                    Some(entry) => entry.expires_at - now,
                    None => return,
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

impl Agent<UnixListener> for SudoAgent {
    fn new_session(&mut self, socket: &UnixStream) -> impl Session {
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
}

impl Connection {
    pub fn new(agent: SudoAgent, socket: &UnixStream) -> Self {
        Self {
            agent,
            peer: Peer::of(socket),
            client: socket.as_fd().try_clone_to_owned().ok(),
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

    fn refuse(&self, reason: &str) -> Result<Signature, AgentError> {
        log!("Refused signature request from {}: {reason}", self.peer);
        Err(AgentError::Failure)
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
        // A client that goes away (e.g. its SSH connection closes) leaves the
        // queue, or has its prompt withdrawn.
        let hung_up = hung_up(self.client.as_ref());
        tokio::pin!(hung_up);

        let _turn = tokio::select! {
            turn = self.agent.requests.lock() => turn,
            () = &mut hung_up => return self.refuse("client disconnected"),
        };

        let key_data = request.credential.key_data();
        let key = match self.agent.describe(key_data, request.flags) {
            Ok(key) => key,
            Err(reason) => return self.refuse(&reason),
        };

        let message = format!("Signature request from {}\n  key: {key}\nAllow?", self.peer);
        let cancel = CancellationToken::new();
        let confirm = self.agent.approvals.ask(&message, &cancel);
        tokio::pin!(confirm);
        let key_gone = self.agent.key_gone(key_data);
        tokio::pin!(key_gone);
        let answer = tokio::select! {
            answer = &mut confirm => Ok(answer),
            () = &mut hung_up => Err("client disconnected"),
            () = &mut key_gone => Err(KEY_EXPIRED_WHILE_WAITING),
        };
        let answer = match answer {
            Ok(answer) => answer,
            Err(reason) => {
                cancel.cancel();
                // Returns once the prompt is gone, so the log follows it.
                let _ = confirm.await;
                return self.refuse(reason);
            }
        };
        let answer = match answer {
            Ok(answer) => answer,
            // No backend answered: that counts as a denial.
            Err(e) => return self.refuse(&format!("not approved: {e}")),
        };
        for problem in &answer.problems {
            log!("Approval backend failed (logged only once): {problem}");
        }
        if !answer.approved {
            return self.refuse(&format!("denied ({})", answer.by));
        }

        match self.agent.sign_with(key_data, &request.data) {
            Ok(signature) => {
                log!(
                    "Approved ({}) signature request from {}",
                    answer.by,
                    self.peer
                );
                Ok(signature)
            }
            Err(reason) => self.refuse(&reason),
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
        let disguising = matches!(
            c,
            '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
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

    const CHALLENGE: &[u8] = b"pam_ssh_agent_auth challenge";

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

    fn request(entry: &KeyEntry) -> SignRequest {
        SignRequest {
            credential: entry.private_key.public_key().key_data().clone().into(),
            data: CHALLENGE.to_vec(),
            flags: 0,
        }
    }

    fn connect(keys: Vec<KeyEntry>, prompter: Arc<dyn Prompter>) -> Connection {
        Connection {
            agent: SudoAgent::new(Arc::new(Mutex::new(keys)), Router::only(prompter)),
            peer: Peer::default(),
            client: None,
        }
    }

    #[tokio::test]
    async fn approved_request_is_signed() {
        let key = entry("laptop", Duration::from_secs(60));
        let public = key.private_key.public_key().clone();
        let request = request(&key);
        let prompter = Arc::new(ScriptedPrompter::with_confirms([true]));
        let mut conn = connect(vec![key], prompter.clone());

        let signature = conn.sign(request).await.unwrap();
        public.key_data().verify(CHALLENGE, &signature).unwrap();

        let asked = prompter.asked();
        assert_eq!(asked.len(), 1);
        assert!(asked[0].contains("laptop") && asked[0].ends_with("Allow?"));
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
        let key = KeyEntry {
            private_key: keys::testing::security_key("token"),
            expires_at: keys::now() + Duration::from_secs(60),
        };
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
        };
        let mut b = Connection {
            agent,
            peer: Peer::default(),
            client: None,
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
