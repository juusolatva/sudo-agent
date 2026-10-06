//! The SSH agent protocol side: listing identities and approving signatures.

use std::fmt;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use signature::Signer;
use ssh_agent_lib::agent::{Agent, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::message::Identity;
use ssh_agent_lib::proto::{SignRequest, signature::RSA_SHA2_512};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, Signature};
use tokio::net::{UnixListener, UnixStream};

use crate::keys::{self, KeyEntry};
use crate::prompt::Prompter;

/// Longest command line shown in an approval prompt, in characters.
const MAX_COMMAND_CHARS: usize = 200;

/// Shared agent state; [`listen`](ssh_agent_lib::agent::listen) asks it for a
/// fresh [`Connection`] per accepted socket.
#[derive(Clone)]
pub struct SudoAgent {
    keys: Arc<Mutex<Vec<KeyEntry>>>,
    prompter: Arc<dyn Prompter>,
    /// Serves signature requests one at a time, in arrival order (tokio's
    /// mutex is fair), from key lookup to logged outcome. Unlike `keys`, this
    /// is meant to be held while prompting: it guards the user's attention,
    /// not key material. It keeps a queued request's prompt from appearing
    /// before the previous outcome is logged, and its details from going
    /// stale while it waits.
    requests: Arc<tokio::sync::Mutex<()>>,
}

impl SudoAgent {
    pub fn new(keys: Arc<Mutex<Vec<KeyEntry>>>, prompter: Arc<dyn Prompter>) -> Self {
        Self {
            keys,
            prompter,
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
            "{} ({}), expires in {}",
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
        let entry =
            find(&keys, key_data, keys::now()).ok_or("key expired while waiting for approval")?;
        entry
            .private_key
            .try_sign(data)
            .map_err(|e| format!("signing failed: {e}"))
    }
}

impl Agent<UnixListener> for SudoAgent {
    fn new_session(&mut self, socket: &UnixStream) -> impl Session {
        Connection {
            agent: self.clone(),
            peer: Peer::of(socket),
        }
    }
}

/// One client connection, e.g. `pam_ssh_agent_auth` inside a `sudo` process.
struct Connection {
    agent: SudoAgent,
    peer: Peer,
}

impl Connection {
    fn refuse(&self, reason: &str) -> Result<Signature, AgentError> {
        log!("Refused signature request from {}: {reason}", self.peer);
        Err(AgentError::Failure)
    }
}

#[async_trait]
impl Session for Connection {
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
                comment: k.private_key.comment().into(),
            })
            .collect();

        Ok(valid_identities)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let _turn = self.agent.requests.lock().await;

        let key_data = request.credential.key_data();
        let key = match self.agent.describe(key_data, request.flags) {
            Ok(key) => key,
            Err(reason) => return self.refuse(&reason),
        };

        let message = format!("Signature request from {}\n  key: {key}\nAllow?", self.peer);
        let approved = match self.agent.prompter.confirm(&message).await {
            Ok(approved) => approved,
            // Timed out or the prompt failed: both count as a denial.
            Err(e) => return self.refuse(&format!("not approved: {e}")),
        };
        if !approved {
            return self.refuse("denied");
        }

        match self.agent.sign_with(key_data, &request.data) {
            Ok(signature) => {
                log!("Approved signature request from {}", self.peer);
                Ok(signature)
            }
            Err(reason) => self.refuse(&reason),
        }
    }
}

fn find<'a>(
    keys: &'a [KeyEntry],
    key_data: &KeyData,
    now: std::time::Duration,
) -> Option<&'a KeyEntry> {
    keys.iter()
        .find(|k| !k.is_expired(now) && k.private_key.public_key().key_data() == key_data)
}

/// `ssh-key` signs RSA only with SHA-512, so an RSA request must ask for
/// `rsa-sha2-512`; answering a SHA-1 or SHA-256 request with it would just
/// fail verification on the other end.
fn unsupported(algorithm: Algorithm, flags: u32) -> Option<&'static str> {
    (algorithm.is_rsa() && flags & RSA_SHA2_512 == 0)
        .then_some("RSA signature requested without rsa-sha2-512 (use an Ed25519 key)")
}

/// The process on the other end of the socket, from `SO_PEERCRED` at connect
/// time. Informational only: the command line is whatever that process says.
#[derive(Default)]
struct Peer {
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
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
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
    if command.chars().count() > MAX_COMMAND_CHARS {
        let truncated: String = command.chars().take(MAX_COMMAND_CHARS).collect();
        Some(format!("{}…", sanitize(&truncated)))
    } else {
        Some(sanitize(command))
    }
}

/// Escapes characters that could rewrite or disguise the prompt on a
/// terminal: control characters (including ANSI escape sequences) and
/// invisible or bidirectional-override formatting characters.
fn sanitize(s: &str) -> String {
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
    use crate::prompt::testing::ScriptedPrompter;
    use signature::Verifier;
    use ssh_key::PrivateKey;
    use ssh_key::rand_core::OsRng;
    use std::io;
    use std::time::Duration;

    const CHALLENGE: &[u8] = b"pam_ssh_agent_auth challenge";

    fn entry(comment: &str, ttl: Duration) -> KeyEntry {
        let mut private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        private_key.set_comment(comment);
        KeyEntry {
            private_key,
            expires_at: keys::now() + ttl,
        }
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
            agent: SudoAgent::new(Arc::new(Mutex::new(keys)), prompter),
            peer: Peer::default(),
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
        async fn confirm(&self, _: &str) -> io::Result<bool> {
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
            agent: SudoAgent::new(store, prompter),
            peer: Peer::default(),
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
        async fn confirm(&self, _: &str) -> io::Result<bool> {
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
        let agent = SudoAgent::new(Arc::new(Mutex::new(vec![key])), prompter.clone());
        let mut a = Connection {
            agent: agent.clone(),
            peer: Peer::default(),
        };
        let mut b = Connection {
            agent,
            peer: Peer::default(),
        };

        let (a, b) = tokio::join!(a.sign(first), b.sign(second));
        assert!(a.is_ok() && b.is_ok());
        assert_eq!(
            prompter.max_open.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
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
