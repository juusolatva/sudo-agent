//! Serving the agent on its sockets until shutdown, apart from how the keys
//! got loaded and what stops the process.

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use ssh_agent_lib::agent::{Agent, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Request, Response};
use ssh_agent_lib::ssh_encoding::{Decode, Encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::agent::SudoAgent;
use crate::control::ControlAgent;

/// The agent's listening sockets.
pub struct Listeners {
    /// `agent.sock`, the one forwarded: listing and approval-gated signing
    /// only.
    pub agent: UnixListener,
    /// `control.sock`, never forwarded: also adding and removing keys, and
    /// `sudo-agent approve`.
    pub control: UnixListener,
}

/// What one socket allows its clients, so a hostile one can't use up the
/// daemon's memory or descriptors.
#[derive(Clone, Copy)]
struct Limits {
    /// Connections served at once; the next one waits in the listen backlog.
    connections: usize,
    /// Largest request frame (OpenSSH's own agent limit); a bigger length
    /// ends the connection before anything is buffered.
    frame: u32,
    /// How long a client may stay silent between requests; `None` for the
    /// trusted local sockets that legitimately idle.
    idle: Option<Duration>,
    /// How long the rest of a frame may take once its length has arrived.
    body: Duration,
}

/// `agent.sock` is reachable by forwarding, so it gets tight limits.
const AGENT_LIMITS: Limits = Limits {
    connections: 64,
    frame: 256 * 1024,
    idle: Some(Duration::from_secs(60)),
    body: Duration::from_secs(10),
};

/// `control.sock` only takes our own uid (see `control.rs`); a client may
/// idle, but not hold unlimited descriptors.
const CONTROL_LIMITS: Limits = Limits {
    idle: None,
    connections: 32,
    ..AGENT_LIMITS
};

/// Serves `agent` on `agent.sock` and `control` (the same agent's control
/// side) on `control.sock`, until accepting fails fatally on either or
/// `shutdown` resolves. Connections still being served then are left to the
/// runtime's shutdown.
pub async fn serve(
    listeners: Listeners,
    agent: SudoAgent,
    control: ControlAgent,
    shutdown: impl Future<Output = ()>,
) -> Result<(), AgentError> {
    tokio::select! {
        result = listen(listeners.agent, agent, AGENT_LIMITS) => result,
        result = listen(listeners.control, control, CONTROL_LIMITS) => result,
        () = shutdown => Ok(()),
    }
}

/// Accepts connections and serves each on its own task, within `limits`.
/// Running out of descriptors (or memory) is waited out rather than ending
/// the agent.
async fn listen(
    socket: UnixListener,
    mut agent: impl Agent<UnixListener>,
    limits: Limits,
) -> Result<(), AgentError> {
    let slots = Arc::new(Semaphore::new(limits.connections));
    let mut starved = false;
    loop {
        let slot = Arc::clone(&slots)
            .acquire_owned()
            .await
            .expect("the semaphore is never closed");
        match socket.accept().await {
            Ok((stream, _)) => {
                starved = false;
                let session = agent.new_session(&stream);
                tokio::spawn(async move {
                    if let Err(e) = serve_connection(session, stream, limits).await {
                        log!("Connection ended: {e}");
                    }
                    drop(slot);
                });
            }
            Err(e) if transient(&e) => {
                if !starved {
                    log!("Cannot accept connections for now ({e}); retrying");
                    starved = true;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => return Err(AgentError::IO(e)),
        }
    }
}

/// An `accept()` failure that passes: the connection went away already, or
/// the process is out of descriptors or memory.
fn transient(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(
            libc::EMFILE
                | libc::ENFILE
                | libc::ENOBUFS
                | libc::ENOMEM
                | libc::ECONNABORTED
                | libc::EINTR
                | libc::EPROTO
        )
    ) || e.kind() == io::ErrorKind::ConnectionAborted
}

fn timed_out(what: &str) -> AgentError {
    AgentError::IO(io::Error::new(io::ErrorKind::TimedOut, what.to_string()))
}

/// Reads one request frame: `Ok(None)` when the client hung up between
/// frames.
async fn read_request(
    stream: &mut UnixStream,
    limits: &Limits,
) -> Result<Option<Request>, AgentError> {
    let mut header = [0u8; 4];
    let first = async {
        match stream.read_exact(&mut header).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
            Err(e) => Err(e),
        }
    };
    let arrived = match limits.idle {
        Some(idle) => timeout(idle, first)
            .await
            .map_err(|_| timed_out("idle connection"))??,
        None => first.await?,
    };
    if !arrived {
        return Ok(None);
    }
    let length = u32::from_be_bytes(header);
    if length > limits.frame {
        return Err(AgentError::IO(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "request of {length} bytes is over the {} limit",
                limits.frame
            ),
        )));
    }
    // Grown as bytes arrive, not reserved up front.
    let mut body = Vec::new();
    timeout(
        limits.body,
        stream.take(u64::from(length)).read_to_end(&mut body),
    )
    .await
    .map_err(|_| timed_out("incomplete request"))??;
    if body.len() != length as usize {
        return Err(AgentError::IO(io::ErrorKind::UnexpectedEof.into()));
    }
    Ok(Some(Request::decode(&mut body.as_slice())?))
}

/// Answers requests on `stream` until the client leaves or breaks a limit.
async fn serve_connection(
    mut session: impl Session,
    mut stream: UnixStream,
    limits: Limits,
) -> Result<(), AgentError> {
    while let Some(request) = read_request(&mut stream, &limits).await? {
        let response = match session.handle(request).await {
            Ok(response) => response,
            Err(AgentError::ExtensionFailure) => Response::ExtensionFailure,
            Err(_) => Response::Failure,
        };
        let mut frame = Vec::new();
        let length = response
            .encoded_len()
            .map_err(ssh_agent_lib::proto::ProtoError::SshEncoding)?;
        (length as u32)
            .encode(&mut frame)
            .map_err(ssh_agent_lib::proto::ProtoError::SshEncoding)?;
        response
            .encode(&mut frame)
            .map_err(ssh_agent_lib::proto::ProtoError::SshEncoding)?;
        stream.write_all(&frame).await?;
    }
    Ok(())
}

/// Socket-level tests: the agent served on a real socket, driven by
/// `ssh-agent-lib`'s client the way `ssh-add` or `pam_ssh_agent_auth` would.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::approve::{self, ApproveClients, Event, Reply};
    use crate::approver;
    use crate::keys::testing::entry;
    use crate::keys::{KeyEntry, TtlPolicy};
    use crate::prompt::Prompter;
    use crate::prompt::testing::{ApprovesAfter, ScriptedPrompter};
    use crate::routing::Router;
    use crate::socket;
    use signature::Verifier;
    use ssh_agent_lib::agent::Session;
    use ssh_agent_lib::client::Client;
    use ssh_agent_lib::proto::{
        AddIdentity, AddIdentityConstrained, AddSmartcardKeyConstrained, Extension, KeyConstraint,
        PrivateCredential, PrivateKeyData, RemoveIdentity, Request, Response, SignRequest,
        SmartcardKey,
    };
    use ssh_key::public::KeyData;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    const CHALLENGE: &[u8] = b"pam_ssh_agent_auth challenge";

    /// A TTL policy for tests that don't look at TTLs.
    const LONG: TtlPolicy = TtlPolicy {
        default: Duration::from_secs(15 * 60),
        max: Duration::from_secs(8 * 3600),
    };

    /// An agent served on both sockets in a temporary directory.
    struct Running {
        _dir: tempfile::TempDir,
        path: PathBuf,
        control_path: PathBuf,
        /// The `sudo-agent approve` backend clients of `control.sock` attach
        /// to; in the routing only with [`Running::with_approve`].
        approve: Arc<ApproveClients>,
        stop: Option<oneshot::Sender<()>>,
        served: JoinHandle<Result<(), AgentError>>,
    }

    impl Running {
        fn start(keys: Vec<KeyEntry>, prompter: Arc<dyn Prompter>) -> Self {
            Self::with_ttl(keys, prompter, LONG)
        }

        fn with_ttl(keys: Vec<KeyEntry>, prompter: Arc<dyn Prompter>, ttl: TtlPolicy) -> Self {
            let approve = Arc::new(ApproveClients::new(Duration::from_secs(60)));
            Self::launch(keys, Router::only(prompter), approve, ttl)
        }

        /// Approvals go to `sudo-agent approve` clients, which wait up to
        /// `timeout`, and to `others` at the same time.
        fn with_approve(
            keys: Vec<KeyEntry>,
            others: Vec<(&'static str, Arc<dyn Prompter>)>,
            timeout: Duration,
        ) -> Self {
            Self::with_approve_in(tempfile::tempdir().unwrap(), keys, others, timeout)
        }

        fn with_approve_in(
            dir: tempfile::TempDir,
            keys: Vec<KeyEntry>,
            others: Vec<(&'static str, Arc<dyn Prompter>)>,
            timeout: Duration,
        ) -> Self {
            let approve = Arc::new(ApproveClients::new(timeout));
            let mut backends = others;
            backends.push(("approve", Arc::clone(&approve) as Arc<dyn Prompter>));
            Self::launch_in(dir, keys, Router::new(backends), approve, LONG)
        }

        fn launch(
            keys: Vec<KeyEntry>,
            router: Router,
            approve: Arc<ApproveClients>,
            ttl: TtlPolicy,
        ) -> Self {
            Self::launch_in(tempfile::tempdir().unwrap(), keys, router, approve, ttl)
        }

        fn launch_in(
            dir: tempfile::TempDir,
            keys: Vec<KeyEntry>,
            router: Router,
            approve: Arc<ApproveClients>,
            ttl: TtlPolicy,
        ) -> Self {
            let path = dir.path().join("agent.sock");
            let control_path = dir.path().join("control.sock");
            let (agent_listener, agent_file) = socket::bind(&path).unwrap();
            let (control_listener, control_file) = socket::bind(&control_path).unwrap();
            let listeners = Listeners {
                agent: agent_listener,
                control: control_listener,
            };
            let agent = SudoAgent::new(Arc::new(Mutex::new(keys)), router);
            let control = ControlAgent::new(agent.clone(), ttl, Arc::clone(&approve));
            let (stop, stopped) = oneshot::channel::<()>();
            let served = tokio::spawn(async move {
                let shutdown = async {
                    let _ = stopped.await;
                };
                let result = serve(listeners, agent, control, shutdown).await;
                drop((agent_file, control_file));
                result
            });
            Self {
                _dir: dir,
                path,
                control_path,
                approve,
                stop: Some(stop),
                served,
            }
        }

        /// A client of `agent.sock`.
        async fn client(&self) -> Client<UnixStream> {
            Client::new(UnixStream::connect(&self.path).await.unwrap())
        }

        /// A client of `control.sock`.
        async fn control(&self) -> Client<UnixStream> {
            Client::new(UnixStream::connect(&self.control_path).await.unwrap())
        }

        /// Comments of the keys listed on `agent.sock`, without the time
        /// left.
        async fn listed(&self) -> Vec<String> {
            let identities = self.client().await.request_identities().await.unwrap();
            identities
                .into_iter()
                .map(|i| match i.comment.rsplit_once(" (") {
                    Some((comment, left)) if left.ends_with(" left)") => comment.to_owned(),
                    _ => panic!("no time left in {:?}", i.comment),
                })
                .collect()
        }

        /// Stops serving; the temporary directory stays until `self` drops.
        async fn stop(&mut self) -> Result<(), AgentError> {
            self.stop.take().unwrap().send(()).unwrap();
            (&mut self.served).await.unwrap()
        }
    }

    /// `sudo-agent approve`'s wait: the connection's next approval event.
    fn approve_wait() -> Request {
        Request::Extension(Extension {
            name: approve::WAIT.into(),
            details: Vec::new().into(),
        })
    }

    fn approve_answer(id: u64, approved: bool) -> Request {
        Request::Extension(Extension::new_message(Reply { id, approved }).unwrap())
    }

    /// `future`'s result, failing the test rather than hanging it if it
    /// doesn't come (e.g. a hang-up isn't noticed).
    async fn within<T>(future: impl Future<Output = T>) -> T {
        let limit = Duration::from_secs(5);
        tokio::time::timeout(limit, future)
            .await
            .expect("timed out")
    }

    /// The next approval event for `client`, attaching it first if it isn't
    /// yet.
    async fn next_event(client: &mut Client<UnixStream>) -> Event {
        match within(client.handle(approve_wait())).await.unwrap() {
            Response::ExtensionResponse(extension) => extension.parse_message().unwrap().unwrap(),
            other => panic!("expected an approval event, got {other:?}"),
        }
    }

    /// A client's wait for its next event, in the background.
    type Waiting = JoinHandle<(Client<UnixStream>, Event)>;

    fn wait_for_event(mut client: Client<UnixStream>) -> Waiting {
        tokio::spawn(async move {
            let event = next_event(&mut client).await;
            (client, event)
        })
    }

    fn pending_id(event: &Event) -> u64 {
        match event {
            Event::Pending { id, .. } => *id,
            other => panic!("expected a pending request, got {other:?}"),
        }
    }

    async fn until(condition: impl Fn() -> bool) {
        within(async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await;
    }

    impl Running {
        /// Attaches a `sudo-agent approve` client over `control.sock`, and
        /// returns its first wait.
        async fn attach(&self) -> Waiting {
            let before = self.approve.attached();
            let waiting = wait_for_event(self.control().await);
            until(|| self.approve.attached() > before).await;
            waiting
        }

        /// Answers request `id` the way `sudo-agent approve` does, over a
        /// connection of its own.
        async fn answer(&self, id: u64, approved: bool) -> Response {
            let mut control = self.control().await;
            within(control.handle(approve_answer(id, approved)))
                .await
                .unwrap()
        }

        /// A signature request on `agent.sock`, in the background.
        fn sign_in_background(&self, key: &KeyData) -> JoinHandle<Response> {
            let (path, request) = (self.path.clone(), sign_request(key));
            tokio::spawn(async move {
                let mut client = Client::new(UnixStream::connect(path).await.unwrap());
                within(client.handle(Request::SignRequest(request)))
                    .await
                    .unwrap()
            })
        }
    }

    fn public(entry: &KeyEntry) -> KeyData {
        entry.private_key.public_key().key_data().clone()
    }

    /// What `ssh-add` sends for `entry`, with `constraints` (`-t`, `-c`, `-h`).
    fn add_request(entry: &KeyEntry, constraints: Vec<KeyConstraint>) -> Request {
        let identity = AddIdentity {
            credential: PrivateCredential::Key {
                privkey: entry.private_key.key_data().clone(),
                comment: entry.private_key.comment().to_owned(),
            },
        };
        if constraints.is_empty() {
            Request::AddIdentity(identity)
        } else {
            Request::AddIdConstrained(AddIdentityConstrained {
                identity,
                constraints,
            })
        }
    }

    fn sign_request(key: &KeyData) -> SignRequest {
        SignRequest {
            credential: key.clone().into(),
            data: CHALLENGE.to_vec(),
            flags: 0,
        }
    }

    #[tokio::test]
    async fn lists_loaded_keys() {
        let key = entry("laptop", Duration::from_secs(3600 + 30));
        let public = public(&key);
        let running = Running::start(vec![key], Arc::new(ScriptedPrompter::default()));

        let identities = running.client().await.request_identities().await.unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].credential.key_data(), &public);
        assert_eq!(identities[0].comment, "laptop (1h00m left)");
    }

    /// `ssh-add -l` shows the time left, on a server through the forwarded
    /// `agent.sock` as well as locally on `control.sock`.
    #[tokio::test]
    async fn listed_comments_show_time_left_on_both_sockets() {
        // Above an hour only minutes are shown, which leaves 30 s of slack.
        let keys = vec![
            entry("one", Duration::from_secs(3600 + 5 * 60 + 30)),
            entry("eight", Duration::from_secs(8 * 3600 + 30)),
        ];
        let running = Running::start(keys, Arc::new(ScriptedPrompter::default()));

        for mut client in [running.client().await, running.control().await] {
            let comments: Vec<_> = client
                .request_identities()
                .await
                .unwrap()
                .into_iter()
                .map(|i| i.comment)
                .collect();
            assert_eq!(comments, ["one (1h05m left)", "eight (8h00m left)"]);
        }
    }

    #[tokio::test]
    async fn approved_request_is_signed() {
        let key = entry("laptop", Duration::from_secs(60));
        let public = public(&key);
        let prompter = Arc::new(ScriptedPrompter::with_confirms([true]));
        let running = Running::start(vec![key], prompter.clone());

        let signature = running
            .client()
            .await
            .sign(sign_request(&public))
            .await
            .unwrap();
        public.verify(CHALLENGE, &signature).unwrap();
        assert_eq!(prompter.asked().len(), 1);
    }

    #[tokio::test]
    async fn refusal_keeps_the_connection_usable() {
        let key = entry("laptop", Duration::from_secs(60));
        let public = public(&key);
        let running = Running::start(
            vec![key],
            Arc::new(ScriptedPrompter::with_confirms([false])),
        );
        let mut client = running.client().await;

        let response = client
            .handle(Request::SignRequest(sign_request(&public)))
            .await;
        assert!(matches!(response, Ok(Response::Failure)));
        assert_eq!(client.request_identities().await.unwrap().len(), 1);
    }

    /// Everything a forwarded socket must not allow: managing keys, locking,
    /// and (for now) any extension, `session-bind@openssh.com` included.
    #[tokio::test]
    async fn agent_socket_refuses_key_management() {
        let loaded = entry("loaded", Duration::from_secs(60));
        let loaded_public = public(&loaded);
        let other = entry("other", Duration::from_secs(60));
        let add = AddIdentity {
            credential: PrivateCredential::Key {
                privkey: other.private_key.key_data().clone(),
                comment: "other".into(),
            },
        };
        let prompter = Arc::new(ScriptedPrompter::with_confirms([true]));
        let running = Running::start(vec![loaded], prompter.clone());
        let mut client = running.client().await;

        let requests = [
            ("add", Request::AddIdentity(add.clone())),
            (
                "add constrained",
                Request::AddIdConstrained(AddIdentityConstrained {
                    identity: add,
                    constraints: vec![KeyConstraint::Lifetime(60)],
                }),
            ),
            (
                "remove",
                Request::RemoveIdentity(RemoveIdentity {
                    credential: loaded_public.clone().into(),
                }),
            ),
            ("remove all", Request::RemoveAllIdentities),
            ("lock", Request::Lock("secret".into())),
            ("unlock", Request::Unlock("secret".into())),
            (
                "extension",
                Request::Extension(Extension {
                    name: "session-bind@openssh.com".into(),
                    details: Vec::new().into(),
                }),
            ),
        ];
        for (name, request) in requests {
            let response = client.handle(request).await;
            assert!(
                matches!(response, Ok(Response::Failure)),
                "{name} should be refused, got {response:?}"
            );
        }

        let identities = client.request_identities().await.unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].credential.key_data(), &loaded_public);
        assert!(prompter.asked().is_empty());
    }

    #[tokio::test]
    async fn client_hanging_up_withdraws_the_prompt() {
        let key = entry("laptop", Duration::from_secs(60));
        let public = public(&key);
        let prompter = Arc::new(ApprovesAfter::new(Duration::from_secs(60)));
        let running = Running::start(vec![key], prompter.clone());
        let mut client = running.client().await;

        let request = sign_request(&public);
        let signing = tokio::spawn(async move { client.sign(request).await });
        prompter.until_asked(1).await;
        signing.abort(); // drops the client, closing its connection

        tokio::time::timeout(Duration::from_secs(5), async {
            while prompter.times_cancelled() == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("prompt withdrawn");
    }

    #[tokio::test]
    async fn shutdown_stops_serving_and_removes_the_socket() {
        let mut running = Running::start(Vec::new(), Arc::new(ScriptedPrompter::default()));
        let path = running.path.clone();
        assert!(
            running
                .client()
                .await
                .request_identities()
                .await
                .unwrap()
                .is_empty()
        );

        running.stop().await.unwrap();
        assert!(!path.exists());
        assert!(UnixStream::connect(&path).await.is_err());
    }

    #[tokio::test]
    async fn shutdown_removes_the_control_socket_too() {
        let mut running = Running::start(Vec::new(), Arc::new(ScriptedPrompter::default()));
        let path = running.control_path.clone();
        assert!(path.exists());
        running.stop().await.unwrap();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn key_added_over_control_is_served_on_the_agent_socket() {
        let key = entry("laptop", Duration::ZERO);
        let public = public(&key);
        let prompter = Arc::new(ScriptedPrompter::with_confirms([true, true]));
        let running = Running::start(Vec::new(), prompter.clone());
        let mut control = running.control().await;

        let response = control.handle(add_request(&key, vec![])).await;
        assert!(matches!(response, Ok(Response::Success)));
        assert_eq!(running.listed().await, ["laptop"]);

        // Signing works on both sockets, approval-gated on both.
        let signature = running
            .client()
            .await
            .sign(sign_request(&public))
            .await
            .unwrap();
        public.verify(CHALLENGE, &signature).unwrap();
        let signature = control.sign(sign_request(&public)).await.unwrap();
        public.verify(CHALLENGE, &signature).unwrap();
        assert_eq!(prompter.asked().len(), 2);
    }

    #[tokio::test]
    async fn lifetime_sets_the_ttl() {
        let short = TtlPolicy {
            default: Duration::from_millis(300),
            max: Duration::from_secs(3600),
        };
        let running = Running::with_ttl(Vec::new(), Arc::new(ScriptedPrompter::default()), short);
        let key = entry("one-second", Duration::ZERO);
        let add = add_request(&key, vec![KeyConstraint::Lifetime(1)]);
        assert!(matches!(
            running.control().await.handle(add).await,
            Ok(Response::Success)
        ));

        // Past the default, within the lifetime.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(running.listed().await, ["one-second"]);
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(running.listed().await.is_empty());
    }

    #[tokio::test]
    async fn lifetime_above_the_cap_is_cut_down() {
        let capped = TtlPolicy {
            default: Duration::from_millis(100),
            max: Duration::from_millis(300),
        };
        let running = Running::with_ttl(Vec::new(), Arc::new(ScriptedPrompter::default()), capped);
        let key = entry("asked-for-an-hour", Duration::ZERO);
        let add = add_request(&key, vec![KeyConstraint::Lifetime(3600)]);
        assert!(matches!(
            running.control().await.handle(add).await,
            Ok(Response::Success)
        ));

        assert_eq!(running.listed().await.len(), 1);
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(running.listed().await.is_empty());
    }

    #[tokio::test]
    async fn no_lifetime_or_zero_gets_the_default() {
        let short = TtlPolicy {
            default: Duration::from_millis(300),
            max: Duration::from_secs(3600),
        };
        let running = Running::with_ttl(Vec::new(), Arc::new(ScriptedPrompter::default()), short);
        let mut control = running.control().await;
        let plain = entry("plain", Duration::ZERO);
        let zero = entry("zero", Duration::ZERO);
        let add_plain = add_request(&plain, vec![]);
        let add_zero = add_request(&zero, vec![KeyConstraint::Lifetime(0)]);
        assert!(matches!(
            control.handle(add_plain).await,
            Ok(Response::Success)
        ));
        assert!(matches!(
            control.handle(add_zero).await,
            Ok(Response::Success)
        ));

        assert_eq!(running.listed().await.len(), 2);
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(running.listed().await.is_empty());
    }

    #[tokio::test]
    async fn re_adding_a_key_replaces_it_and_restarts_its_ttl() {
        let short = TtlPolicy {
            default: Duration::from_millis(300),
            max: Duration::from_secs(3600),
        };
        let running = Running::with_ttl(Vec::new(), Arc::new(ScriptedPrompter::default()), short);
        let mut control = running.control().await;
        let mut key = entry("first", Duration::ZERO);
        assert!(matches!(
            control.handle(add_request(&key, vec![])).await,
            Ok(Response::Success)
        ));

        tokio::time::sleep(Duration::from_millis(200)).await;
        key.private_key.set_comment("second");
        assert!(matches!(
            control.handle(add_request(&key, vec![])).await,
            Ok(Response::Success)
        ));
        // One entry, not two.
        assert_eq!(running.listed().await, ["second"]);

        // The first TTL would have run out by now.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(running.listed().await, ["second"]);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(running.listed().await.is_empty());
    }

    #[tokio::test]
    async fn confirm_constraint_is_accepted_restrictions_are_not() {
        let running = Running::start(Vec::new(), Arc::new(ScriptedPrompter::default()));
        let mut control = running.control().await;
        let extension = |name: &str| {
            KeyConstraint::Extension(Extension {
                name: name.into(),
                details: Vec::new().into(),
            })
        };

        let confirmed = entry("confirmed", Duration::ZERO);
        let add = add_request(&confirmed, vec![KeyConstraint::Confirm]);
        assert!(matches!(control.handle(add).await, Ok(Response::Success)));

        for name in [
            "restrict-destination-v00@openssh.com",
            "something@example.com",
        ] {
            let restricted = entry("restricted", Duration::ZERO);
            let add = add_request(
                &restricted,
                vec![KeyConstraint::Lifetime(60), extension(name)],
            );
            let response = control.handle(add).await;
            assert!(
                matches!(response, Ok(Response::Failure)),
                "{name}: {response:?}"
            );
        }
        assert_eq!(running.listed().await, ["confirmed"]);
    }

    #[tokio::test]
    async fn remove_and_remove_all() {
        let one = entry("one", Duration::from_secs(60));
        let one_public = public(&one);
        let two = entry("two", Duration::from_secs(60));
        let running = Running::start(vec![one, two], Arc::new(ScriptedPrompter::default()));
        let mut control = running.control().await;
        let remove = || {
            Request::RemoveIdentity(RemoveIdentity {
                credential: one_public.clone().into(),
            })
        };

        assert!(matches!(
            control.handle(remove()).await,
            Ok(Response::Success)
        ));
        assert_eq!(running.listed().await, ["two"]);
        // Removing a key that isn't loaded fails, as with OpenSSH's agent.
        assert!(matches!(
            control.handle(remove()).await,
            Ok(Response::Failure)
        ));
        let remove_all = control.handle(Request::RemoveAllIdentities).await;
        assert!(matches!(remove_all, Ok(Response::Success)));
        assert!(running.listed().await.is_empty());
    }

    #[tokio::test]
    async fn control_does_not_lock_yet() {
        let running = Running::start(Vec::new(), Arc::new(ScriptedPrompter::default()));
        let mut control = running.control().await;
        for request in [Request::Lock("pw".into()), Request::Unlock("pw".into())] {
            assert!(matches!(
                control.handle(request).await,
                Ok(Response::Failure)
            ));
        }
    }

    #[tokio::test]
    async fn certificates_are_refused() {
        let running = Running::start(Vec::new(), Arc::new(ScriptedPrompter::default()));
        let mut control = running.control().await;
        let key = entry("certified", Duration::ZERO);
        let ca = entry("ca", Duration::ZERO);
        let mut builder =
            ssh_key::certificate::Builder::new(vec![0; 16], public(&key), 0, i64::MAX as u64)
                .unwrap();
        builder.all_principals_valid().unwrap();
        let certificate = builder.sign(&ca.private_key).unwrap();

        let add = Request::AddIdentity(AddIdentity {
            credential: PrivateCredential::Cert {
                algorithm: key.private_key.algorithm(),
                certificate: Box::new(certificate),
                privkey: PrivateKeyData::Ed25519(
                    key.private_key.key_data().ed25519().unwrap().clone(),
                ),
                comment: "certified".into(),
            },
        });
        let response = control.handle(add).await;
        assert!(matches!(response, Ok(Response::Failure)), "{response:?}");
        assert!(running.listed().await.is_empty());
    }

    #[tokio::test]
    async fn smartcard_keys_are_refused() {
        let running = Running::start(Vec::new(), Arc::new(ScriptedPrompter::default()));
        let mut control = running.control().await;
        let card = || SmartcardKey {
            id: "/usr/lib64/opensc-pkcs11.so".into(),
            pin: "123456".to_owned().into(),
        };
        for request in [
            Request::AddSmartcardKey(card()),
            Request::AddSmartcardKeyConstrained(AddSmartcardKeyConstrained {
                key: card(),
                constraints: vec![KeyConstraint::Lifetime(60)],
            }),
            Request::RemoveSmartcardKey(card()),
        ] {
            let response = control.handle(request).await;
            assert!(matches!(response, Ok(Response::Failure)), "{response:?}");
        }
        assert!(running.listed().await.is_empty());
    }

    /// What `ssh` sends before forwarding a connection (or using it for a
    /// login): from then on the connection gets nothing.
    #[tokio::test]
    async fn session_bind_refuses_the_control_connection_for_good() {
        let loaded = entry("loaded", Duration::from_secs(60));
        let loaded_public = public(&loaded);
        let prompter = Arc::new(ScriptedPrompter::with_confirms([true]));
        let running = Running::start(vec![loaded], prompter.clone());
        let mut forwarded = running.control().await;

        let bind = Request::Extension(Extension {
            name: "session-bind@openssh.com".into(),
            details: Vec::new().into(),
        });
        assert!(matches!(
            forwarded.handle(bind).await,
            Ok(Response::Failure)
        ));

        let other = entry("other", Duration::ZERO);
        let requests = [
            ("list", Request::RequestIdentities),
            ("sign", Request::SignRequest(sign_request(&loaded_public))),
            ("add", add_request(&other, vec![])),
            ("remove all", Request::RemoveAllIdentities),
        ];
        for (name, request) in requests {
            let response = forwarded.handle(request).await;
            assert!(
                matches!(response, Ok(Response::Failure)),
                "{name} should be refused, got {response:?}"
            );
        }
        assert_eq!(running.listed().await, ["loaded"]);
        assert!(prompter.asked().is_empty());

        // Other connections are unaffected.
        let add = add_request(&other, vec![]);
        assert!(matches!(
            running.control().await.handle(add).await,
            Ok(Response::Success)
        ));
    }

    const MINUTE: Duration = Duration::from_secs(60);

    #[tokio::test]
    async fn approve_clients_answer_and_the_rest_are_withdrawn() {
        for approved in [true, false] {
            let key = entry("laptop", Duration::from_secs(600));
            let public = public(&key);
            let popup = Arc::new(ApprovesAfter::new(MINUTE));
            let running = Running::with_approve(vec![key], vec![("popup", popup.clone())], MINUTE);
            let (one, two) = (running.attach().await, running.attach().await);
            let signing = running.sign_in_background(&public);

            // Both clients are shown the same request.
            let (mut one, first) = one.await.unwrap();
            let (mut two, second) = two.await.unwrap();
            assert_eq!(pending_id(&first), pending_id(&second));
            let Event::Pending {
                id,
                closes_in,
                message,
            } = first
            else {
                unreachable!()
            };
            assert!(
                message.starts_with("Signature request from pid "),
                "{message}"
            );
            assert!(message.contains("\n  key: laptop (SHA256:"), "{message}");
            assert!(closes_in > MINUTE - Duration::from_secs(5) && closes_in <= MINUTE);

            assert!(matches!(
                running.answer(id, approved).await,
                Response::Success
            ));
            match signing.await.unwrap() {
                Response::SignResponse(_) if approved => {}
                Response::Failure if !approved => {}
                other => panic!("approved {approved}, got {other:?}"),
            }
            // The popup and both clients are withdrawn.
            assert_eq!(popup.times_cancelled(), 1);
            for client in [&mut one, &mut two] {
                let Event::Withdrawn { id: gone, reason } = next_event(client).await else {
                    panic!("not withdrawn");
                };
                assert_eq!(gone, id);
                assert!(
                    reason.starts_with("answered by approve client pid "),
                    "{reason}"
                );
            }
            // Already answered.
            assert!(matches!(running.answer(id, true).await, Response::Failure));
        }
    }

    /// The withdrawal comes while the client isn't waiting, so it is queued
    /// for its next wait.
    #[tokio::test]
    async fn another_backend_answering_withdraws_the_request_from_clients() {
        let key = entry("laptop", Duration::from_secs(600));
        let public = public(&key);
        let popup = Arc::new(ApprovesAfter::new(Duration::from_millis(50)));
        let running = Running::with_approve(vec![key], vec![("popup", popup)], MINUTE);
        let waiting = running.attach().await;
        let signing = running.sign_in_background(&public);

        let (mut client, event) = waiting.await.unwrap();
        let id = pending_id(&event);
        assert!(matches!(signing.await.unwrap(), Response::SignResponse(_)));
        let withdrawn = Event::Withdrawn {
            id,
            reason: approve::WITHDRAWN.into(),
        };
        assert_eq!(next_event(&mut client).await, withdrawn);
        assert!(matches!(running.answer(id, true).await, Response::Failure));
    }

    #[tokio::test]
    async fn without_an_attached_client_requests_are_refused_at_once() {
        let key = entry("laptop", Duration::from_secs(600));
        let public = public(&key);
        let running = Running::with_approve(vec![key], vec![], MINUTE);
        let signing = running.sign_in_background(&public);
        let response = tokio::time::timeout(Duration::from_secs(5), signing).await;
        assert!(matches!(response.unwrap().unwrap(), Response::Failure));
    }

    #[tokio::test]
    async fn a_client_attaching_later_is_shown_the_request_in_flight() {
        let key = entry("laptop", Duration::from_secs(600));
        let public = public(&key);
        let running = Running::with_approve(vec![key], vec![], MINUTE);
        let early = running.attach().await;
        let signing = running.sign_in_background(&public);
        let (_early, event) = early.await.unwrap();
        let id = pending_id(&event);

        let (_late, late_event) = wait_for_event(running.control().await).await.unwrap();
        assert_eq!(pending_id(&late_event), id);
        assert!(matches!(running.answer(id, true).await, Response::Success));
        assert!(matches!(signing.await.unwrap(), Response::SignResponse(_)));
    }

    #[tokio::test]
    async fn a_timed_out_request_is_withdrawn_with_the_reason() {
        let key = entry("laptop", Duration::from_secs(600));
        let public = public(&key);
        let running = Running::with_approve(vec![key], vec![], Duration::from_millis(200));
        let waiting = running.attach().await;
        let signing = running.sign_in_background(&public);
        let (mut client, event) = waiting.await.unwrap();
        let id = pending_id(&event);

        assert!(matches!(signing.await.unwrap(), Response::Failure));
        let Event::Withdrawn { id: gone, reason } = next_event(&mut client).await else {
            panic!("not withdrawn");
        };
        assert_eq!(gone, id);
        assert!(reason.starts_with("no answer within "), "{reason}");
        assert!(matches!(running.answer(id, true).await, Response::Failure));

        // Hanging up between waits detaches it.
        drop(client);
        until(|| running.approve.attached() == 0).await;
    }

    /// The session is busy in the wait then, so this is the socket watch,
    /// not the protocol loop seeing EOF.
    #[tokio::test]
    async fn a_client_hanging_up_while_waiting_detaches() {
        let running = Running::with_approve(vec![], vec![], MINUTE);
        let waiting = running.attach().await;
        waiting.abort();
        until(|| running.approve.attached() == 0).await;
    }

    /// Through forwarding, a server must not be able to approve anything.
    #[tokio::test]
    async fn agent_socket_refuses_the_approve_extensions() {
        let key = entry("laptop", Duration::from_secs(600));
        let public = public(&key);
        let running = Running::with_approve(vec![key], vec![], MINUTE);
        let mut forwarded = running.client().await;
        assert!(matches!(
            forwarded.handle(approve_wait()).await.unwrap(),
            Response::Failure
        ));
        assert_eq!(running.approve.attached(), 0);

        let waiting = running.attach().await;
        let signing = running.sign_in_background(&public);
        let (_client, event) = waiting.await.unwrap();
        let id = pending_id(&event);
        assert!(matches!(
            forwarded.handle(approve_answer(id, true)).await.unwrap(),
            Response::Failure
        ));
        // Still pending: denying it over control.sock works.
        assert!(matches!(running.answer(id, false).await, Response::Success));
        assert!(matches!(signing.await.unwrap(), Response::Failure));
    }

    fn session_bind() -> Request {
        Request::Extension(Extension {
            name: "session-bind@openssh.com".into(),
            details: Vec::new().into(),
        })
    }

    /// An accidental `ForwardAgent …/control.sock`: once `ssh` binds the
    /// connection it is refused for good, so it can neither see nor answer
    /// requests.
    #[tokio::test]
    async fn a_connection_refused_for_session_bind_cannot_approve() {
        let key = entry("laptop", Duration::from_secs(600));
        let public = public(&key);
        let running = Running::with_approve(vec![key], vec![], MINUTE);
        let waiting = running.attach().await;
        let signing = running.sign_in_background(&public);
        let (_client, event) = waiting.await.unwrap();
        let id = pending_id(&event);

        let mut forwarded = running.control().await;
        for request in [session_bind(), approve_answer(id, true), approve_wait()] {
            let response = within(forwarded.handle(request)).await.unwrap();
            assert!(matches!(response, Response::Failure), "{response:?}");
        }
        assert_eq!(running.approve.attached(), 1);
        // Still pending: denying it over a clean connection works.
        assert!(matches!(running.answer(id, false).await, Response::Success));
        assert!(matches!(signing.await.unwrap(), Response::Failure));
    }

    /// At once rather than when the connection closes, or `approve` would
    /// still count as available.
    #[tokio::test]
    async fn session_bind_detaches_an_attached_connection() {
        let key = entry("laptop", Duration::from_secs(600));
        let public = public(&key);
        let running = Running::with_approve(vec![key], vec![], MINUTE);
        let waiting = running.attach().await;
        let signing = running.sign_in_background(&public);
        let (mut client, event) = waiting.await.unwrap();

        let response = within(client.handle(session_bind())).await.unwrap();
        assert!(matches!(response, Response::Failure));
        assert_eq!(running.approve.attached(), 0);
        let id = pending_id(&event);
        assert!(matches!(running.answer(id, true).await, Response::Success));
        assert!(matches!(signing.await.unwrap(), Response::SignResponse(_)));
    }

    #[tokio::test]
    async fn malformed_and_unknown_answers_fail() {
        let running = Running::with_approve(vec![], vec![], MINUTE);
        let mut control = running.control().await;
        let malformed = Request::Extension(Extension {
            name: approve::ANSWER.into(),
            details: vec![0, 0].into(),
        });
        assert!(matches!(
            control.handle(malformed).await.unwrap(),
            Response::Failure
        ));
        assert!(matches!(running.answer(42, true).await, Response::Failure));
    }

    /// `sudo-agent approve` on `running`'s control socket, answering with
    /// `prompter`, until the returned sender fires.
    fn approver(
        running: &Running,
        prompter: Arc<dyn Prompter>,
    ) -> (JoinHandle<std::io::Result<()>>, oneshot::Sender<()>) {
        let (stop, stopped) = oneshot::channel::<()>();
        let path = running.control_path.clone();
        let shutdown = async {
            let _ = stopped.await;
        };
        let attending = tokio::spawn(approver::attend(path, prompter, shutdown));
        (attending, stop)
    }

    #[tokio::test]
    async fn approve_client_shows_requests_and_answers_them() {
        let key = entry("laptop", Duration::from_secs(600));
        let public = public(&key);
        let running = Running::with_approve(vec![key], vec![], MINUTE);
        let prompter = Arc::new(ScriptedPrompter::with_confirms([true, false]));
        let (attending, stop) = approver(&running, prompter.clone());
        until(|| running.approve.attached() == 1).await;

        assert!(matches!(
            running.sign_in_background(&public).await.unwrap(),
            Response::SignResponse(_)
        ));
        assert!(matches!(
            running.sign_in_background(&public).await.unwrap(),
            Response::Failure
        ));
        let asked = prompter.asked();
        assert_eq!(asked.len(), 2);
        assert!(asked[0].contains("key: laptop"), "{asked:?}");
        assert!(asked[0].contains("Allow? (closes in 1m00s)"), "{asked:?}");

        stop.send(()).unwrap();
        within(attending).await.unwrap().unwrap();
        until(|| running.approve.attached() == 0).await;
    }

    #[tokio::test]
    async fn approve_client_drops_a_prompt_answered_elsewhere() {
        let key = entry("laptop", Duration::from_secs(600));
        let public = public(&key);
        let popup: Arc<dyn Prompter> = Arc::new(ApprovesAfter::new(Duration::from_millis(50)));
        let running = Running::with_approve(vec![key], vec![("popup", popup)], MINUTE);
        let prompter = Arc::new(ApprovesAfter::new(MINUTE));
        let (_attending, _stop) = approver(&running, prompter.clone());
        until(|| running.approve.attached() == 1).await;

        assert!(matches!(
            running.sign_in_background(&public).await.unwrap(),
            Response::SignResponse(_)
        ));
        until(|| prompter.times_cancelled() == 1).await;
        assert_eq!(prompter.times_asked(), 1);
    }

    #[tokio::test]
    async fn approve_client_attaches_again_after_the_agent_restarts() {
        // The agent before the restart: it takes the client's connection,
        // then exits (hangs up), leaving its socket file behind.
        let dir = tempfile::tempdir().unwrap();
        let control_path = dir.path().join("control.sock");
        let old = tokio::net::UnixListener::bind(&control_path).unwrap();
        let prompter = Arc::new(ScriptedPrompter::with_confirms([true]));
        let shutdown = std::future::pending();
        let attending = tokio::spawn(approver::attend(control_path, prompter.clone(), shutdown));
        drop(within(old.accept()).await.unwrap());
        drop(old);

        let key = entry("laptop", Duration::from_secs(600));
        let public = public(&key);
        let running = Running::with_approve_in(dir, vec![key], vec![], MINUTE);
        until(|| running.approve.attached() == 1).await;
        assert!(matches!(
            running.sign_in_background(&public).await.unwrap(),
            Response::SignResponse(_)
        ));
        assert_eq!(prompter.asked().len(), 1);
        attending.abort();
    }

    #[tokio::test]
    async fn approve_client_withdraws_its_prompt_when_stopped() {
        let key = entry("laptop", Duration::from_secs(600));
        let public = public(&key);
        let running = Running::with_approve(vec![key], vec![], MINUTE);
        let prompter = Arc::new(ApprovesAfter::new(MINUTE));
        let (attending, stop) = approver(&running, prompter.clone());
        until(|| running.approve.attached() == 1).await;
        let signing = running.sign_in_background(&public);
        until(|| prompter.times_asked() == 1).await;

        stop.send(()).unwrap();
        within(attending).await.unwrap().unwrap();
        assert_eq!(prompter.times_cancelled(), 1);
        signing.abort();
    }

    #[tokio::test]
    async fn approve_client_fails_without_an_agent_that_takes_it() {
        let running = Running::with_approve(vec![], vec![], MINUTE);
        let prompter: Arc<dyn Prompter> = Arc::new(ScriptedPrompter::default());
        // `agent.sock` refuses approvals.
        let refused = approver::attend(
            running.path.clone(),
            prompter.clone(),
            std::future::pending(),
        );
        let e = within(refused).await.unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}");
        let missing = running.path.with_file_name("missing.sock");
        let e = approver::attend(missing, prompter, std::future::pending())
            .await
            .unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
    }

    /// A bare `agent.sock` served within `limits`.
    fn limited(limits: Limits) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let (listener, file) = socket::bind(&path).unwrap();
        let agent = SudoAgent::new(
            Arc::new(Mutex::new(vec![entry("k", LONG.default)])),
            Router::only(Arc::new(ScriptedPrompter::with_confirms([]))),
        );
        tokio::spawn(async move {
            let _file = file;
            let _ = listen(listener, agent, limits).await;
        });
        (dir, path)
    }

    const SMALL: Limits = Limits {
        connections: 2,
        frame: 1024,
        idle: Some(Duration::from_millis(200)),
        body: Duration::from_millis(200),
    };

    /// True once the daemon has closed `stream`.
    async fn closed(stream: &mut UnixStream) -> bool {
        let mut byte = [0u8; 1];
        matches!(
            timeout(Duration::from_secs(2), stream.read(&mut byte)).await,
            Ok(Ok(0) | Err(_))
        )
    }

    #[tokio::test]
    async fn oversized_frame_is_refused_before_buffering() {
        let (_dir, path) = limited(SMALL);
        let mut stream = UnixStream::connect(&path).await.unwrap();
        stream.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        assert!(closed(&mut stream).await);
    }

    #[tokio::test]
    async fn unfinished_frame_times_out() {
        let (_dir, path) = limited(SMALL);
        let mut stream = UnixStream::connect(&path).await.unwrap();
        stream.write_all(&[0, 0, 0, 100, 11]).await.unwrap();
        assert!(closed(&mut stream).await);
    }

    #[tokio::test]
    async fn idle_connection_times_out_and_frees_its_slot() {
        let (_dir, path) = limited(SMALL);
        let mut idle = vec![
            UnixStream::connect(&path).await.unwrap(),
            UnixStream::connect(&path).await.unwrap(),
        ];
        // Both slots are taken, so this one is not served until one frees.
        let mut third = Client::new(UnixStream::connect(&path).await.unwrap());
        for stream in &mut idle {
            assert!(closed(stream).await);
        }
        let listed = timeout(Duration::from_secs(2), third.request_identities())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(listed.len(), 1);
    }
}
