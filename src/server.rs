//! Serving the agent on its sockets until shutdown, apart from how the keys
//! got loaded and what stops the process.

use std::future::Future;

use ssh_agent_lib::agent::listen;
use ssh_agent_lib::error::AgentError;
use tokio::net::UnixListener;

use crate::agent::SudoAgent;
use crate::control::ControlAgent;
use crate::keys::TtlPolicy;

/// The agent's listening sockets.
pub struct Listeners {
    /// `agent.sock`, the one forwarded: listing and approval-gated signing
    /// only.
    pub agent: UnixListener,
    /// `control.sock`, never forwarded: also adding and removing keys.
    pub control: UnixListener,
}

/// Serves `agent` on both sockets until accepting fails on either or
/// `shutdown` resolves. Keys added over `control.sock` get their TTL from
/// `ttl`. Connections still being served then are left to the runtime's
/// shutdown.
pub async fn serve(
    listeners: Listeners,
    agent: SudoAgent,
    ttl: TtlPolicy,
    shutdown: impl Future<Output = ()>,
) -> Result<(), AgentError> {
    let control = ControlAgent::new(agent.clone(), ttl);
    tokio::select! {
        result = listen(listeners.agent, agent) => result,
        result = listen(listeners.control, control) => result,
        () = shutdown => Ok(()),
    }
}

/// Socket-level tests: the agent served on a real socket, driven by
/// `ssh-agent-lib`'s client the way `ssh-add` or `pam_ssh_agent_auth` would.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyEntry;
    use crate::keys::testing::entry;
    use crate::prompt::Prompter;
    use crate::prompt::testing::{ApprovesAfter, ScriptedPrompter};
    use crate::socket;
    use signature::Verifier;
    use ssh_agent_lib::agent::Session;
    use ssh_agent_lib::client::Client;
    use ssh_agent_lib::proto::{
        AddIdentity, AddIdentityConstrained, Extension, KeyConstraint, PrivateCredential,
        RemoveIdentity, Request, Response, SignRequest,
    };
    use ssh_key::public::KeyData;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::net::UnixStream;
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;

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
        stop: Option<oneshot::Sender<()>>,
        served: JoinHandle<Result<(), AgentError>>,
    }

    impl Running {
        fn start(keys: Vec<KeyEntry>, prompter: Arc<dyn Prompter>) -> Self {
            Self::with_ttl(keys, prompter, LONG)
        }

        fn with_ttl(keys: Vec<KeyEntry>, prompter: Arc<dyn Prompter>, ttl: TtlPolicy) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("agent.sock");
            let control_path = dir.path().join("control.sock");
            let (agent_listener, agent_file) = socket::bind(&path).unwrap();
            let (control_listener, control_file) = socket::bind(&control_path).unwrap();
            let listeners = Listeners {
                agent: agent_listener,
                control: control_listener,
            };
            let agent = SudoAgent::new(Arc::new(Mutex::new(keys)), prompter);
            let (stop, stopped) = oneshot::channel::<()>();
            let served = tokio::spawn(async move {
                let shutdown = async {
                    let _ = stopped.await;
                };
                let result = serve(listeners, agent, ttl, shutdown).await;
                drop((agent_file, control_file));
                result
            });
            Self {
                _dir: dir,
                path,
                control_path,
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
}
