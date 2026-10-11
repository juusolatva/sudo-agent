//! Serving the agent on its socket until shutdown, apart from how the keys
//! got loaded and what stops the process.

use std::future::Future;

use ssh_agent_lib::agent::listen;
use ssh_agent_lib::error::AgentError;
use tokio::net::UnixListener;

use crate::agent::SudoAgent;

/// Serves `agent` on `listener` until accepting fails or `shutdown`
/// resolves. Connections still being served then are left to the runtime's
/// shutdown.
pub async fn serve(
    listener: UnixListener,
    agent: SudoAgent,
    shutdown: impl Future<Output = ()>,
) -> Result<(), AgentError> {
    tokio::select! {
        result = listen(listener, agent) => result,
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

    /// An agent served on a socket in a temporary directory.
    struct Running {
        _dir: tempfile::TempDir,
        path: PathBuf,
        stop: Option<oneshot::Sender<()>>,
        served: JoinHandle<Result<(), AgentError>>,
    }

    impl Running {
        fn start(keys: Vec<KeyEntry>, prompter: Arc<dyn Prompter>) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("agent.sock");
            let (listener, socket_file) = socket::bind(&path).unwrap();
            let agent = SudoAgent::new(Arc::new(Mutex::new(keys)), prompter);
            let (stop, stopped) = oneshot::channel::<()>();
            let served = tokio::spawn(async move {
                let shutdown = async {
                    let _ = stopped.await;
                };
                let result = serve(listener, agent, shutdown).await;
                drop(socket_file);
                result
            });
            Self {
                _dir: dir,
                path,
                stop: Some(stop),
                served,
            }
        }

        async fn client(&self) -> Client<UnixStream> {
            Client::new(UnixStream::connect(&self.path).await.unwrap())
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

    fn sign_request(key: &KeyData) -> SignRequest {
        SignRequest {
            credential: key.clone().into(),
            data: CHALLENGE.to_vec(),
            flags: 0,
        }
    }

    #[tokio::test]
    async fn lists_loaded_keys() {
        let key = entry("laptop", Duration::from_secs(60));
        let public = public(&key);
        let running = Running::start(vec![key], Arc::new(ScriptedPrompter::default()));

        let identities = running.client().await.request_identities().await.unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].credential.key_data(), &public);
        assert_eq!(identities[0].comment, "laptop");
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
}
