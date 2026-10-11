//! The control socket (`control.sock`): what `agent.sock` serves, plus adding
//! and removing keys (`ssh-add`). It must never be usable through SSH agent
//! forwarding, where a server could add keys (or, later, answer approvals),
//! so every connection is checked three ways; see [`refusal`] and
//! [`ControlConnection::extension`].

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use ssh_agent_lib::agent::{Agent, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{
    AddIdentity, AddIdentityConstrained, AddSmartcardKeyConstrained, Extension, Identity,
    KeyConstraint, PrivateCredential, RemoveIdentity, SignRequest, SmartcardKey,
};
use ssh_key::{HashAlg, PrivateKey, Signature};
use tokio::net::{UnixListener, UnixStream};

use crate::agent::{Connection, SudoAgent, sanitize};
use crate::keys::{self, KeyEntry, TtlPolicy};

/// Sent by OpenSSH (≥ 8.9) on every agent connection it uses for a login or
/// forwards to a server.
const SESSION_BIND: &str = "session-bind@openssh.com";

/// The `ssh-add -h` (destination restriction) key constraint.
const RESTRICT_DESTINATION: &str = "restrict-destination-v00@openssh.com";

/// [`listen`](ssh_agent_lib::agent::listen) asks it for a [`ControlConnection`]
/// per accepted socket.
pub struct ControlAgent {
    agent: SudoAgent,
    ttl: TtlPolicy,
}

impl ControlAgent {
    pub fn new(agent: SudoAgent, ttl: TtlPolicy) -> Self {
        Self { agent, ttl }
    }
}

impl Agent<UnixListener> for ControlAgent {
    fn new_session(&mut self, socket: &UnixStream) -> impl Session {
        let inner = Connection::new(self.agent.clone(), socket);
        let refused = match socket.peer_cred() {
            Ok(cred) => {
                let exe = cred
                    .pid()
                    .and_then(|pid| std::fs::read_link(format!("/proc/{pid}/exe")).ok());
                // SAFETY: geteuid has no preconditions and can't fail.
                let own_uid = unsafe { libc::geteuid() };
                refusal(Some(cred.uid()), own_uid, exe.as_deref())
            }
            Err(_) => refusal(None, 0, None),
        };
        if let Some(reason) = &refused {
            log!("Refused control connection from {}: {reason}", inner.peer());
        }
        ControlConnection {
            inner,
            ttl: self.ttl,
            refused,
        }
    }
}

/// Why a control connection is refused, if it is: the peer must be this
/// agent's own user, and must not be `ssh` itself (which is what talks to
/// the socket when it is forwarded, or used for a login). The `ssh` check
/// goes by executable name, so it is a tripwire; the `session-bind` check
/// in [`ControlConnection::extension`] is the protocol-level one.
fn refusal(peer_uid: Option<u32>, own_uid: u32, peer_exe: Option<&Path>) -> Option<String> {
    match peer_uid {
        None => return Some("can't tell which user is connecting".into()),
        Some(uid) if uid != own_uid => {
            return Some(format!("uid {uid} isn't this agent's user ({own_uid})"));
        }
        Some(_) => {}
    }
    if peer_exe
        .and_then(Path::file_name)
        .is_some_and(|name| name == "ssh")
    {
        return Some(
            "it comes from ssh; control.sock must never be forwarded or used for logins".into(),
        );
    }
    None
}

/// One client of `control.sock`, e.g. `ssh-add`. Once refused, every request
/// on the connection fails.
pub struct ControlConnection {
    inner: Connection,
    ttl: TtlPolicy,
    refused: Option<String>,
}

impl ControlConnection {
    fn check(&self) -> Result<(), AgentError> {
        match self.refused {
            Some(_) => Err(AgentError::Failure),
            None => Ok(()),
        }
    }

    fn unsupported(&self, what: &str) -> Result<(), AgentError> {
        log!("Refused {what} from {}: not supported", self.inner.peer());
        Err(AgentError::Failure)
    }

    fn refuse_key(&self, comment: &str, reason: &str) -> Result<(), AgentError> {
        log!(
            "Refused to add key {} from {}: {reason}",
            sanitize(comment),
            self.inner.peer()
        );
        Err(AgentError::Failure)
    }

    /// Adds a key from `ssh-add`, with its TTL from the requested lifetime
    /// (`-t`) under the [`TtlPolicy`]. `-c` is accepted: every signature is
    /// confirmed anyway. Any other constraint, `-h` in particular, refuses
    /// the key: silently ignoring a restriction asked for would be worse.
    fn add(
        &self,
        credential: PrivateCredential,
        constraints: &[KeyConstraint],
    ) -> Result<(), AgentError> {
        let (privkey, comment) = match credential {
            PrivateCredential::Key { privkey, comment } => (privkey, comment),
            PrivateCredential::Cert { comment, .. } => {
                return self.refuse_key(&comment, "certificates aren't supported");
            }
        };
        let mut lifetime = None;
        for constraint in constraints {
            match constraint {
                KeyConstraint::Lifetime(seconds) => {
                    lifetime = Some(Duration::from_secs(u64::from(*seconds)));
                }
                KeyConstraint::Confirm => {}
                KeyConstraint::Extension(Extension { name, .. })
                    if name == RESTRICT_DESTINATION =>
                {
                    return self.refuse_key(
                        &comment,
                        "destination restrictions (ssh-add -h) aren't supported",
                    );
                }
                KeyConstraint::Extension(Extension { name, .. }) => {
                    let reason = format!("unsupported constraint {}", sanitize(name));
                    return self.refuse_key(&comment, &reason);
                }
            }
        }
        let private_key = match PrivateKey::new(privkey, comment.clone()) {
            Ok(key) => key,
            Err(e) => return self.refuse_key(&comment, &format!("unusable key: {e}")),
        };

        let (ttl, capped) = self.ttl.ttl(lifetime);
        let description = format!(
            "{} ({})",
            sanitize(private_key.comment()),
            private_key.fingerprint(HashAlg::Sha256)
        );
        let replaced = self.inner.agent().add(KeyEntry {
            private_key,
            expires_at: keys::now() + ttl,
        });
        let action = if replaced { "Replaced" } else { "Added" };
        let cap = match (capped, lifetime) {
            (true, Some(asked)) => format!(
                " (lifetime {} capped to {})",
                keys::format_duration(asked),
                keys::format_duration(ttl)
            ),
            _ => String::new(),
        };
        log!(
            "{action} key {description} from {}, usable for {}{cap}",
            self.inner.peer(),
            keys::format_duration(ttl)
        );
        Ok(())
    }
}

#[async_trait]
impl Session for ControlConnection {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        self.check()?;
        self.inner.request_identities().await
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        self.check()?;
        self.inner.sign(request).await
    }

    async fn add_identity(&mut self, identity: AddIdentity) -> Result<(), AgentError> {
        self.check()?;
        self.add(identity.credential, &[])
    }

    async fn add_identity_constrained(
        &mut self,
        identity: AddIdentityConstrained,
    ) -> Result<(), AgentError> {
        self.check()?;
        self.add(identity.identity.credential, &identity.constraints)
    }

    async fn remove_identity(&mut self, identity: RemoveIdentity) -> Result<(), AgentError> {
        self.check()?;
        let key_data = identity.credential.key_data();
        match self.inner.agent().remove(key_data) {
            Some(comment) => {
                log!(
                    "Removed key {} ({}) for {}",
                    sanitize(&comment),
                    key_data.fingerprint(HashAlg::Sha256),
                    self.inner.peer()
                );
                Ok(())
            }
            None => Err(AgentError::Failure),
        }
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        self.check()?;
        let count = self.inner.agent().remove_all();
        log!("Removed all keys ({count}) for {}", self.inner.peer());
        Ok(())
    }

    async fn lock(&mut self, _: String) -> Result<(), AgentError> {
        self.check()?;
        self.unsupported("locking")
    }

    async fn unlock(&mut self, _: String) -> Result<(), AgentError> {
        self.check()?;
        self.unsupported("unlocking")
    }

    async fn add_smartcard_key(&mut self, _: SmartcardKey) -> Result<(), AgentError> {
        self.check()?;
        self.unsupported("adding a smartcard key")
    }

    async fn add_smartcard_key_constrained(
        &mut self,
        _: AddSmartcardKeyConstrained,
    ) -> Result<(), AgentError> {
        self.check()?;
        self.unsupported("adding a smartcard key")
    }

    async fn remove_smartcard_key(&mut self, _: SmartcardKey) -> Result<(), AgentError> {
        self.check()?;
        self.unsupported("removing a smartcard key")
    }

    /// `session-bind@openssh.com` means the connection came through `ssh`:
    /// refuse it, and everything after it, for good. Other extensions aren't
    /// supported yet.
    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        if extension.name == SESSION_BIND && self.refused.is_none() {
            let reason = "it came through ssh (session-bind); control.sock must never be \
                          forwarded or used for logins";
            log!(
                "Refused control connection from {}: {reason}",
                self.inner.peer()
            );
            self.refused = Some(reason.into());
        }
        Err(AgentError::Failure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn only_the_same_user_and_not_ssh() {
        let me = 1000;
        let exe = |path: &str| Some(PathBuf::from(path));
        let refused = |uid, exe: Option<PathBuf>| refusal(uid, me, exe.as_deref()).is_some();

        assert!(!refused(Some(me), exe("/usr/bin/ssh-add")));
        assert!(!refused(Some(me), exe("/home/me/bin/sudo-agent")));
        assert!(!refused(Some(me), None)); // exe unreadable: the tripwire can't fire
        assert!(refused(Some(1001), exe("/usr/bin/ssh-add")));
        assert!(refused(Some(0), exe("/usr/bin/ssh-add")));
        assert!(refused(None, exe("/usr/bin/ssh-add")));
        assert!(refused(Some(me), exe("/usr/bin/ssh")));
        assert!(refused(Some(me), exe("/opt/openssh/bin/ssh")));
    }
}
