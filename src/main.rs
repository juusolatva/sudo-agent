use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use async_trait::async_trait;
use ssh_agent_lib::agent::{listen, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::message::Identity;
use ssh_agent_lib::proto::SignRequest;
use ssh_key::{PublicKey, Signature};
#[cfg(unix)]
use tokio::net::UnixListener as Listener;

struct KeyEntry {
    public_key: PublicKey,
    // Add raw private key bytes / signature handling here
    loaded_at: Instant,
    ttl: Duration,
}

#[derive(Clone)]
pub struct CustomAgent {
    keys: Arc<Mutex<Vec<KeyEntry>>>,
}

// `CustomAgent` implements `Session` (and is `Clone`), so `ssh-agent-lib` picks it up
// as an `Agent` automatically: a fresh clone handles each accepted connection.
#[async_trait]
impl Session for CustomAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let keys = self.keys.lock().unwrap();
        let now = Instant::now();

        // Filter out expired keys automatically
        let valid_identities = keys
            .iter()
            .filter(|k| now.duration_since(k.loaded_at) < k.ttl)
            .map(|k| Identity {
                credential: k.public_key.key_data().clone().into(),
                comment: "custom-agent-key".into(),
            })
            .collect();

        Ok(valid_identities)
    }

    async fn sign(&mut self, _sign_request: SignRequest) -> Result<Signature, AgentError> {
        // Here is where you can intercept signing calls!
        // 1. Check key expiration
        // 2. Trigger desktop notification / approval prompt
        // 3. Sign and return signature
        todo!("Implement signing logic")
    }
}

#[tokio::main]
async fn main() -> Result<(), AgentError> {
    let socket_path = "/tmp/sudo_agent.sock";
    let agent = CustomAgent {
        keys: Arc::new(Mutex::new(Vec::new())),
    };

    let _ = std::fs::remove_file(socket_path); // remove stale socket if present

    println!("Agent listening on {}", socket_path);
    listen(Listener::bind(socket_path)?, agent).await?;

    Ok(())
}
