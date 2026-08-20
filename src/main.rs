use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use async_trait::async_trait;
use ssh_agent_lib::agent::{Agent, bind_and_listen};
use ssh_agent_lib::proto::identity::Identity;
use ssh_agent_lib::proto::message::Request;
use ssh_key::PublicKey;

struct KeyEntry {
    public_key: PublicKey,
    // Add raw private key bytes / signature handling here
    loaded_at: Instant,
    ttl: Duration,
}

pub struct CustomAgent {
    keys: Arc<Mutex<Vec<KeyEntry>>>,
}

// #[async_trait]
//pub trait ApprovalProvider: Send + Sync {
//    async fn request_approval(&self, server_identity: &str, key_fp: &str) -> Result<bool, Error>;
//}

#[async_trait]
impl Agent for CustomAgent {
    async fn handle(&self, request: Request) -> Result<Request, Box<dyn std::error::Error + Send + Sync>> {
        match request {
            Request::RequestIdentities => {
                let keys = self.keys.lock().unwrap();
                let now = Instant::now();

                // Filter out expired keys automatically
                let valid_identities: Vec<Identity> = keys.iter()
                    .filter(|k| now.duration_since(k.loaded_at) < k.ttl)
                    .map(|k| Identity {
                        pubkey: k.public_key.to_bytes().unwrap(),
                        comment: "custom-agent-key".into(),
                    })
                    .collect();

                Ok(Request::IdentitiesAnswer(valid_identities))
            }
            Request::SignRequest(sign_req) => {
                // Here is where you can intercept signing calls!
                // 1. Check key expiration
                // 2. Trigger desktop notification / approval prompt
                // 3. Sign and return signature
                todo!("Implement signing logic")
            }
            _ => Ok(Request::Failure),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket_path = "/tmp/my_custom_agent.sock";
    let agent = CustomAgent {
        keys: Arc::new(Mutex::new(Vec::new())),
    };

    let mut listener = bind_and_listen(socket_path)?;
    println!("Agent listening on {}", socket_path);

    // Accept incoming socket connections (e.g. from SSH or pam_ssh_agent_auth)
    while let Ok((stream, _)) = listener.accept().await {
        let agent_ref = agent.clone();
        tokio::spawn(async move {
            ssh_agent_lib::agent::run_agent(agent_ref, stream).await;
        });
    }

    Ok(())
}
