mod socket;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ssh_agent_lib::agent::{Session, listen};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::SignRequest;
use ssh_agent_lib::proto::message::Identity;
use ssh_key::{PrivateKey, Signature};

struct KeyEntry {
    /// Decrypted at load time; `ssh-key` zeroizes the key material on drop.
    private_key: PrivateKey,
    loaded_at: Instant,
    ttl: Duration,
}

#[derive(Clone)]
pub struct CustomAgent {
    keys: Arc<Mutex<Vec<KeyEntry>>>,
}

// 'CustomAgent' implements 'Session' (and is 'Clone'), so 'ssh-agent-lib' picks it up
// as an 'Agent' automatically: a fresh clone handles each accepted connection.
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
                credential: k.private_key.public_key().key_data().clone().into(),
                comment: k.private_key.comment().into(),
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

/// Parses `--socket <path>`, the only argument supported so far.
fn socket_override() -> Result<Option<PathBuf>, AgentError> {
    let mut args = std::env::args_os().skip(1);
    let mut socket = None;
    while let Some(arg) = args.next() {
        if arg == "--socket" {
            let path = args.next().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "--socket needs a path")
            })?;
            socket = Some(PathBuf::from(path));
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unknown argument: {}", arg.to_string_lossy()),
            )
            .into());
        }
    }
    Ok(socket)
}

#[tokio::main]
async fn main() -> Result<(), AgentError> {
    let socket_path = match socket_override()? {
        Some(path) => path,
        None => socket::default_path()?,
    };
    let agent = CustomAgent {
        keys: Arc::new(Mutex::new(Vec::new())),
    };

    let listener = socket::bind(&socket_path)?;
    println!("Agent listening on {}", socket_path.display());
    println!("export SSH_AUTH_SOCK='{}'", socket_path.display());
    listen(listener, agent).await?;

    Ok(())
}
