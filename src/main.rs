mod keys;
#[expect(dead_code, reason = "confirm() is wired into sign() in the next step")]
mod prompt;
mod socket;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use clap::Parser;
use ssh_agent_lib::agent::{Session, listen};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::SignRequest;
use ssh_agent_lib::proto::message::Identity;
use ssh_key::{HashAlg, Signature};

use crate::keys::KeyEntry;
use crate::prompt::TerminalPrompter;

/// PAM-aware SSH agent for time-bound, human-approved sudo.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// OpenSSH private key to load (repeatable). Its passphrase is asked for
    /// once, at startup.
    #[arg(long = "key", value_name = "PATH", required = true)]
    keys: Vec<PathBuf>,

    /// How long loaded keys stay usable, e.g. 90s, 15m or 8h.
    #[arg(long, value_name = "DURATION", default_value = "15m", value_parser = keys::parse_ttl)]
    ttl: Duration,

    /// Socket path [default: $XDG_RUNTIME_DIR/sudo-agent/agent.sock]
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
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

    async fn sign(&mut self, _sign_request: SignRequest) -> Result<Signature, AgentError> {
        // Here is where you can intercept signing calls!
        // 1. Check key expiration
        // 2. Trigger desktop notification / approval prompt
        // 3. Sign and return signature
        todo!("Implement signing logic")
    }
}

/// Drops keys as their TTL runs out, so expired key material doesn't linger
/// in memory.
fn spawn_expiry_reaper(store: Arc<Mutex<Vec<KeyEntry>>>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            for comment in keys::purge_expired(&store, keys::now()) {
                eprintln!("Key expired and was removed: {comment}");
            }
        }
    });
}

async fn run(args: Args) -> Result<(), AgentError> {
    let socket_path = match args.socket {
        Some(path) => path,
        None => socket::default_path()?,
    };
    // Bind before asking for passphrases, so a socket problem doesn't waste them.
    let listener = socket::bind(&socket_path)?;

    let prompter = TerminalPrompter::default();
    let mut loaded: Vec<KeyEntry> = Vec::new();
    for path in &args.keys {
        let entry = keys::load(path, args.ttl, &prompter).await?;
        let public_key = entry.private_key.public_key();
        if loaded
            .iter()
            .any(|k| k.private_key.public_key().key_data() == public_key.key_data())
        {
            eprintln!("warning: {} is already loaded, skipping", path.display());
            continue;
        }
        eprintln!(
            "Loaded {} ({}), usable for {}",
            path.display(),
            public_key.fingerprint(HashAlg::Sha256),
            keys::format_ttl(args.ttl)
        );
        loaded.push(entry);
    }

    let store = Arc::new(Mutex::new(loaded));
    spawn_expiry_reaper(Arc::clone(&store));

    println!("Agent listening on {}", socket_path.display());
    println!("export SSH_AUTH_SOCK='{}'", socket_path.display());
    listen(listener, CustomAgent { keys: store }).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            match e {
                // Our own startup errors already carry context; skip the "Agent: I/O error" prefix.
                AgentError::IO(e) => eprintln!("sudo-agent: {e}"),
                e => eprintln!("sudo-agent: {e}"),
            }
            ExitCode::FAILURE
        }
    }
}
