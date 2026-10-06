mod agent;
mod keys;
mod prompt;
mod socket;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use ssh_agent_lib::agent::listen;
use ssh_agent_lib::error::AgentError;
use ssh_key::HashAlg;

use crate::agent::SudoAgent;
use crate::keys::KeyEntry;
use crate::prompt::{Prompter, TerminalPrompter};

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

    // One prompter for passphrases now and approvals later, so they share the
    // terminal one prompt at a time.
    let prompter: Arc<dyn Prompter> = Arc::new(TerminalPrompter::default());
    let mut loaded: Vec<KeyEntry> = Vec::new();
    for path in &args.keys {
        let entry = keys::load(path, args.ttl, prompter.as_ref()).await?;
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
    listen(listener, SudoAgent::new(store, prompter)).await?;

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
