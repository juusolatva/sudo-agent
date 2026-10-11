/// Like `eprintln!`, but emits the whole line in a single `write()`. The
/// kernel never interleaves one write to a terminal with another, so a line
/// logged while a prompt is on screen lands whole instead of splitting it.
/// Use it for anything printed while requests are being served.
macro_rules! log {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let line = format!("{}\n", format_args!($($arg)*));
        let _ = std::io::stderr().write_all(line.as_bytes());
    }};
}

mod agent;
mod keys;
mod prompt;
mod server;
mod socket;

use std::io;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::error::ErrorKind;
use clap::{CommandFactory, Parser};
use ssh_agent_lib::error::AgentError;
use ssh_key::HashAlg;
use tokio::signal::unix::{SignalKind, signal};

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
    #[arg(long, value_name = "DURATION", default_value = "15m", value_parser = keys::parse_duration)]
    ttl: Duration,

    /// Longest TTL a key may have; a longer --ttl is an error.
    #[arg(long, value_name = "DURATION", default_value = "8h", value_parser = keys::parse_duration)]
    max_ttl: Duration,

    /// How long an approval prompt waits for an answer before denying.
    #[arg(long, value_name = "DURATION", default_value = "2m", value_parser = keys::parse_duration)]
    approval_timeout: Duration,

    /// Socket path [default: $XDG_RUNTIME_DIR/sudo-agent/agent.sock]
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

/// Drops keys as their TTL runs out, so expired key material doesn't linger
/// in memory.
fn spawn_expiry_reaper(store: Arc<Mutex<Vec<KeyEntry>>>) {
    // A key is unusable from its deadline on (every lookup checks expiry), so
    // removing it a moment later costs nothing. That moment lets an approval
    // prompt for the key be withdrawn first, so this log line doesn't land
    // inside the prompt's line.
    const DELAY: Duration = Duration::from_millis(250);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let now = keys::now().saturating_sub(DELAY);
            for comment in keys::purge_expired(&store, now) {
                log!("Key expired and was removed: {comment}");
            }
        }
    });
}

async fn run(args: Args) -> Result<(), AgentError> {
    let socket_path = match args.socket {
        Some(path) => path,
        None => socket::default_path()?,
    };
    // Bind before asking for passphrases, so a socket problem doesn't waste
    // them. Every return from here on removes the socket file again (via
    // `socket_file`'s drop), except being killed during passphrase entry; the
    // next start cleans that up as a stale socket.
    let (listener, socket_file) = socket::bind(&socket_path)?;

    // One prompter for passphrases now and approvals later, so they share the
    // terminal one prompt at a time.
    let terminal = Arc::new(TerminalPrompter::new(args.approval_timeout));
    let prompter: Arc<dyn Prompter> = terminal.clone();
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
            keys::format_duration(args.ttl)
        );
        loaded.push(entry);
    }

    // Installed only now: during passphrase entry the terminal has echo off,
    // and the default SIGINT action is the safer way out of that.
    let shutdown = shutdown_signal(move || terminal.interrupt())?;

    let store = Arc::new(Mutex::new(loaded));
    spawn_expiry_reaper(Arc::clone(&store));

    println!("Agent listening on {}", socket_path.display());
    println!("export SSH_AUTH_SOCK='{}'", socket_path.display());
    let shutdown = async {
        let signal = shutdown.await;
        // Ctrl-C echoes "^C" with no newline (possibly after a prompt).
        let newline = if signal == "SIGINT" { "\n" } else { "" };
        log!("{newline}Received {signal}, shutting down");
    };
    let agent = SudoAgent::new(Arc::clone(&store), prompter);
    let result = server::serve(listener, agent, shutdown).await;

    // Drop (and so zeroize) the keys now rather than relying on destructors
    // running at exit: main doesn't wait for in-flight tasks.
    store.lock().unwrap().clear();
    drop(socket_file);
    result
}

/// Resolves on the first signal that should stop the agent cleanly: SIGINT
/// (Ctrl-C), SIGTERM, or SIGHUP (its terminal went away).
///
/// Ctrl-C at an open approval prompt only denies that request (`interrupt`
/// returns whether there was one to deny). Pressing it again within
/// [`STOP_WINDOW`] stops the agent anyway, so a stream of requests can't
/// keep it running.
fn shutdown_signal(
    interrupt: impl Fn() -> bool + Send + 'static,
) -> io::Result<impl Future<Output = &'static str>> {
    let mut interrupt_signal = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    Ok(async move {
        // When a Ctrl-C last denied a prompt instead of stopping the agent.
        let mut denied_at: Option<tokio::time::Instant> = None;
        loop {
            tokio::select! {
                _ = interrupt_signal.recv() => {
                    let again = denied_at.is_some_and(|at| at.elapsed() < STOP_WINDOW);
                    if again || !interrupt() {
                        return "SIGINT";
                    }
                    denied_at = Some(tokio::time::Instant::now());
                }
                _ = terminate.recv() => return "SIGTERM",
                _ = hangup.recv() => return "SIGHUP",
            }
        }
    })
}

/// How soon a second Ctrl-C must follow one that denied a prompt to stop the
/// agent anyway.
const STOP_WINDOW: Duration = Duration::from_secs(2);

fn main() -> ExitCode {
    let args = Args::parse();
    if args.ttl > args.max_ttl {
        let message = format!(
            "--ttl {} is longer than --max-ttl {}",
            keys::format_duration(args.ttl),
            keys::format_duration(args.max_ttl)
        );
        Args::command()
            .error(ErrorKind::ArgumentConflict, message)
            .exit();
    }
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("sudo-agent: failed to start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(run(args));
    // An approval prompt may still be blocked reading the terminal; dropping
    // the runtime normally would wait for it, so don't.
    runtime.shutdown_background();

    match result {
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
