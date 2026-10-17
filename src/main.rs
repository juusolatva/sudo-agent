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
mod cli;
mod control;
mod keys;
#[allow(dead_code)] // Not used for approvals until step 2c.
mod pinentry;
mod prompt;
mod routing;
mod server;
mod socket;

use std::env;
use std::io;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ssh_agent_lib::error::AgentError;
use ssh_key::HashAlg;
use tokio::signal::unix::{SignalKind, signal};

use crate::agent::SudoAgent;
use crate::cli::ServeArgs;
use crate::keys::{KeyEntry, TtlPolicy};
use crate::prompt::{Prompter, TerminalPrompter};
use crate::routing::Router;
use crate::server::Listeners;

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

async fn run(args: ServeArgs) -> Result<(), AgentError> {
    let agent_path = socket::choose_path(
        args.agent_socket,
        env::var_os(socket::AGENT_SOCKET_ENV),
        || socket::default_path("agent"),
    )?;
    let control_path = socket::choose_path(
        args.control_socket,
        env::var_os(socket::CONTROL_SOCKET_ENV),
        || socket::default_path("control"),
    )?;
    if agent_path == control_path {
        let message = format!(
            "the agent and control sockets must differ, both are {}",
            agent_path.display()
        );
        return Err(io::Error::new(io::ErrorKind::InvalidInput, message).into());
    }
    // Bind before asking for passphrases, so a socket problem doesn't waste
    // them. Every return from here on removes the socket files again (via
    // the `SocketFile`s' drop), except being killed during passphrase entry;
    // the next start cleans that up as stale sockets. Binding refuses while
    // another agent answers on either path: one instance per user.
    let (agent_listener, agent_file) = socket::bind(&agent_path)?;
    let (control_listener, control_file) = socket::bind(&control_path)?;

    // Passphrases now and approvals later share the terminal, one prompt at a
    // time.
    let terminal = Arc::new(TerminalPrompter::new(args.approval_timeout));
    let mut loaded: Vec<KeyEntry> = Vec::new();
    for path in &args.keys {
        let entry = keys::load(path, args.ttl, terminal.as_ref()).await?;
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
    let shutdown = shutdown_signal({
        let terminal = Arc::clone(&terminal);
        move || terminal.interrupt()
    })?;
    let approvals: Arc<dyn Prompter> =
        Arc::new(Router::new([("terminal", terminal as Arc<dyn Prompter>)]));

    let store = Arc::new(Mutex::new(loaded));
    spawn_expiry_reaper(Arc::clone(&store));

    println!("Agent listening on {}", agent_path.display());
    println!(
        "Control socket on {} (for ssh-add; never forward it)",
        control_path.display()
    );
    if args.keys.is_empty() {
        println!(
            "No keys loaded yet; add one with: SSH_AUTH_SOCK='{}' ssh-add <key>",
            control_path.display()
        );
    }
    println!("export SSH_AUTH_SOCK='{}'", agent_path.display());
    let shutdown = async {
        let signal = shutdown.await;
        // Ctrl-C echoes "^C" with no newline (possibly after a prompt).
        let newline = if signal == "SIGINT" { "\n" } else { "" };
        log!("{newline}Received {signal}, shutting down");
    };
    let agent = SudoAgent::new(Arc::clone(&store), approvals);
    let listeners = Listeners {
        agent: agent_listener,
        control: control_listener,
    };
    let ttl = TtlPolicy {
        default: args.ttl,
        max: args.max_ttl,
    };
    let result = server::serve(listeners, agent, ttl, shutdown).await;

    // Drop (and so zeroize) the keys now rather than relying on destructors
    // running at exit: main doesn't wait for in-flight tasks.
    store.lock().unwrap().clear();
    drop(agent_file);
    drop(control_file);
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
    let args = cli::parse();
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
