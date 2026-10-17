//! Command line: `sudo-agent serve [OPTIONS]` runs the agent, and the bare
//! form `sudo-agent [OPTIONS]` (how 0.1 was invoked) is an alias for it.

use std::path::PathBuf;
use std::time::Duration;

use clap::error::ErrorKind;
use clap::{Args, CommandFactory, Parser, Subcommand};

use crate::keys;

/// PAM-aware SSH agent for time-bound, human-approved sudo.
#[derive(Parser)]
#[command(version, args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Used when no subcommand is given: the bare form means `serve`.
    #[command(flatten)]
    serve: ServeArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Run the agent (also what `sudo-agent [OPTIONS]` does).
    Serve(ServeArgs),
}

#[derive(Args)]
pub struct ServeArgs {
    /// OpenSSH private key to load at startup (repeatable); its passphrase is
    /// asked for here. Keys can also be added later with ssh-add through the
    /// control socket.
    #[arg(long = "key", value_name = "PATH")]
    pub keys: Vec<PathBuf>,

    /// How long keys stay usable, e.g. 90s, 15m or 8h: those loaded with
    /// --key, and those added with ssh-add without -t.
    #[arg(long, value_name = "DURATION", default_value = "15m", value_parser = keys::parse_duration)]
    pub ttl: Duration,

    /// Longest TTL a key may have: a longer --ttl is an error, a longer
    /// ssh-add -t is cut down to it.
    #[arg(long, value_name = "DURATION", default_value = "8h", value_parser = keys::parse_duration)]
    pub max_ttl: Duration,

    /// How long the terminal prompt waits for an answer before giving up.
    #[arg(long, value_name = "DURATION", default_value = "2m", value_parser = keys::parse_duration)]
    pub approval_timeout: Duration,

    /// Program for approval popups, run for each request while DISPLAY or
    /// WAYLAND_DISPLAY is set.
    #[arg(long, value_name = "PROGRAM", default_value = "pinentry")]
    pub pinentry: PathBuf,

    /// How long a pinentry popup waits for an answer before giving up.
    #[arg(long, value_name = "DURATION", default_value = "60s", value_parser = keys::parse_duration)]
    pub pinentry_timeout: Duration,

    /// Don't show pinentry popups; approve at this terminal only.
    #[arg(long, conflicts_with_all = ["pinentry", "pinentry_timeout"])]
    pub no_pinentry: bool,

    /// Agent socket, the one to forward [env: SUDO_AGENT_SOCKET]
    /// [default: $XDG_RUNTIME_DIR/sudo-agent/agent.sock]
    #[arg(long, alias = "socket", value_name = "PATH")]
    pub agent_socket: Option<PathBuf>,

    /// Control socket, for ssh-add; never forward it
    /// [env: SUDO_AGENT_CONTROL_SOCKET]
    /// [default: $XDG_RUNTIME_DIR/sudo-agent/control.sock]
    #[arg(long, value_name = "PATH")]
    pub control_socket: Option<PathBuf>,
}

/// Parses the command line, exiting with a usage error if it's invalid.
pub fn parse() -> ServeArgs {
    Cli::try_parse()
        .and_then(serve_args)
        .unwrap_or_else(|e| e.exit())
}

fn serve_args(cli: Cli) -> Result<ServeArgs, clap::Error> {
    let args = match cli.command {
        Some(Command::Serve(args)) => args,
        None => cli.serve,
    };
    if args.ttl > args.max_ttl {
        let message = format!(
            "--ttl {} is longer than --max-ttl {}",
            keys::format_duration(args.ttl),
            keys::format_duration(args.max_ttl)
        );
        return Err(Cli::command().error(ErrorKind::ArgumentConflict, message));
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<ServeArgs, clap::Error> {
        Cli::try_parse_from(std::iter::once("sudo-agent").chain(args.iter().copied()))
            .and_then(serve_args)
    }

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn bare_form_and_serve_are_the_same() {
        for args in [
            &["--key", "k", "--ttl", "1h"][..],
            &["serve", "--key", "k", "--ttl", "1h"][..],
        ] {
            let parsed = parse(args).unwrap();
            assert_eq!(parsed.keys, [PathBuf::from("k")], "{args:?}");
            assert_eq!(parsed.ttl, Duration::from_secs(3600), "{args:?}");
            assert_eq!(parsed.max_ttl, Duration::from_secs(8 * 3600), "{args:?}");
        }
    }

    #[test]
    fn socket_is_an_alias_for_agent_socket() {
        for flag in ["--agent-socket", "--socket"] {
            let parsed = parse(&["serve", "--key", "k", flag, "/tmp/a.sock"]).unwrap();
            assert_eq!(parsed.agent_socket, Some(PathBuf::from("/tmp/a.sock")));
        }
    }

    #[test]
    fn keys_are_optional() {
        // Keys can be added later with ssh-add.
        for args in [&[][..], &["serve"][..]] {
            assert!(parse(args).unwrap().keys.is_empty(), "{args:?}");
        }
    }

    #[test]
    fn control_socket_flag() {
        let parsed = parse(&["serve", "--control-socket", "/tmp/c.sock"]).unwrap();
        assert_eq!(parsed.control_socket, Some(PathBuf::from("/tmp/c.sock")));
        assert_eq!(parsed.agent_socket, None);
    }

    #[test]
    fn pinentry_defaults() {
        let parsed = parse(&["serve"]).unwrap();
        assert_eq!(parsed.pinentry, PathBuf::from("pinentry"));
        assert_eq!(parsed.pinentry_timeout, Duration::from_secs(60));
        let parsed = parse(&["--pinentry", "pinentry-qt", "--pinentry-timeout", "30s"]).unwrap();
        assert_eq!(parsed.pinentry, PathBuf::from("pinentry-qt"));
        assert_eq!(parsed.pinentry_timeout, Duration::from_secs(30));
    }

    #[test]
    fn no_pinentry() {
        assert!(!parse(&["serve"]).unwrap().no_pinentry);
        assert!(parse(&["serve", "--no-pinentry"]).unwrap().no_pinentry);
        // Setting up popups that are off is a mistake worth pointing out.
        for other in [["--pinentry", "pinentry-qt"], ["--pinentry-timeout", "30s"]] {
            let args = [&["serve", "--no-pinentry"][..], &other[..]].concat();
            let error = parse(&args).err().unwrap();
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        }
    }

    #[test]
    fn options_before_the_subcommand_are_rejected() {
        // Bare-form options and a subcommand don't mix: which would win?
        assert!(parse(&["--key", "k", "serve", "--key", "k"]).is_err());
    }

    #[test]
    fn ttl_above_the_cap_is_an_error() {
        let error = parse(&["serve", "--key", "k", "--ttl", "9h"])
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        assert!(parse(&["--key", "k", "--ttl", "9h", "--max-ttl", "10h"]).is_ok());
    }
}
