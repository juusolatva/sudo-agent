//! Approvals in a pinentry popup: one `pinentry` process per request, spoken
//! to over its Assuan protocol on stdin/stdout. Only `CONFIRM` (Allow / Deny)
//! is used; pinentry never asks for a passphrase here.

use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{self, ErrorKind};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::agent::sanitize;
use crate::keys;
use crate::prompt::Prompter;

/// Assuan's limit on a line, newline included.
const MAX_LINE: usize = 1000;

/// How long pinentry may take to start, and to acknowledge each setting.
const SETUP_WAIT: Duration = Duration::from_secs(5);

/// How long past its own timeout pinentry may take to answer `CONFIRM`.
const GRACE: Duration = Duration::from_secs(5);

/// How long a withdrawn pinentry gets to exit after SIGTERM before SIGKILL.
const TERM_WAIT: Duration = Duration::from_secs(1);

// libgpg-error codes: the low 16 bits of the number in an `ERR` reply.
const GPG_ERR_TIMEOUT: u32 = 62;
/// Deny, Escape or closing the window. The only code that is a denial:
/// others (e.g. "Not confirmed" from a `pinentry-tty` with no terminal) mean
/// pinentry failed, which isn't an answer.
const GPG_ERR_CANCELED: u32 = 99;

/// Asks for approval in a pinentry popup, started anew for each request.
pub struct Pinentry {
    program: OsString,
    args: Vec<OsString>,
    /// How long the popup waits for an answer (pinentry's own `SETTIMEOUT`).
    timeout: Duration,
    grace: Duration,
    /// Whether there was a display for a popup at startup.
    display: bool,
}

impl Pinentry {
    pub fn new(program: impl Into<OsString>, timeout: Duration) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            timeout,
            grace: GRACE,
            display: has_display(
                env::var_os("DISPLAY").as_deref(),
                env::var_os("WAYLAND_DISPLAY").as_deref(),
            ),
        }
    }

    fn spawn(&self) -> io::Result<Child> {
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Its messages would land in the middle of the terminal prompt.
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let parent = std::process::id();
        // SAFETY: the closure only makes async-signal-safe calls (setsid,
        // prctl, getppid), as required between fork and exec.
        unsafe {
            command.pre_exec(move || {
                // Its own session, without a controlling terminal: a curses or
                // tty pinentry fails instead of taking `serve`'s terminal, and
                // Ctrl-C there doesn't reach it.
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                // Killed if the agent dies without withdrawing it. This follows
                // the thread that forks, a runtime worker that lives as long as
                // the agent.
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                    return Err(io::Error::last_os_error());
                }
                // The agent may have died before that took effect.
                if libc::getppid() as u32 != parent {
                    return Err(io::Error::other("the agent exited"));
                }
                Ok(())
            });
        }
        command.spawn().map_err(|e| {
            let program = Path::new(&self.program).display();
            let hint = match e.kind() {
                ErrorKind::NotFound => "; install pinentry, or name one with --pinentry",
                _ => "",
            };
            io::Error::new(e.kind(), format!("can't start {program}: {e}{hint}"))
        })
    }

    async fn ask(&self, session: &mut Session, message: &str) -> io::Result<bool> {
        session.expect_ok("start").await?;
        let description = escape(message, MAX_LINE - "SETDESC \n".len());
        // pinentry reads 0 as "no timeout".
        let timeout = self.timeout.as_secs().max(1);
        for command in [
            "SETTITLE sudo-agent".to_owned(),
            format!("SETDESC {description}"),
            "SETOK Allow".to_owned(),
            "SETCANCEL Deny".to_owned(),
            format!("SETTIMEOUT {timeout}"),
        ] {
            session.send(&command).await?;
            let name = command.split(' ').next().unwrap_or_default();
            session.expect_ok(name).await?;
        }
        session.send("CONFIRM").await?;
        // Its own timeout ends the popup; this one only covers a pinentry
        // that hangs.
        match session.reply(self.timeout + self.grace).await? {
            Reply::Ok => Ok(true),
            Reply::Err(code, _) if code & 0xFFFF == GPG_ERR_CANCELED => Ok(false),
            Reply::Err(code, _) if code & 0xFFFF == GPG_ERR_TIMEOUT => Err(io::Error::new(
                ErrorKind::TimedOut,
                format!("no answer within {}", keys::format_duration(self.timeout)),
            )),
            Reply::Err(_, text) => Err(io::Error::other(format!(
                "pinentry failed: {}; if it's a terminal pinentry, name a graphical one \
                 with --pinentry",
                sanitize(&text)
            ))),
        }
    }
}

/// Whether a graphical pinentry could show a popup: `DISPLAY` or
/// `WAYLAND_DISPLAY` is set. That says nothing about anyone looking (after
/// logout, behind a lock screen), which routing tolerates: a popup that fails
/// or times out is no answer, not a denial.
fn has_display(display: Option<&OsStr>, wayland_display: Option<&OsStr>) -> bool {
    [display, wayland_display]
        .into_iter()
        .any(|value| value.is_some_and(|value| !value.is_empty()))
}

#[async_trait]
impl Prompter for Pinentry {
    async fn passphrase(&self, _: &str) -> io::Result<Zeroizing<String>> {
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "pinentry only asks for approvals",
        ))
    }

    fn available(&self) -> bool {
        self.display
    }

    async fn confirm(&self, message: &str, cancel: &CancellationToken) -> io::Result<bool> {
        if cancel.is_cancelled() {
            return Err(io::Error::other("cancelled"));
        }
        let mut child = self.spawn()?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            stop(&mut child).await;
            return Err(io::Error::other("pinentry has no pipes"));
        };
        let mut session = Session {
            stdin,
            stdout: BufReader::new(stdout),
        };
        let result = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(io::Error::other("cancelled")),
            answer = self.ask(&mut session, message) => answer,
        };
        drop(session);
        // Returns once pinentry is gone, so the popup is too.
        stop(&mut child).await;
        result
    }
}

/// Ends `child` and reaps it: SIGTERM first, so a GUI pinentry can close its
/// window, then SIGKILL if it hasn't exited within [`TERM_WAIT`].
async fn stop(child: &mut Child) {
    if let Some(pid) = child.id() {
        // SAFETY: plain kill(2). `pid` is our own child and not reaped yet,
        // so it can't belong to another process.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    }
    if tokio::time::timeout(TERM_WAIT, child.wait()).await.is_err() {
        let _ = child.kill().await;
    }
}

/// A reply that ends a command.
#[derive(Debug, PartialEq)]
enum Reply {
    Ok,
    /// The error code and its text.
    Err(u32, String),
}

/// The pipes to one pinentry.
struct Session {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Session {
    async fn send(&mut self, line: &str) -> io::Result<()> {
        self.stdin.write_all(format!("{line}\n").as_bytes()).await
    }

    /// Waits for `OK` to `what` (a command, or pinentry's greeting).
    async fn expect_ok(&mut self, what: &str) -> io::Result<()> {
        match self.reply(SETUP_WAIT).await? {
            Reply::Ok => Ok(()),
            Reply::Err(_, text) => Err(io::Error::other(format!(
                "pinentry refused {what}: {}",
                sanitize(&text)
            ))),
        }
    }

    /// The next `OK` or `ERR`, skipping comments and status lines, within
    /// `wait`.
    async fn reply(&mut self, wait: Duration) -> io::Result<Reply> {
        let late = || {
            let wait = keys::format_duration(wait);
            io::Error::new(
                ErrorKind::TimedOut,
                format!("pinentry didn't reply within {wait}"),
            )
        };
        tokio::time::timeout(wait, self.next_reply())
            .await
            .map_err(|_| late())?
    }

    async fn next_reply(&mut self) -> io::Result<Reply> {
        loop {
            let mut line = String::new();
            let read = (&mut self.stdout)
                .take(MAX_LINE as u64)
                .read_line(&mut line)
                .await?;
            let Some(line) = line.strip_suffix('\n') else {
                return Err(match read {
                    0 => io::Error::new(ErrorKind::UnexpectedEof, "pinentry exited"),
                    _ => io::Error::new(ErrorKind::InvalidData, "garbled reply from pinentry"),
                });
            };
            if let Some(reply) = parse(line)? {
                return Ok(reply);
            }
        }
    }
}

/// One line from pinentry: a reply, or `None` for a comment or status line.
/// Anything else (e.g. a curses pinentry drawing into the pipe) is an error.
fn parse(line: &str) -> io::Result<Option<Reply>> {
    if line == "OK" || line.starts_with("OK ") {
        return Ok(Some(Reply::Ok));
    }
    if let Some(rest) = line.strip_prefix("ERR ") {
        let (code, text) = rest.split_once(' ').unwrap_or((rest, ""));
        if let Ok(code) = code.parse() {
            return Ok(Some(Reply::Err(code, text.to_owned())));
        }
    }
    if line.starts_with('#') || line == "S" || line.starts_with("S ") {
        return Ok(None);
    }
    Err(io::Error::new(
        ErrorKind::InvalidData,
        format!("unexpected reply from pinentry: {}", sanitize(line)),
    ))
}

/// Percent-escapes `text` for an Assuan line (`%`, CR and LF), cut short
/// with `…` if it would take more than `max` bytes.
fn escape(text: &str, max: usize) -> String {
    let mut out = String::new();
    // Where each escaped character ends, so a cut never splits one.
    let mut ends = Vec::new();
    for c in text.chars() {
        match c {
            '%' => out.push_str("%25"),
            '\r' => out.push_str("%0D"),
            '\n' => out.push_str("%0A"),
            c => out.push(c),
        }
        ends.push(out.len());
    }
    if out.len() > max {
        let room = max - '…'.len_utf8();
        let end = ends.into_iter().take_while(|&end| end <= room).last();
        out.truncate(end.unwrap_or(0));
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const TIMEOUT: Duration = Duration::from_secs(60);

    /// A fake pinentry (`sh -c`): `OK` to everything but `CONFIRM`, which runs
    /// `confirm`. Logs every line it gets to `log`.
    fn fake(confirm: &str, log: &Path) -> Pinentry {
        let script = format!(
            r#"echo "OK Pleased to meet you"
while IFS= read -r line; do
  printf '%s\n' "$line" >> '{log}'
  case "$line" in
    CONFIRM) {confirm} ;;
    *) echo OK ;;
  esac
done"#,
            log = log.display()
        );
        Pinentry {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            timeout: TIMEOUT,
            grace: Duration::from_millis(200),
            display: true,
        }
    }

    struct Fake {
        dir: tempfile::TempDir,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
            }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        fn pinentry(&self, confirm: &str) -> Pinentry {
            fake(confirm, &self.path("log"))
        }

        async fn confirm(&self, confirm: &str) -> io::Result<bool> {
            let message = "Signature request from pid 1\n  key: k\nAllow?";
            self.pinentry(confirm)
                .confirm(message, &CancellationToken::new())
                .await
        }

        fn log(&self) -> Vec<String> {
            let log = std::fs::read_to_string(self.path("log")).unwrap_or_default();
            log.lines().map(str::to_owned).collect()
        }

        /// The pid the fake wrote to `pid` (with `echo $$ > …/pid`).
        async fn pid(&self) -> libc::pid_t {
            loop {
                if let Ok(pid) = std::fs::read_to_string(self.path("pid"))
                    && let Ok(pid) = pid.trim().parse()
                {
                    return pid;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }

    fn alive(pid: libc::pid_t) -> bool {
        // SAFETY: signal 0 only checks that the process exists.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    #[tokio::test]
    async fn allow_approves() {
        let fake = Fake::new();
        assert!(fake.confirm("echo OK").await.unwrap());
        assert_eq!(
            fake.log(),
            [
                "SETTITLE sudo-agent",
                "SETDESC Signature request from pid 1%0A  key: k%0AAllow?",
                "SETOK Allow",
                "SETCANCEL Deny",
                "SETTIMEOUT 60",
                "CONFIRM",
            ]
        );
    }

    #[tokio::test]
    async fn deny_denies() {
        let fake = Fake::new();
        let deny = "echo 'ERR 83886179 Operation cancelled <Pinentry>'";
        assert!(!fake.confirm(deny).await.unwrap());
    }

    #[tokio::test]
    async fn its_own_timeout_is_no_answer() {
        let fake = Fake::new();
        let timeout = "echo 'ERR 83886142 Timeout <Pinentry>'";
        let e = fake.confirm(timeout).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::TimedOut);
        assert_eq!(e.to_string(), "no answer within 1m");
    }

    #[tokio::test]
    async fn other_errors_are_failures_not_denials() {
        let fake = Fake::new();
        // What pinentry-tty and pinentry-curses answer without a terminal.
        for error in [
            "echo 'ERR 83886194 Not confirmed <Pinentry>'",
            "echo 'S ERROR curses.isatty 83918950 '; \
             echo 'ERR 83918950 Inappropriate ioctl for device <Pinentry>'",
        ] {
            let e = fake.confirm(error).await.unwrap_err();
            assert!(e.to_string().starts_with("pinentry failed: "), "{e}");
        }
    }

    #[tokio::test]
    async fn garbage_is_a_failure() {
        let fake = Fake::new();
        let e = fake
            .confirm(r"printf '\033[?1049h\033[H\n'")
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidData);
        assert!(!e.to_string().contains('\x1b'), "{e}");

        // Without a newline, and then nothing: given up at the deadline.
        let mut pinentry = fake.pinentry(r"printf '\033[?1049h'; exec sleep 60");
        pinentry.timeout = Duration::from_millis(100);
        let e = pinentry
            .confirm("Allow?", &CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn a_hung_pinentry_is_given_up_and_killed() {
        let fake = Fake::new();
        let mut pinentry = fake.pinentry(&format!(
            "echo $$ > '{}'; exec sleep 60",
            fake.path("pid").display()
        ));
        pinentry.timeout = Duration::from_millis(100);
        let e = pinentry
            .confirm("Allow?", &CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::TimedOut);
        assert!(!alive(fake.pid().await));
    }

    #[tokio::test]
    async fn exiting_without_an_answer_is_a_failure() {
        let fake = Fake::new();
        let e = fake.confirm("exit 0").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn withdrawing_kills_it() {
        // The second one ignores SIGTERM and needs SIGKILL.
        for trap in ["", "trap '' TERM; "] {
            let fake = Fake::new();
            let pinentry = fake.pinentry(&format!(
                "{trap}echo $$ > '{}'; exec sleep 60",
                fake.path("pid").display()
            ));
            let cancel = CancellationToken::new();
            let asking = tokio::spawn({
                let cancel = cancel.clone();
                async move { pinentry.confirm("Allow?", &cancel).await }
            });
            let pid = fake.pid().await;
            cancel.cancel();
            let withdrawn = tokio::time::timeout(Duration::from_secs(5), asking).await;
            let e = withdrawn.expect("withdrawn in time").unwrap().unwrap_err();
            assert_eq!(e.to_string(), "cancelled");
            assert!(!alive(pid), "{trap:?}");
        }
    }

    #[tokio::test]
    async fn runs_in_its_own_session() {
        let fake = Fake::new();
        let ids = fake.path("ids");
        // Field 6 of /proc/<pid>/stat is the session id.
        let record = format!(
            "set -- $(cat /proc/$$/stat); echo \"$$ $6\" > '{}'; echo OK",
            ids.display()
        );
        assert!(fake.confirm(&record).await.unwrap());
        let ids = std::fs::read_to_string(ids).unwrap();
        let (pid, session) = ids.trim().split_once(' ').unwrap();
        assert_eq!(pid, session, "should lead its own session");
    }

    #[tokio::test]
    async fn a_missing_program_is_a_failure() {
        let pinentry = Pinentry::new("/nonexistent/pinentry", TIMEOUT);
        let e = pinentry
            .confirm("Allow?", &CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotFound);
        assert!(
            e.to_string()
                .starts_with("can't start /nonexistent/pinentry: ")
        );
    }

    #[test]
    fn needs_a_display() {
        let set = Some(OsStr::new(":0"));
        let empty = Some(OsStr::new(""));
        assert!(has_display(set, None));
        assert!(has_display(None, Some(OsStr::new("wayland-0"))));
        assert!(has_display(empty, set));
        assert!(!has_display(None, None));
        assert!(!has_display(empty, empty));
    }

    #[test]
    fn replies() {
        assert_eq!(parse("OK").unwrap(), Some(Reply::Ok));
        assert_eq!(parse("OK Pleased to meet you").unwrap(), Some(Reply::Ok));
        assert_eq!(
            parse("ERR 83886179 Operation cancelled <Pinentry>").unwrap(),
            Some(Reply::Err(
                83886179,
                "Operation cancelled <Pinentry>".to_owned()
            ))
        );
        assert_eq!(parse("ERR 5").unwrap(), Some(Reply::Err(5, String::new())));
        assert_eq!(parse("# a comment").unwrap(), None);
        assert_eq!(parse("S PROGRESS").unwrap(), None);
        for line in [
            "",
            "OKAY",
            "ERR",
            "ERR x y",
            "D data",
            "INQUIRE PIN",
            "\x1b[2J",
        ] {
            assert!(parse(line).is_err(), "{line:?}");
        }
    }

    #[test]
    fn escaping() {
        assert_eq!(escape("a%b\r\nc", 100), "a%25b%0D%0Ac");
        assert_eq!(escape("abc", 3), "abc");
        assert_eq!(escape("abcd", 4), "abcd");
        assert_eq!(escape("abcde", 4), "a…");
        // Never splits an escape or a character.
        assert_eq!(escape("a\nbcdef", 6), "a…");
        assert_eq!(escape("aäö", 4), "a…");
        let long = "x".repeat(2000);
        assert!(escape(&long, MAX_LINE - 9).len() <= MAX_LINE - 9);
    }

    /// Opens the real pinentry (`$PINENTRY`, default `pinentry`), to be
    /// answered by hand: `cargo test real_pinentry -- --ignored --nocapture`.
    fn real() -> Pinentry {
        let program = std::env::var_os("PINENTRY").unwrap_or_else(|| "pinentry".into());
        Pinentry::new(program, Duration::from_secs(30))
    }

    const REAL_MESSAGE: &str = "Signature request from pid 402599, uid 1000: ssh server\n  \
                                key: laptop (SHA256:LaGG9bgLw3dl0cl0JDUUbOPEl36TgNwNysXvEICHKtU), \
                                expires in 12m30s\nAllow?";

    #[tokio::test]
    #[ignore = "opens a real pinentry popup"]
    async fn real_pinentry_answer() {
        let answer = real()
            .confirm(REAL_MESSAGE, &CancellationToken::new())
            .await;
        println!("pinentry answered: {answer:?}");
    }

    #[tokio::test]
    #[ignore = "opens a real pinentry popup"]
    async fn real_pinentry_withdrawn() {
        let cancel = CancellationToken::new();
        let withdraw = {
            let cancel = cancel.clone();
            async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                println!("withdrawing the popup now");
                cancel.cancel();
            }
        };
        let pinentry = real();
        let (answer, ()) = tokio::join!(pinentry.confirm(REAL_MESSAGE, &cancel), withdraw);
        println!("pinentry answered: {answer:?}");
    }
}
