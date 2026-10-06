//! User prompts: secret entry (key passphrase, once at load time) and yes/no
//! confirmation (approval, on every sign).
//!
//! Callers depend only on [`Prompter`]; [`TerminalPrompter`] is the first
//! backend and must keep working once GUI/notification backends exist.

use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::keys;

#[async_trait]
pub trait Prompter: Send + Sync {
    /// Asks for a secret, e.g. a key passphrase. Only used at key load time.
    async fn passphrase(&self, message: &str) -> io::Result<Zeroizing<String>>;

    /// Asks a yes/no question. Anything but an explicit "yes" is `false`;
    /// callers must also treat `Err` as a denial. A backend that gives up
    /// waiting returns an `ErrorKind::TimedOut` error saying so.
    async fn confirm(&self, message: &str) -> io::Result<bool>;
}

/// Prompts on the controlling terminal (`/dev/tty`), one prompt at a time.
#[derive(Clone)]
pub struct TerminalPrompter {
    // Locked inside the blocking task rather than across an `.await`, so the
    // terminal stays owned by whichever prompt is actually reading from it,
    // even if the request that started it has gone away.
    tty: Arc<Mutex<()>>,
    /// How long an approval waits for an answer before it counts as denied.
    /// Passphrase prompts (startup only) don't time out.
    approval_timeout: Duration,
}

impl TerminalPrompter {
    pub fn new(approval_timeout: Duration) -> Self {
        Self {
            tty: Arc::default(),
            approval_timeout,
        }
    }

    async fn with_tty<T, F>(&self, f: F) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> io::Result<T> + Send + 'static,
    {
        let tty = Arc::clone(&self.tty);
        tokio::task::spawn_blocking(move || {
            let _guard = tty.lock().unwrap_or_else(PoisonError::into_inner);
            f()
        })
        .await
        .map_err(io::Error::other)?
    }
}

#[async_trait]
impl Prompter for TerminalPrompter {
    async fn passphrase(&self, message: &str) -> io::Result<Zeroizing<String>> {
        let prompt = format!("{message}: ");
        self.with_tty(move || rpassword::prompt_password(prompt).map(Zeroizing::new))
            .await
    }

    async fn confirm(&self, message: &str) -> io::Result<bool> {
        let message = message.to_owned();
        let timeout = self.approval_timeout;
        self.with_tty(move || {
            let tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
            discard_pending_input(&tty)?;
            let deadline = keys::now() + timeout;
            let wait = || wait_readable(tty.as_fd(), deadline);
            ask_yes_no(&mut &tty, &mut &tty, &message, wait)?.ok_or_else(|| {
                io::Error::new(
                    ErrorKind::TimedOut,
                    format!("no answer within {}", keys::format_duration(timeout)),
                )
            })
        })
        .await
    }
}

/// Waits until `fd` has input to read (in canonical mode: a complete line),
/// or `deadline` on the [`keys::now`] clock passes. Returning lets the prompt
/// give up the terminal instead of leaving a read behind that would swallow
/// the answer meant for the next prompt.
fn wait_readable(fd: BorrowedFd<'_>, deadline: Duration) -> io::Result<bool> {
    loop {
        let now = keys::now();
        if now >= deadline {
            return Ok(false);
        }
        // `poll` sleeps on CLOCK_MONOTONIC, which stops during suspend; waking
        // at least every second re-checks the deadline on the suspend-aware
        // clock, like the key TTL.
        let slice = (deadline - now).min(Duration::from_secs(1));
        let mut pollfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pollfd` is a valid array of one entry, and `fd` is open for
        // as long as it is borrowed.
        let rc = unsafe { libc::poll(&mut pollfd, 1, slice.as_millis() as libc::c_int) };
        match rc {
            0 => continue,
            // Readable, or hung up/errored: either way the read will tell.
            1.. => return Ok(true),
            _ => {
                let err = io::Error::last_os_error();
                if err.kind() != ErrorKind::Interrupted {
                    return Err(err);
                }
            }
        }
    }
}

/// Drops anything typed before the prompt appeared, so type-ahead can't
/// answer it.
fn discard_pending_input(tty: &File) -> io::Result<()> {
    // SAFETY: the descriptor is valid for as long as `tty` is borrowed.
    if unsafe { libc::tcflush(tty.as_raw_fd(), libc::TCIFLUSH) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Requires a typed "y"/"yes" plus Enter; a lone stray keypress can't approve.
/// `wait` blocks until an answer can be read, returning `false` once the time
/// to answer has run out, which yields `None`.
fn ask_yes_no(
    input: &mut impl Read,
    output: &mut impl Write,
    message: &str,
    wait: impl FnOnce() -> io::Result<bool>,
) -> io::Result<Option<bool>> {
    // One write, so a concurrently logged line can't land inside the prompt.
    output.write_all(format!("{message} [y/N] ").as_bytes())?;
    output.flush()?;

    if !wait()? {
        output.write_all(b"\n")?; // finish the prompt line before the log
        return Ok(None);
    }
    // A single read: a terminal in canonical mode returns at most one line,
    // and a second read could block past the deadline. Anything too long for
    // the buffer isn't a "yes"; its remainder is flushed by the next prompt.
    let mut answer = [0; 64];
    let n = input.read(&mut answer)?;
    if n == 0 {
        output.write_all(b"\n")?; // EOF (Ctrl-D): finish the prompt line, deny
        return Ok(Some(false));
    }
    let answer = String::from_utf8_lossy(&answer[..n]);
    Ok(Some(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn answer(input: &str) -> bool {
        let mut output = Vec::new();
        let approved = ask_yes_no(&mut Cursor::new(input), &mut output, "Allow?", || Ok(true))
            .unwrap()
            .expect("answered in time");
        assert!(
            String::from_utf8(output)
                .unwrap()
                .starts_with("Allow? [y/N] ")
        );
        approved
    }

    #[test]
    fn no_answer_in_time_is_not_an_answer() {
        let mut output = Vec::new();
        let result = ask_yes_no(&mut Cursor::new("y\n"), &mut output, "Allow?", || Ok(false));
        assert_eq!(result.unwrap(), None);
        assert_eq!(output, b"Allow? [y/N] \n");
    }

    #[test]
    fn wait_readable_honours_deadline() {
        let (reader, mut writer) = io::pipe().unwrap();
        let soon = || keys::now() + Duration::from_millis(50);
        assert!(!wait_readable(reader.as_fd(), soon()).unwrap());
        writer.write_all(b"y\n").unwrap();
        assert!(wait_readable(reader.as_fd(), soon()).unwrap());
    }

    #[test]
    fn explicit_yes_approves() {
        for input in ["y\n", "Y\n", "yes\n", "YES\n", "  y  \n", "y"] {
            assert!(answer(input), "{input:?} should approve");
        }
    }

    #[test]
    fn anything_else_denies() {
        for input in [
            "\n",
            "",
            "n\n",
            "no\n",
            "yy\n",
            "ye\n",
            "yes please\n",
            "q\n",
        ] {
            assert!(!answer(input), "{input:?} should deny");
        }
    }

    #[test]
    fn prompter_is_object_safe() {
        let _: Arc<dyn Prompter> = Arc::new(TerminalPrompter::new(Duration::from_secs(1)));
    }
}

/// A [`Prompter`] that answers from a script, for tests.
#[cfg(test)]
pub mod testing {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Default)]
    pub struct ScriptedPrompter {
        passphrases: Mutex<VecDeque<String>>,
        confirms: Mutex<VecDeque<bool>>,
        asked: Mutex<Vec<String>>,
    }

    impl ScriptedPrompter {
        pub fn with_passphrases<'a>(answers: impl IntoIterator<Item = &'a str>) -> Self {
            let prompter = Self::default();
            prompter
                .passphrases
                .lock()
                .unwrap()
                .extend(answers.into_iter().map(str::to_owned));
            prompter
        }

        pub fn with_confirms(answers: impl IntoIterator<Item = bool>) -> Self {
            let prompter = Self::default();
            prompter.confirms.lock().unwrap().extend(answers);
            prompter
        }

        /// Every message prompted so far, in order.
        pub fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Prompter for ScriptedPrompter {
        async fn passphrase(&self, message: &str) -> io::Result<Zeroizing<String>> {
            self.asked.lock().unwrap().push(message.to_owned());
            let answer = self.passphrases.lock().unwrap().pop_front();
            answer.map(Zeroizing::new).ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "no scripted passphrase")
            })
        }

        /// Denies once the script runs out, like a real prompt would on EOF.
        async fn confirm(&self, message: &str) -> io::Result<bool> {
            self.asked.lock().unwrap().push(message.to_owned());
            Ok(self.confirms.lock().unwrap().pop_front().unwrap_or(false))
        }
    }
}
