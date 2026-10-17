//! User prompts: secret entry (key passphrase, once at load time) and yes/no
//! confirmation (approval, on every sign).
//!
//! Callers depend only on [`Prompter`]; [`TerminalPrompter`] is the first
//! backend and must keep working once GUI/notification backends exist.

use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, PipeReader, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::keys;

#[async_trait]
pub trait Prompter: Send + Sync {
    /// Asks for a secret, e.g. a key passphrase. Only used at key load time.
    async fn passphrase(&self, message: &str) -> io::Result<Zeroizing<String>>;

    /// Asks a yes/no question. `Ok` is an answer: anything but an explicit
    /// "yes" is `false`. `Err` means no answer (timed out, withdrawn, or the
    /// backend failed), which routing doesn't count as a denial while another
    /// backend may still answer; callers must treat it as one otherwise. A
    /// backend that gives up waiting returns an `ErrorKind::TimedOut` error
    /// saying so.
    ///
    /// Once `cancel` fires (e.g. the requesting client went away), the
    /// backend withdraws the question and returns an error. It must not
    /// return before the question is gone, so nothing printed afterwards
    /// lands inside it.
    async fn confirm(&self, message: &str, cancel: &CancellationToken) -> io::Result<bool>;

    /// Whether this backend can ask anything at all, e.g. there is a terminal
    /// to prompt on. Routing skips backends that can't.
    fn available(&self) -> bool {
        true
    }
}

/// Prompts on the controlling terminal (`/dev/tty`), one prompt at a time.
#[derive(Clone)]
pub struct TerminalPrompter {
    // Locked inside the blocking task rather than across an `.await`, so the
    // terminal stays owned by whichever prompt is actually reading from it,
    // even if the request that started it has gone away.
    tty: Arc<Mutex<()>>,
    /// Cancels the approval prompt currently on the terminal, if any; see
    /// [`interrupt`](Self::interrupt). Set and cleared while holding `tty`.
    open: Arc<Mutex<Option<CancellationToken>>>,
    /// How long an approval waits for an answer before it counts as denied.
    /// Passphrase prompts (startup only) don't time out.
    approval_timeout: Duration,
    /// Whether there was a terminal to prompt on at startup (there isn't
    /// under systemd or `setsid`).
    has_tty: bool,
}

impl TerminalPrompter {
    pub fn new(approval_timeout: Duration) -> Self {
        Self {
            tty: Arc::default(),
            open: Arc::default(),
            approval_timeout,
            has_tty: OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")
                .is_ok(),
        }
    }

    /// Answers the approval prompt on the terminal with a denial, if one is
    /// open. Returns whether there was one. Used for Ctrl-C,
    /// which should answer the prompt rather than stop the agent.
    pub fn interrupt(&self) -> bool {
        let open = self
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        open.inspect(CancellationToken::cancel).is_some()
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

    async fn confirm(&self, message: &str, cancel: &CancellationToken) -> io::Result<bool> {
        if cancel.is_cancelled() {
            return Err(io::Error::other("cancelled"));
        }
        // Fires on `cancel`, or on Ctrl-C while this prompt is open.
        let stop = cancel.child_token();
        // The prompt polls `wake` alongside the terminal; dropping `wake_up`
        // hangs up the pipe, which ends the wait. This also happens if this
        // future is dropped.
        let (wake, wake_up) = io::pipe()?;
        let message = message.to_owned();
        let timeout = self.approval_timeout;
        let open = Arc::clone(&self.open);
        let interruptible = stop.clone();
        let prompt = self.with_tty(move || {
            *open.lock().unwrap_or_else(PoisonError::into_inner) = Some(interruptible);
            let answer = ask_on_tty(&message, &wake, timeout);
            open.lock().unwrap_or_else(PoisonError::into_inner).take();
            answer
        });
        tokio::pin!(prompt);
        let answer = tokio::select! {
            answer = &mut prompt => answer?,
            () = stop.cancelled() => {
                drop(wake_up);
                // Let the prompt finish its line and release the terminal.
                prompt.await?
            }
        };
        match answer {
            Ok(approved) => Ok(approved),
            Err(NoAnswer::TimedOut) => Err(io::Error::new(
                ErrorKind::TimedOut,
                format!("no answer within {}", keys::format_duration(timeout)),
            )),
            Err(NoAnswer::Cancelled) if cancel.is_cancelled() => Err(io::Error::other("cancelled")),
            // Ctrl-C is an answer, so it also withdraws the other backends.
            Err(NoAnswer::Cancelled) => Ok(false),
        }
    }

    fn available(&self) -> bool {
        self.has_tty
    }
}

/// Why a prompt ended without an answer.
#[derive(Debug, PartialEq)]
enum NoAnswer {
    TimedOut,
    /// `wake` was hung up: the prompt was withdrawn.
    Cancelled,
}

/// One approval prompt on `/dev/tty`, run while holding the terminal.
fn ask_on_tty(
    message: &str,
    wake: &PipeReader,
    timeout: Duration,
) -> io::Result<Result<bool, NoAnswer>> {
    let tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    discard_pending_input(&tty)?;
    let deadline = keys::now() + timeout;
    let wait = || wait_readable(tty.as_fd(), wake.as_fd(), deadline);
    ask_yes_no(&mut &tty, &mut &tty, message, wait)
}

/// Waits until `fd` has input to read (in canonical mode: a complete line),
/// `deadline` on the [`keys::now`] clock passes, or `wake` hangs up (or
/// becomes readable). Returning lets the prompt give up the terminal instead
/// of leaving a read behind that would swallow the answer meant for the next
/// prompt.
fn wait_readable(
    fd: BorrowedFd<'_>,
    wake: BorrowedFd<'_>,
    deadline: Duration,
) -> io::Result<Result<(), NoAnswer>> {
    loop {
        let now = keys::now();
        if now >= deadline {
            return Ok(Err(NoAnswer::TimedOut));
        }
        // `poll` sleeps on CLOCK_MONOTONIC, which stops during suspend; waking
        // at least every second re-checks the deadline on the suspend-aware
        // clock, like the key TTL.
        let slice = (deadline - now).min(Duration::from_secs(1));
        let mut pollfds = [fd, wake].map(|fd| libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        // SAFETY: `pollfds` is a valid array of its length, and both
        // descriptors are open for as long as they are borrowed.
        let rc = unsafe {
            libc::poll(
                pollfds.as_mut_ptr(),
                pollfds.len() as libc::nfds_t,
                slice.as_millis() as libc::c_int,
            )
        };
        match rc {
            0 => continue,
            // Being withdrawn wins over an answer typed at the same moment.
            1.. if pollfds[1].revents != 0 => return Ok(Err(NoAnswer::Cancelled)),
            // Readable, or hung up/errored: either way the read will tell.
            1.. => return Ok(Ok(())),
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
/// `wait` blocks until an answer can be read, or says why there won't be one.
fn ask_yes_no(
    input: &mut impl Read,
    output: &mut impl Write,
    message: &str,
    wait: impl FnOnce() -> io::Result<Result<(), NoAnswer>>,
) -> io::Result<Result<bool, NoAnswer>> {
    // One write, so a concurrently logged line can't land inside the prompt.
    output.write_all(format!("{message} [y/N] ").as_bytes())?;
    output.flush()?;

    if let Err(no_answer) = wait()? {
        output.write_all(b"\n")?; // finish the prompt line before the log
        return Ok(Err(no_answer));
    }
    // A single read: a terminal in canonical mode returns at most one line,
    // and a second read could block past the deadline. Anything too long for
    // the buffer isn't a "yes"; its remainder is flushed by the next prompt.
    let mut answer = [0; 64];
    let n = input.read(&mut answer)?;
    if n == 0 {
        output.write_all(b"\n")?; // EOF (Ctrl-D): finish the prompt line, deny
        return Ok(Ok(false));
    }
    let answer = String::from_utf8_lossy(&answer[..n]);
    Ok(Ok(matches!(
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
        let approved = ask_yes_no(&mut Cursor::new(input), &mut output, "Allow?", || {
            Ok(Ok(()))
        })
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
        for why in [NoAnswer::TimedOut, NoAnswer::Cancelled] {
            let mut output = Vec::new();
            let result = ask_yes_no(&mut Cursor::new("y\n"), &mut output, "Allow?", || {
                Ok(Err(why))
            });
            assert!(result.unwrap().is_err());
            assert_eq!(output, b"Allow? [y/N] \n");
        }
    }

    #[test]
    fn wait_readable_honours_deadline() {
        let (reader, mut writer) = io::pipe().unwrap();
        let (wake, _wake_up) = io::pipe().unwrap();
        let soon = || keys::now() + Duration::from_millis(50);
        let wait = || wait_readable(reader.as_fd(), wake.as_fd(), soon()).unwrap();
        assert_eq!(wait(), Err(NoAnswer::TimedOut));
        writer.write_all(b"y\n").unwrap();
        assert_eq!(wait(), Ok(()));
    }

    #[test]
    fn wait_readable_gives_up_when_woken() {
        let later = keys::now() + Duration::from_secs(60);
        let (reader, _writer) = io::pipe().unwrap();
        let (wake, wake_up) = io::pipe().unwrap();
        let waiter = std::thread::spawn(move || wait_readable(reader.as_fd(), wake.as_fd(), later));
        std::thread::sleep(Duration::from_millis(20));
        drop(wake_up);
        assert_eq!(waiter.join().unwrap().unwrap(), Err(NoAnswer::Cancelled));
    }

    #[test]
    fn withdrawn_prompt_ignores_waiting_answer() {
        let later = keys::now() + Duration::from_secs(60);
        let (reader, mut writer) = io::pipe().unwrap();
        writer.write_all(b"y\n").unwrap();
        let (wake, wake_up) = io::pipe().unwrap();
        drop(wake_up);
        let result = wait_readable(reader.as_fd(), wake.as_fd(), later).unwrap();
        assert_eq!(result, Err(NoAnswer::Cancelled));
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
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering::SeqCst;

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
        async fn confirm(&self, message: &str, _: &CancellationToken) -> io::Result<bool> {
            self.asked.lock().unwrap().push(message.to_owned());
            Ok(self.confirms.lock().unwrap().pop_front().unwrap_or(false))
        }
    }

    /// Gives up at once without answering, like a backend that failed.
    pub struct GivesUp {
        kind: io::ErrorKind,
        asked: AtomicUsize,
    }

    impl GivesUp {
        pub const REASON: &str = "gave up";

        pub fn new(kind: io::ErrorKind) -> Self {
            Self {
                kind,
                asked: AtomicUsize::new(0),
            }
        }

        pub fn times_asked(&self) -> usize {
            self.asked.load(SeqCst)
        }
    }

    #[async_trait]
    impl Prompter for GivesUp {
        async fn passphrase(&self, _: &str) -> io::Result<Zeroizing<String>> {
            unreachable!("GivesUp only confirms")
        }

        async fn confirm(&self, _: &str, _: &CancellationToken) -> io::Result<bool> {
            self.asked.fetch_add(1, SeqCst);
            Err(io::Error::new(self.kind, Self::REASON))
        }
    }

    /// A backend that can't ask anything; panics if asked anyway.
    pub struct Unavailable;

    #[async_trait]
    impl Prompter for Unavailable {
        async fn passphrase(&self, _: &str) -> io::Result<Zeroizing<String>> {
            unreachable!("Unavailable is never asked")
        }

        async fn confirm(&self, _: &str, _: &CancellationToken) -> io::Result<bool> {
            unreachable!("Unavailable is never asked")
        }

        fn available(&self) -> bool {
            false
        }
    }

    /// Approves after `delay` unless cancelled first, counting what happened.
    pub struct ApprovesAfter {
        delay: Duration,
        asked: AtomicUsize,
        cancelled: AtomicUsize,
    }

    impl ApprovesAfter {
        pub fn new(delay: Duration) -> Self {
            Self {
                delay,
                asked: AtomicUsize::new(0),
                cancelled: AtomicUsize::new(0),
            }
        }

        pub fn times_asked(&self) -> usize {
            self.asked.load(SeqCst)
        }

        pub fn times_cancelled(&self) -> usize {
            self.cancelled.load(SeqCst)
        }

        /// Waits until a prompt has been opened `times` times.
        pub async fn until_asked(&self, times: usize) {
            while self.times_asked() < times {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }

    #[async_trait]
    impl Prompter for ApprovesAfter {
        async fn passphrase(&self, _: &str) -> io::Result<Zeroizing<String>> {
            unreachable!("ApprovesAfter only confirms")
        }

        async fn confirm(&self, _: &str, cancel: &CancellationToken) -> io::Result<bool> {
            self.asked.fetch_add(1, SeqCst);
            tokio::select! {
                () = tokio::time::sleep(self.delay) => Ok(true),
                () = cancel.cancelled() => {
                    self.cancelled.fetch_add(1, SeqCst);
                    Err(io::Error::other("cancelled"))
                }
            }
        }
    }
}
