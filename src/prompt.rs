//! User prompts: secret entry (key passphrase, once at load time) and yes/no
//! confirmation (approval, on every sign).
//!
//! Callers depend only on [`Prompter`]; [`TerminalPrompter`] is the first
//! backend and must keep working once GUI/notification backends exist.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use zeroize::Zeroizing;

#[async_trait]
pub trait Prompter: Send + Sync {
    /// Asks for a secret, e.g. a key passphrase. Only used at key load time.
    async fn passphrase(&self, message: &str) -> io::Result<Zeroizing<String>>;

    /// Asks a yes/no question. Anything but an explicit "yes" is `false`;
    /// callers must also treat `Err` as a denial.
    async fn confirm(&self, message: &str) -> io::Result<bool>;
}

/// Prompts on the controlling terminal (`/dev/tty`), one prompt at a time.
#[derive(Clone, Default)]
pub struct TerminalPrompter {
    // Locked inside the blocking task rather than across an `.await`, so the
    // terminal stays owned by whichever prompt is actually reading from it,
    // even if the request that started it has gone away.
    tty: Arc<Mutex<()>>,
}

impl TerminalPrompter {
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
        self.with_tty(move || {
            let tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
            discard_pending_input(&tty)?;
            ask_yes_no(&mut BufReader::new(&tty), &mut &tty, &message)
        })
        .await
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
fn ask_yes_no(
    input: &mut impl BufRead,
    output: &mut impl Write,
    message: &str,
) -> io::Result<bool> {
    write!(output, "{message} [y/N] ")?;
    output.flush()?;

    let mut answer = String::new();
    if input.read_line(&mut answer)? == 0 {
        writeln!(output)?; // EOF (Ctrl-D): finish the prompt line, deny
        return Ok(false);
    }
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn answer(input: &str) -> bool {
        let mut output = Vec::new();
        let approved = ask_yes_no(&mut Cursor::new(input), &mut output, "Allow?").unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .starts_with("Allow? [y/N] ")
        );
        approved
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
        let _: Arc<dyn Prompter> = Arc::new(TerminalPrompter::default());
    }
}
