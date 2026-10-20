//! Log line formatting for the `log!` macro: a local timestamp in front,
//! except when stderr is the journal, which stamps lines itself.

use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

static STAMPED: OnceLock<bool> = OnceLock::new();

/// Decides once whether log lines get timestamps. `main` calls it before
/// anything is logged, so the check (an `fstat` of stderr) never runs inside
/// async code; [`line`] falls back to it if not.
pub fn init() -> bool {
    *STAMPED.get_or_init(|| {
        let journal = std::env::var_os("JOURNAL_STREAM");
        !stderr_id().is_ok_and(|id| is_journal(journal.as_deref(), id))
    })
}

/// `args` as one log line, newline included.
pub fn line(args: fmt::Arguments) -> String {
    match init().then(timestamp).flatten() {
        Some(stamp) => format!("{stamp} {args}\n"),
        None => format!("{args}\n"),
    }
}

/// Device and inode of stderr, for comparing with `JOURNAL_STREAM`.
fn stderr_id() -> io::Result<(u64, u64)> {
    let meta = File::from(io::stderr().as_fd().try_clone_to_owned()?).metadata()?;
    Ok((meta.dev(), meta.ino()))
}

/// Whether stderr (`dev`, `ino`) is the journal stream systemd describes in
/// `JOURNAL_STREAM` (`<dev>:<ino>`). Checking only that the variable is set
/// would be wrong for a child that inherited it but logs elsewhere, e.g.
/// `setsid -f sudo-agent serve > log` from a shell started by a service.
fn is_journal(journal_stream: Option<&OsStr>, (dev, ino): (u64, u64)) -> bool {
    let Some((d, i)) = journal_stream
        .and_then(OsStr::to_str)
        .and_then(|v| v.split_once(':'))
    else {
        return false;
    };
    d.parse() == Ok(dev) && i.parse() == Ok(ino)
}

/// The current local time as `2026-10-20 14:03:12`, the way `journalctl`
/// shows it by default.
fn timestamp() -> Option<String> {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let secs = libc::time_t::try_from(secs).ok()?;
    // SAFETY: an all-zero `tm` is valid (the zone name pointer is null).
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are valid for the call; localtime_r() keeps no
    // reference to them. It loads the time zone (TZ, /etc/localtime) on first
    // use, which reads the environment; nothing here ever changes it.
    if unsafe { libc::localtime_r(&secs, &mut tm) }.is_null() {
        return None;
    }
    Some(format_tm(&tm))
}

fn format_tm(tm: &libc::tm) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_stream_must_match_stderr() {
        let journal = |v: &str| is_journal(Some(OsStr::new(v)), (8, 12345));
        assert!(journal("8:12345"));
        assert!(!journal("8:12346"), "other inode");
        assert!(!journal("9:12345"), "other device");
        assert!(!journal(""));
        assert!(!journal("8"));
        assert!(!journal("8:12345:1"));
        assert!(!journal(" 8:12345"));
        assert!(!is_journal(None, (8, 12345)), "unset");
    }

    #[test]
    fn stderr_is_identified() {
        // Whatever stderr the test harness gives, it has a device and inode.
        let id = stderr_id().unwrap();
        let value = format!("{}:{}", id.0, id.1);
        assert!(is_journal(Some(OsStr::new(&value)), id));
    }

    #[test]
    fn formats_like_journalctl() {
        // SAFETY: an all-zero `tm` is valid.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        tm.tm_year = 126;
        tm.tm_mon = 9;
        tm.tm_mday = 20;
        tm.tm_hour = 4;
        tm.tm_min = 3;
        tm.tm_sec = 2;
        assert_eq!(format_tm(&tm), "2026-10-20 04:03:02");
    }

    #[test]
    fn timestamp_has_the_right_shape() {
        let stamp = timestamp().unwrap();
        let shape: String = stamp
            .chars()
            .map(|c| if c.is_ascii_digit() { 'd' } else { c })
            .collect();
        assert_eq!(shape, "dddd-dd-dd dd:dd:dd");
    }

    #[test]
    fn line_ends_with_the_message_and_a_newline() {
        let line = line(format_args!("Approved {}", "x"));
        assert!(line.ends_with("Approved x\n"), "{line:?}");
    }
}
