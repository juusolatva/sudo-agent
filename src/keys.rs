//! Loaded keys, their expiry, and loading them from disk.

use std::io::{self, ErrorKind};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use ssh_key::PrivateKey;

use crate::prompt::Prompter;

const PASSPHRASE_ATTEMPTS: usize = 3;

pub struct KeyEntry {
    /// Decrypted at load time; `ssh-key` zeroizes the key material on drop.
    pub private_key: PrivateKey,
    /// Deadline on the [`now`] clock.
    pub expires_at: Duration,
}

impl KeyEntry {
    pub fn is_expired(&self, now: Duration) -> bool {
        now >= self.expires_at
    }
}

/// Current time on `CLOCK_BOOTTIME`. Unlike `Instant` (`CLOCK_MONOTONIC` on
/// Linux), this keeps counting while the machine is suspended, so a key's TTL
/// can't be stretched by closing the laptop lid.
pub fn now() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime(CLOCK_BOOTTIME) failed");
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// Drops expired keys (zeroizing them) and returns their comments.
pub fn purge_expired(keys: &Mutex<Vec<KeyEntry>>, now: Duration) -> Vec<String> {
    let mut keys = keys.lock().unwrap();
    let mut expired = Vec::new();
    keys.retain(|k| {
        let keep = !k.is_expired(now);
        if !keep {
            expired.push(k.private_key.comment().to_owned());
        }
        keep
    });
    expired
}

/// Reads an OpenSSH private key, asking for its passphrase if it is
/// encrypted. The TTL starts once the key is decrypted.
pub async fn load(path: &Path, ttl: Duration, prompter: &dyn Prompter) -> io::Result<KeyEntry> {
    let pem = std::fs::read(path)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    let key = PrivateKey::from_openssh(pem).map_err(|e| key_error(path, e))?;
    let private_key = if key.is_encrypted() {
        decrypt(&key, path, prompter).await?
    } else {
        eprintln!("warning: {} is not passphrase-protected", path.display());
        key
    };
    Ok(KeyEntry {
        private_key,
        expires_at: now() + ttl,
    })
}

async fn decrypt(key: &PrivateKey, path: &Path, prompter: &dyn Prompter) -> io::Result<PrivateKey> {
    let message = format!("Passphrase for {}", path.display());
    let mut attempts_left = PASSPHRASE_ATTEMPTS;
    loop {
        let passphrase = prompter.passphrase(&message).await?;
        if passphrase.is_empty() {
            return Err(io::Error::new(
                ErrorKind::Interrupted,
                format!("no passphrase entered for {}", path.display()),
            ));
        }
        match key.decrypt(passphrase.as_bytes()) {
            Ok(key) => return Ok(key),
            Err(ssh_key::Error::Crypto) if attempts_left > 1 => {
                attempts_left -= 1;
                eprintln!("Wrong passphrase, try again.");
            }
            Err(ssh_key::Error::Crypto) => {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    format!("wrong passphrase for {}", path.display()),
                ));
            }
            Err(e) => return Err(key_error(path, e)),
        }
    }
}

fn key_error(path: &Path, error: ssh_key::Error) -> io::Error {
    io::Error::new(
        ErrorKind::InvalidData,
        format!("{}: {error}", path.display()),
    )
}

/// Parses a TTL like `90s`, `15m` or `8h`.
pub fn parse_ttl(s: &str) -> Result<Duration, String> {
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (number, unit) = s.split_at(split);
    let number: u64 = number
        .parse()
        .map_err(|_| format!("invalid TTL {s:?}: expected e.g. 90s, 15m or 8h"))?;
    let seconds = match unit {
        "s" => number,
        "m" => number.saturating_mul(60),
        "h" => number.saturating_mul(60 * 60),
        _ => return Err(format!("invalid TTL unit in {s:?}: use s, m or h")),
    };
    if seconds == 0 {
        return Err("TTL must be greater than zero".to_owned());
    }
    Ok(Duration::from_secs(seconds))
}

/// Formats a TTL the way [`parse_ttl`] accepts it, in the largest exact unit.
pub fn format_ttl(ttl: Duration) -> String {
    match ttl.as_secs() {
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// Formats time left before expiry, to the second, e.g. `1h05m`, `14m30s`, `45s`.
pub fn format_remaining(left: Duration) -> String {
    match left.as_secs() {
        s if s >= 3600 => format!("{}h{:02}m", s / 3600, s % 3600 / 60),
        s if s >= 60 => format!("{}m{:02}s", s / 60, s % 60),
        s => format!("{s}s"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::testing::ScriptedPrompter;
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, LineEnding};
    use std::path::PathBuf;

    const TTL: Duration = Duration::from_secs(60);

    /// Writes a fresh Ed25519 key (encrypted if `passphrase` is given) to a
    /// temp dir that is deleted when the returned guard drops. Generated per
    /// test so no private key is ever committed.
    fn write_key(name: &str, passphrase: Option<&str>) -> (tempfile::TempDir, PathBuf) {
        let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        key.set_comment(name);
        if let Some(passphrase) = passphrase {
            key = key.encrypt(&mut OsRng, passphrase).unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        key.write_openssh_file(&path, LineEnding::LF).unwrap();
        (dir, path)
    }

    #[tokio::test]
    async fn unencrypted_key_loads_without_prompting() {
        let (_dir, path) = write_key("plain", None);
        let prompter = ScriptedPrompter::default();
        let entry = load(&path, TTL, &prompter).await.unwrap();
        assert_eq!(entry.private_key.comment(), "plain");
        assert!(prompter.asked().is_empty());
    }

    #[tokio::test]
    async fn encrypted_key_loads_with_correct_passphrase() {
        let (_dir, path) = write_key("enc-ok", Some("correct horse"));
        let prompter = ScriptedPrompter::with_passphrases(["correct horse"]);
        let entry = load(&path, TTL, &prompter).await.unwrap();
        assert!(!entry.private_key.is_encrypted());
        assert!(!entry.is_expired(now()));
    }

    #[tokio::test]
    async fn wrong_passphrase_is_retried() {
        let (_dir, path) = write_key("enc-retry", Some("right"));
        let prompter = ScriptedPrompter::with_passphrases(["wrong", "right"]);
        load(&path, TTL, &prompter).await.unwrap();
        assert_eq!(prompter.asked().len(), 2);
    }

    #[tokio::test]
    async fn gives_up_after_three_wrong_passphrases() {
        let (_dir, path) = write_key("enc-fail", Some("right"));
        let prompter = ScriptedPrompter::with_passphrases(["a", "b", "c", "right"]);
        let err = load(&path, TTL, &prompter).await.err().unwrap();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        assert_eq!(prompter.asked().len(), PASSPHRASE_ATTEMPTS);
    }

    #[tokio::test]
    async fn empty_passphrase_aborts() {
        let (_dir, path) = write_key("enc-empty", Some("right"));
        let prompter = ScriptedPrompter::with_passphrases([""]);
        let err = load(&path, TTL, &prompter).await.err().unwrap();
        assert_eq!(err.kind(), ErrorKind::Interrupted);
    }

    #[tokio::test]
    async fn purge_drops_only_expired_keys() {
        let prompter = ScriptedPrompter::default();
        let (_short_dir, short_path) = write_key("short", None);
        let (_long_dir, long_path) = write_key("long", None);
        let mut short = load(&short_path, TTL, &prompter).await.unwrap();
        let long = load(&long_path, TTL, &prompter).await.unwrap();
        short.expires_at = long.expires_at - Duration::from_secs(30);

        let keys = Mutex::new(vec![short, long]);
        let at = keys.lock().unwrap()[0].expires_at;
        assert_eq!(purge_expired(&keys, at), ["short"]);
        assert_eq!(keys.lock().unwrap().len(), 1);
    }

    #[test]
    fn ttl_parsing() {
        assert_eq!(parse_ttl("90s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_ttl("15m"), Ok(Duration::from_secs(900)));
        assert_eq!(parse_ttl("8h"), Ok(Duration::from_secs(8 * 3600)));
        for bad in ["", "15", "m", "0m", "1.5h", "-5m", "15 m", "15min", "1d"] {
            assert!(parse_ttl(bad).is_err(), "{bad:?} should be rejected");
        }
        for ttl in ["90s", "15m", "8h", "61s", "90m"] {
            assert_eq!(format_ttl(parse_ttl(ttl).unwrap()), ttl);
        }
    }

    #[test]
    fn remaining_formatting() {
        let secs = Duration::from_secs;
        assert_eq!(format_remaining(Duration::from_millis(900)), "0s");
        assert_eq!(format_remaining(secs(45)), "45s");
        assert_eq!(format_remaining(secs(870)), "14m30s");
        assert_eq!(format_remaining(secs(3900)), "1h05m");
    }
}
