//! Agent socket placement and setup.
//!
//! The default location is `$XDG_RUNTIME_DIR/sudo-agent/agent.sock` (per-user,
//! `0700`, tmpfs, cleared on logout). When that isn't set (`su`, containers,
//! WSL, non-systemd sessions) we fall back to
//! `${XDG_CACHE_HOME:-$HOME/.cache}/sudo-agent/agent-<hostname>.sock`; the
//! hostname suffix keeps machines sharing an NFS home from clobbering each
//! other's sockets.

use std::fs::{self, DirBuilder, Permissions};
use std::io::{self, ErrorKind};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use tokio::net::UnixListener;

const APP_DIR: &str = "sudo-agent";

/// Size of `sockaddr_un.sun_path` on Linux, including the trailing NUL.
const SUN_PATH_LEN: usize = 108;

/// Returns the default socket path, creating its parent directory with mode
/// `0700` and verifying ownership/permissions if it already exists.
pub fn default_path() -> io::Result<PathBuf> {
    let (dir, file_name) = match env_dir("XDG_RUNTIME_DIR") {
        Some(runtime) => (runtime.join(APP_DIR), "agent.sock".to_owned()),
        None => {
            let cache = env_dir("XDG_CACHE_HOME")
                .or_else(|| env_dir("HOME").map(|home| home.join(".cache")))
                .ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::NotFound,
                        "none of XDG_RUNTIME_DIR, XDG_CACHE_HOME or HOME is set; use --socket",
                    )
                })?;
            let file_name = match hostname() {
                Some(host) => format!("agent-{host}.sock"),
                None => "agent.sock".to_owned(),
            };
            (cache.join(APP_DIR), file_name)
        }
    };

    ensure_private_dir(&dir)?;
    Ok(dir.join(file_name))
}

/// Binds the agent socket at `path`, replacing a stale socket left behind by a
/// previous run, and restricts it to the owner (`0600`).
///
/// Refuses to start if another agent is still answering on `path`, or if
/// `path` exists but isn't a socket.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    if path.as_os_str().len() >= SUN_PATH_LEN {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "socket path {} is longer than the {} byte limit for Unix sockets",
                path.display(),
                SUN_PATH_LEN - 1
            ),
        ));
    }

    remove_stale(path)?;
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn remove_stale(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
        Ok(meta) if !meta.file_type().is_socket() => {
            return Err(io::Error::new(
                ErrorKind::AlreadyExists,
                format!(
                    "{} exists and is not a socket; refusing to remove it",
                    path.display()
                ),
            ));
        }
        Ok(_) => {}
    }

    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => Err(io::Error::new(
            ErrorKind::AddrInUse,
            format!("another agent is already listening on {}", path.display()),
        )),
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => fs::remove_file(path),
        Err(e) => Err(e),
    }
}

/// Creates `dir` with mode `0700` if missing, then checks that it is a real
/// directory (not a symlink) owned by us and inaccessible to anyone else.
fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent)?;
    }
    match DirBuilder::new().mode(0o700).create(dir) {
        Err(e) if e.kind() != ErrorKind::AlreadyExists => return Err(e),
        _ => {}
    }

    let meta = fs::symlink_metadata(dir)?;
    // SAFETY: getuid() has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    let insecure = if !meta.file_type().is_dir() {
        Some("is not a directory")
    } else if meta.uid() != uid {
        Some("is not owned by the current user")
    } else if meta.mode() & 0o077 != 0 {
        Some("is accessible to other users (expected mode 0700)")
    } else {
        None
    };

    match insecure {
        Some(reason) => Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!("socket directory {} {reason}", dir.display()),
        )),
        None => Ok(()),
    }
}

/// Reads an environment variable holding a directory, ignoring unset, empty
/// or relative values (as the XDG Base Directory spec requires).
fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

fn hostname() -> Option<String> {
    let host = fs::read_to_string("/proc/sys/kernel/hostname").ok()?;
    let host = host.trim();
    (!host.is_empty() && !host.contains('/')).then(|| host.to_owned())
}
