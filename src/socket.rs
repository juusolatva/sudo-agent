//! Socket placement and setup, for `agent.sock` and `control.sock`.
//!
//! The default location is `$XDG_RUNTIME_DIR/sudo-agent/<name>.sock`
//! (per-user, `0700`, tmpfs, cleared on logout). When that isn't set (`su`,
//! containers, WSL, non-systemd sessions) we fall back to
//! `${XDG_CACHE_HOME:-$HOME/.cache}/sudo-agent/<name>-<hostname>.sock`; the
//! hostname suffix keeps machines sharing an NFS home from clobbering each
//! other's sockets.

use std::ffi::OsString;
use std::fs::{self, DirBuilder, Permissions};
use std::io::{self, ErrorKind};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use socket2::{Domain, SockAddr, Socket, Type};
use tokio::net::UnixListener;

const APP_DIR: &str = "sudo-agent";

/// Size of `sockaddr_un.sun_path` on Linux, including the trailing NUL.
const SUN_PATH_LEN: usize = 108;

/// Environment variable naming the agent socket (overridden by
/// `--agent-socket`).
pub const AGENT_SOCKET_ENV: &str = "SUDO_AGENT_SOCKET";

/// Environment variable naming the control socket (overridden by
/// `--control-socket`).
pub const CONTROL_SOCKET_ENV: &str = "SUDO_AGENT_CONTROL_SOCKET";

/// Picks a socket path: `flag` if given, else `env_value` if set and
/// non-empty (an empty variable counts as unset), else `default()`.
pub fn choose_path(
    flag: Option<PathBuf>,
    env_value: Option<OsString>,
    default: impl FnOnce() -> io::Result<PathBuf>,
) -> io::Result<PathBuf> {
    let env_path = env_value.filter(|v| !v.is_empty()).map(PathBuf::from);
    match flag.or(env_path) {
        Some(path) => Ok(path),
        None => default(),
    }
}

/// Returns the default path of the `name` socket (`agent` or `control`),
/// creating its parent directory with mode `0700` and verifying
/// ownership/permissions if it already exists.
pub fn default_path(name: &str) -> io::Result<PathBuf> {
    let (dir, file_name) = match env_dir("XDG_RUNTIME_DIR") {
        Some(runtime) => (runtime.join(APP_DIR), format!("{name}.sock")),
        None => {
            let cache = env_dir("XDG_CACHE_HOME")
                .or_else(|| env_dir("HOME").map(|home| home.join(".cache")))
                .ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::NotFound,
                        format!(
                            "none of XDG_RUNTIME_DIR, XDG_CACHE_HOME or HOME is set; \
                             use --{name}-socket"
                        ),
                    )
                })?;
            let file_name = match hostname() {
                Some(host) => format!("{name}-{host}.sock"),
                None => format!("{name}.sock"),
            };
            (cache.join(APP_DIR), file_name)
        }
    };

    ensure_private_dir(&dir)?;
    Ok(dir.join(file_name))
}

/// Binds the agent socket at `path`, replacing a stale socket left behind by a
/// previous run, and restricts it to the owner (`0600`). The socket file is
/// removed again when the returned [`SocketFile`] is dropped.
///
/// Refuses to start if another agent is still answering on `path`, or if
/// `path` exists but isn't a socket.
pub fn bind(path: &Path) -> io::Result<(UnixListener, SocketFile)> {
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
    let listener = listen_private(path)?;
    let file = SocketFile::new(path)?;
    // Already so; a cheap check that it stays that way.
    fs::set_permissions(path, Permissions::from_mode(0o600))?;
    Ok((listener, file))
}

/// Listens on a new socket at `path`, created with mode `0600`: Linux gives
/// the socket file the mode set on the socket before `bind` (minus the
/// umask). Binding first and changing the mode after would leave a moment in
/// which others could connect, and such a connection would stay open; that
/// matters for a `--agent-socket` or `--control-socket` path in a shared
/// directory such as `/tmp` (the default directory is private anyway).
fn listen_private(path: &Path) -> io::Result<UnixListener> {
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    // SAFETY: the descriptor is valid for as long as `socket` lives.
    if unsafe { libc::fchmod(socket.as_raw_fd(), 0o600) } != 0 {
        return Err(io::Error::last_os_error());
    }
    socket.bind(&SockAddr::unix(path)?)?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    UnixListener::from_std(socket.into())
}

/// The socket file this process bound; removed on drop.
pub struct SocketFile {
    path: PathBuf,
    /// `(st_dev, st_ino)` at bind time. If something else has since replaced
    /// the file (e.g. another instance started after this one's was deleted),
    /// it is left alone.
    id: (u64, u64),
}

impl SocketFile {
    fn new(path: &Path) -> io::Result<Self> {
        let meta = fs::symlink_metadata(path)?;
        Ok(Self {
            path: path.to_owned(),
            id: (meta.dev(), meta.ino()),
        })
    }
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        let ours =
            fs::symlink_metadata(&self.path).is_ok_and(|meta| (meta.dev(), meta.ino()) == self.id);
        if ours {
            let _ = fs::remove_file(&self.path);
        }
    }
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
    // The effective uid, which owns the files we create; `control.sock`
    // compares peers with it too.
    // SAFETY: geteuid() has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_beats_environment_beats_default() {
        let default = || Ok(PathBuf::from("default.sock"));
        let flag = || Some(PathBuf::from("flag.sock"));
        let env = |v: &str| Some(OsString::from(v));
        let choose = |flag, env| choose_path(flag, env, default).unwrap();

        assert_eq!(choose(flag(), env("env.sock")), PathBuf::from("flag.sock"));
        assert_eq!(choose(None, env("env.sock")), PathBuf::from("env.sock"));
        assert_eq!(choose(None, None), PathBuf::from("default.sock"));
        assert_eq!(choose(None, env("")), PathBuf::from("default.sock"));
        // The default (which creates a directory) isn't even computed when
        // a path was given.
        let unreachable = || -> io::Result<PathBuf> { panic!("default computed") };
        choose_path(flag(), None, unreachable).unwrap();
    }

    /// Without the mode set before `bind`, the usual umask (022) would give
    /// `0755` until the `chmod`.
    #[tokio::test]
    async fn socket_is_created_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let _listener = listen_private(&path).unwrap();
        let mode = fs::symlink_metadata(&path).unwrap().mode();
        assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
    }

    #[tokio::test]
    async fn socket_file_is_removed_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let (listener, file) = bind(&path).unwrap();
        assert!(path.exists());
        drop(listener);
        drop(file);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn replaced_socket_file_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let (_listener, file) = bind(&path).unwrap();
        fs::remove_file(&path).unwrap();
        fs::write(&path, "someone else's").unwrap();
        drop(file);
        assert!(path.exists());
    }
}
