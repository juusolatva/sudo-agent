//! Socket placement and setup, for `agent.sock` and `control.sock`.
//!
//! The default location is `$XDG_RUNTIME_DIR/sudo-agent/<name>.sock`
//! (per-user, `0700`, tmpfs, cleared on logout). When that isn't set (`su`,
//! containers, WSL, non-systemd sessions) we fall back to
//! `${XDG_CACHE_HOME:-$HOME/.cache}/sudo-agent/<name>-<hostname>.sock`; the
//! hostname suffix keeps machines sharing an NFS home from clobbering each
//! other's sockets.

use std::ffi::OsString;
use std::fs::{self, DirBuilder};
use std::io::{self, ErrorKind};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt};
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
    let (dir, file_name) = default_location(name, |var| std::env::var_os(var), hostname)?;
    ensure_private_dir(&dir)?;
    Ok(dir.join(file_name))
}

/// The default path of the `name` socket for a client: like
/// [`default_path`], but creates nothing (no agent has, if the directory is
/// missing).
pub fn default_client_path(name: &str) -> io::Result<PathBuf> {
    let (dir, file_name) = default_location(name, |var| std::env::var_os(var), hostname)?;
    Ok(dir.join(file_name))
}

/// The directory and file name of the default `name` socket, given a way to
/// read environment variables (`var`) and the hostname. Touches nothing.
fn default_location(
    name: &str,
    var: impl Fn(&str) -> Option<OsString>,
    hostname: impl FnOnce() -> Option<String>,
) -> io::Result<(PathBuf, String)> {
    let dir = |variable: &str| env_dir(var(variable));
    let location = match dir("XDG_RUNTIME_DIR") {
        Some(runtime) => (runtime.join(APP_DIR), format!("{name}.sock")),
        None => {
            let cache = dir("XDG_CACHE_HOME")
                .or_else(|| dir("HOME").map(|home| home.join(".cache")))
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
    Ok(location)
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

    check_location(path)?;
    remove_stale(path)?;
    let listener = listen_private(path)?;
    let file = SocketFile::new(path)?;
    // Already so; a cheap check (that follows no symlink) that it stays so.
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_socket() || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!("{} isn't a private socket after binding", path.display()),
        ));
    }
    Ok((listener, file))
}

/// Checks that only we (or root) can change what `path` names: its
/// directory must be ours and writable by no one else, and every directory
/// above it owned by us or root and writable by no one else unless sticky
/// (like `/tmp`, where others can't rename what's ours). Otherwise another
/// user could put their own socket there, and `ssh-add` would hand it a
/// key. Applies to every socket path, given or default.
pub fn check_location(path: &Path) -> io::Result<()> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let dir = fs::canonicalize(dir).map_err(|e| {
        io::Error::new(e.kind(), format!("socket directory {}: {e}", dir.display()))
    })?;
    // SAFETY: geteuid() has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    for (i, ancestor) in dir.ancestors().enumerate() {
        let meta = fs::metadata(ancestor)?;
        let place = if i == 0 { Place::Socket } else { Place::Above };
        if let Some(reason) = unsafe_dir(place, meta.uid(), meta.mode(), uid) {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "{} is unsafe for a socket: {} {reason}",
                    path.display(),
                    ancestor.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Where a directory is on the way to a socket.
#[derive(Clone, Copy, PartialEq)]
enum Place {
    /// The socket's own directory.
    Socket,
    /// One above it.
    Above,
}

/// Why a directory (owned by `owner`, with `mode`) at `place` lets someone
/// other than user `uid` or root replace the socket, if it does.
fn unsafe_dir(place: Place, owner: u32, mode: u32, uid: u32) -> Option<&'static str> {
    let writable_by_others = mode & 0o022 != 0;
    let sticky = mode & libc::S_ISVTX != 0;
    match place {
        Place::Socket if owner != uid => Some("is not owned by the current user"),
        Place::Socket if writable_by_others => Some("is writable by other users"),
        Place::Above if owner != uid && owner != 0 => Some("is owned by another user"),
        Place::Above if writable_by_others && !sticky => {
            Some("is writable by other users (and not sticky)")
        }
        _ => None,
    }
}

/// Whether `a` and `b` name the same socket, though spelled differently
/// (`./a.sock` and `a.sock`, or through a symlinked directory).
pub fn same_path(a: &Path, b: &Path) -> bool {
    let resolved = |path: &Path| {
        let dir = match path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir,
            _ => Path::new("."),
        };
        Some((fs::canonicalize(dir).ok()?, path.file_name()?.to_owned()))
    };
    match (resolved(a), resolved(b)) {
        (Some(a), Some(b)) => a == b,
        _ => a == b,
    }
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

    // Non-blocking, so a listener that doesn't accept (stopped, with a full
    // backlog) can't hang startup: that's an answer too.
    let probe = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    probe.set_nonblocking(true)?;
    match probe.connect(&SockAddr::unix(path)?) {
        Ok(()) => Err(in_use(path)),
        Err(e) if e.kind() == ErrorKind::WouldBlock => Err(in_use(path)),
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => fs::remove_file(path),
        Err(e) => Err(e),
    }
}

fn in_use(path: &Path) -> io::Error {
    io::Error::new(
        ErrorKind::AddrInUse,
        format!("another agent is already listening on {}", path.display()),
    )
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

/// The value of an environment variable holding a directory, ignoring unset,
/// empty or relative values (as the XDG Base Directory spec requires).
fn env_dir(value: Option<OsString>) -> Option<PathBuf> {
    value.map(PathBuf::from).filter(|path| path.is_absolute())
}

fn hostname() -> Option<String> {
    usable_hostname(&fs::read_to_string("/proc/sys/kernel/hostname").ok()?)
}

/// `raw` trimmed, unless that leaves nothing or something that can't be part
/// of a file name.
fn usable_hostname(raw: &str) -> Option<String> {
    let host = raw.trim();
    (!host.is_empty() && !host.contains('/')).then(|| host.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;

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

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().mode() & 0o777
    }

    #[test]
    fn unsafe_directories_are_named() {
        let me = 1000;
        let ok = |place, owner, mode| unsafe_dir(place, owner, mode, me).is_none();
        // The socket's own directory: ours, writable only by us.
        assert!(ok(Place::Socket, me, 0o700));
        assert!(ok(Place::Socket, me, 0o755));
        assert!(!ok(Place::Socket, 0, 0o755));
        assert!(!ok(Place::Socket, 1001, 0o700));
        assert!(!ok(Place::Socket, me, 0o770));
        assert!(!ok(Place::Socket, me, 0o1777));
        // Those above: ours or root's, writable by others only if sticky.
        assert!(ok(Place::Above, 0, 0o755));
        assert!(ok(Place::Above, me, 0o700));
        assert!(ok(Place::Above, 0, 0o1777)); // /tmp
        assert!(!ok(Place::Above, 0, 0o777));
        assert!(!ok(Place::Above, me, 0o775));
        assert!(!ok(Place::Above, 1001, 0o755));
    }

    #[test]
    fn sockets_go_only_where_no_one_else_can_replace_them() {
        let dir = tempfile::tempdir().unwrap();
        let ours = dir.path().join("ours");
        fs::create_dir(&ours).unwrap();
        fs::set_permissions(&ours, Permissions::from_mode(0o755)).unwrap();
        check_location(&ours.join("agent.sock")).unwrap();

        // Writable by others: refused, whether the socket's directory or
        // one above it (without the sticky bit).
        let shared = dir.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, Permissions::from_mode(0o777)).unwrap();
        let below = shared.join("below");
        fs::create_dir(&below).unwrap();
        fs::set_permissions(&below, Permissions::from_mode(0o700)).unwrap();
        for path in [shared.join("agent.sock"), below.join("agent.sock")] {
            let err = check_location(&path).unwrap_err();
            assert_eq!(
                err.kind(),
                ErrorKind::PermissionDenied,
                "{}",
                path.display()
            );
            assert!(err.to_string().contains("shared"), "{err}");
            // bind refuses before touching anything.
            assert_eq!(
                bind(&path).err().unwrap().kind(),
                ErrorKind::PermissionDenied
            );
            assert!(!path.exists());
        }
        // With the sticky bit, a private directory inside is fine.
        fs::set_permissions(&shared, Permissions::from_mode(0o1777)).unwrap();
        check_location(&below.join("agent.sock")).unwrap();
        // A missing directory is an error of its own kind.
        let err = check_location(&ours.join("missing").join("agent.sock")).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }

    #[test]
    fn same_socket_however_spelled() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&sub, &link).unwrap();
        assert!(same_path(&sub.join("a.sock"), &link.join("a.sock")));
        assert!(same_path(
            &sub.join("a.sock"),
            &sub.join(".").join("a.sock")
        ));
        assert!(!same_path(&sub.join("a.sock"), &sub.join("b.sock")));
        assert!(same_path(Path::new("a.sock"), Path::new("./a.sock")));
    }

    #[test]
    fn busy_socket_counts_as_live_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        // Listening, never accepting, with the smallest backlog: fill it.
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
        socket.bind(&SockAddr::unix(&path).unwrap()).unwrap();
        socket.listen(0).unwrap();
        let mut fillers = Vec::new();
        loop {
            let filler = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
            filler.set_nonblocking(true).unwrap();
            if filler.connect(&SockAddr::unix(&path).unwrap()).is_err() {
                break;
            }
            fillers.push(filler);
        }
        // On a thread, so a blocking connect would show as a timeout here.
        let (sender, receiver) = std::sync::mpsc::channel();
        let probed = path.clone();
        std::thread::spawn(move || sender.send(remove_stale(&probed)));
        let err = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("didn't hang")
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::AddrInUse);
        assert!(path.exists());
    }

    #[test]
    fn missing_directory_is_created_private() {
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("cache").join(APP_DIR);
        ensure_private_dir(&private).unwrap();
        assert!(private.is_dir());
        assert_eq!(mode(&private), 0o700);
        // And an existing private one is accepted as it is.
        ensure_private_dir(&private).unwrap();
    }

    #[test]
    fn directory_open_to_others_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let open = dir.path().join(APP_DIR);
        fs::create_dir(&open).unwrap();
        for mode in [0o750, 0o705, 0o755, 0o777] {
            fs::set_permissions(&open, Permissions::from_mode(mode)).unwrap();
            let err = ensure_private_dir(&open).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::PermissionDenied, "mode {mode:o}");
        }
        // Refusing doesn't tighten the mode behind the user's back.
        assert_eq!(mode(&open), 0o777);
    }

    #[test]
    fn symlink_or_file_instead_of_a_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, Permissions::from_mode(0o700)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let file = dir.path().join("file");
        fs::write(&file, "").unwrap();

        for path in [&link, &file] {
            let err = ensure_private_dir(path).unwrap_err();
            assert_eq!(
                err.kind(),
                ErrorKind::PermissionDenied,
                "{}",
                path.display()
            );
            assert!(err.to_string().contains("is not a directory"), "{err}");
        }
    }

    #[test]
    fn runtime_dir_beats_cache_home_beats_home() {
        let place = |vars: &[(&str, &str)], host: Option<&str>| {
            let vars: Vec<(String, OsString)> = vars
                .iter()
                .map(|(k, v)| (k.to_string(), OsString::from(v)))
                .collect();
            let var = |name: &str| vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
            let (dir, file) = default_location("agent", var, || host.map(String::from))?;
            Ok::<_, io::Error>(dir.join(file))
        };
        let path = |s: &str| PathBuf::from(s);
        let all = [
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ("XDG_CACHE_HOME", "/home/me/cache"),
            ("HOME", "/home/me"),
        ];

        // The runtime directory is per-machine already: no hostname.
        let got = place(&all, Some("laptop")).unwrap();
        assert_eq!(got, path("/run/user/1000/sudo-agent/agent.sock"));
        let got = place(&all[1..], Some("laptop")).unwrap();
        assert_eq!(got, path("/home/me/cache/sudo-agent/agent-laptop.sock"));
        let got = place(&all[2..], Some("laptop")).unwrap();
        assert_eq!(got, path("/home/me/.cache/sudo-agent/agent-laptop.sock"));
        let got = place(&all[2..], None).unwrap();
        assert_eq!(got, path("/home/me/.cache/sudo-agent/agent.sock"));

        // Empty and relative values count as unset.
        let ignored = [
            ("XDG_RUNTIME_DIR", ""),
            ("XDG_CACHE_HOME", "relative/cache"),
            ("HOME", "/home/me"),
        ];
        let got = place(&ignored, None).unwrap();
        assert_eq!(got, path("/home/me/.cache/sudo-agent/agent.sock"));

        let err = place(&[("HOME", "")], None).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
        assert!(err.to_string().contains("--agent-socket"), "{err}");
    }

    #[test]
    fn hostname_must_make_a_file_name() {
        assert_eq!(usable_hostname("laptop\n").as_deref(), Some("laptop"));
        assert_eq!(usable_hostname(" \n"), None);
        assert_eq!(usable_hostname("../../etc"), None);
    }

    /// A socket left behind by a run that didn't clean up (`std`'s listener
    /// doesn't remove its file).
    fn dead_socket(path: &Path) {
        drop(std::os::unix::net::UnixListener::bind(path).unwrap());
        assert!(fs::symlink_metadata(path).unwrap().file_type().is_socket());
    }

    #[tokio::test]
    async fn stale_socket_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        dead_socket(&path);
        let (_listener, _file) = bind(&path).unwrap();
        tokio::net::UnixStream::connect(&path).await.unwrap();
    }

    #[tokio::test]
    async fn live_socket_is_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let (_listener, _file) = bind(&path).unwrap();
        let err = bind(&path).err().unwrap();
        assert_eq!(err.kind(), ErrorKind::AddrInUse);
        // The first agent still answers.
        tokio::net::UnixStream::connect(&path).await.unwrap();
    }

    #[tokio::test]
    async fn something_else_at_the_path_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("agent.sock");
        fs::write(&file, "not a socket").unwrap();
        // A symlink to a dead socket isn't followed, nor removed.
        let socket = dir.path().join("dead.sock");
        dead_socket(&socket);
        let link = dir.path().join("link.sock");
        std::os::unix::fs::symlink(&socket, &link).unwrap();

        for path in [&file, &link] {
            let err = bind(path).err().unwrap();
            assert_eq!(err.kind(), ErrorKind::AlreadyExists, "{}", path.display());
        }
        assert_eq!(fs::read_to_string(&file).unwrap(), "not a socket");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            fs::symlink_metadata(&socket)
                .unwrap()
                .file_type()
                .is_socket()
        );
    }

    #[tokio::test]
    async fn too_long_path_is_refused_before_touching_anything() {
        let dir = tempfile::tempdir().unwrap();
        let name = "s".repeat(SUN_PATH_LEN);
        let path = dir.path().join(name);
        let err = bind(&path).err().unwrap();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(!path.exists());
    }
}
