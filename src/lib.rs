#![allow(clippy::needless_doctest_main)]
//! Small crate which helps with writing daemon applications in Rust.
//!
//! I am aware about [daemonize](https://crates.io/crates/daemonize) and
//! [daemonize-me](https://crates.io/crates/daemonize-me) crates, but needed some
//! extended functionality like locking PID file and searching for running daemon.
//!
//! Complete example:
//!
//! ```rust,no_run
//! use daemonizr::{Daemonizr, DaemonizrError, Group, Stderr, Stdout, User};
//! use std::{path::PathBuf, process::exit, thread::sleep, time::Duration};
//!
//! fn main() {
//!     match Daemonizr::new()
//!         .work_dir(PathBuf::from("/Users/alex/git/private/daemonizr"))
//!         .expect("invalid path")
//!         .as_user(User::by_name("alex").expect("invalid user"))
//!         .as_group(Group::by_name("staff").expect("invalid group"))
//!         .pidfile(PathBuf::from("dmnzr.pid"))
//!         .stdout(Stdout::Redirect(PathBuf::from("dmnzr.out")))
//!         .stderr(Stderr::Redirect(PathBuf::from("dmnzr.err")))
//!         .umask(0o027)
//!         .expect("invalid umask")
//!         .spawn()
//!     {
//!         Err(DaemonizrError::AlreadyRunning) => {
//!             /* search for the daemon's PID  */
//!             match Daemonizr::new()
//!                 .work_dir(PathBuf::from("/Users/alex/git/private/daemonizr"))
//!                 .unwrap()
//!                 .pidfile(PathBuf::from("dmnzr.pid"))
//!                 .search()
//!             {
//!                 Err(x) => eprintln!("error: {}", x),
//!                 Ok(pid) => {
//!                     eprintln!("another daemon with pid {} is already running", pid);
//!                     exit(1);
//!                 }
//!             };
//!         }
//!         Err(e) => eprintln!("DaemonizrError: {}", e),
//!         Ok(()) => { /* We are in daemon process now */ }
//!     };
//!
//!     /* actual daemon work goes here */
//!     println!("write something to stdout");
//!     eprintln!("write something to stderr");
//!     sleep(Duration::from_secs(60));
//!     println!("Daemon exits.")
//! }
//! ```
//! Hint:
//! > ⚠️ This crate will only work on POSIX compatible systems,
//! > where the "nix" and "libc" crates are available.
//!
use nix::{
    fcntl::{OFlag, flock, open},
    libc::{
        STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO, getgrgid, getgrnam, getpwnam, getpwuid, mode_t,
    },
    sys::stat::{Mode, umask},
    unistd::{
        Gid, Uid, close, dup, fork, fsync, ftruncate, geteuid, getpid, setgid, setsid, setuid,
        write,
    },
};
use std::os::unix::io::RawFd;
use std::{
    env::{current_dir, set_current_dir},
    error::Error,
    ffi::CString,
    path::PathBuf,
};

/// Daemonizr holds context needed for spawning the daemon process.
///
/// It includes:
/// * working directory of the daemon;
/// * UID and GID to be set to after going daemon;
/// * umask which daemon uses after dropping the privileges;
/// * the PID file to use;
/// * setup for stdout/stderr files
///
#[derive(Debug)]
pub struct Daemonizr {
    work_dir: PathBuf,
    user: User,
    group: Group,
    umask: Mode,
    pidfile: PathBuf,
    stdout: Stdout,
    stderr: Stderr,
    fd_lock: RawFd,
}

/// Super
impl Daemonizr {
    /// Creates a new default Daemonizr context with following attributes:
    ///
    /// * current directory is used as working directory;
    /// * current user and his default group used for daemon;
    /// * the [umask()](https://man7.org/linux/man-pages/man2/umask.2.html) is set to 0 (means creation mode = 777);
    /// * PID file "daemonizr.pid" in current directory is used as PID file;
    /// * the stdout and stderr are both closed.
    ///
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let work_dir = current_dir().expect("unable to get current working directory");
        let (user, group) = whoami().expect("unable to determine current user");
        let pidfile = work_dir.clone().join("daemonizr.pid");
        let umask = Mode::from_bits(0o027).expect("invalid bit mask: 0o027");
        Daemonizr {
            work_dir,
            user,
            group,
            umask,
            pidfile,
            stdout: Stdout::Close,
            stderr: Stderr::Close,
            fd_lock: -1 as RawFd,
        }
    }

    /// Path to working directory for the daemon, this path must be a directory,
    /// must exist AND be an absolute path.
    pub fn work_dir(mut self, work_dir: PathBuf) -> Result<Self, DaemonizrError> {
        if !work_dir.is_absolute() {
            return Err(DaemonizrError::WorkDirNotAbsolute(work_dir));
        }
        if !work_dir.exists() {
            return Err(DaemonizrError::WorkDirNotExists(work_dir));
        }
        if !work_dir.is_dir() {
            return Err(DaemonizrError::WorkDirNotDir(work_dir));
        }
        self.work_dir = work_dir;

        Ok(self)
    }

    /// User to be set after going daemon
    pub fn as_user(mut self, user: User) -> Self {
        self.user = user;
        self
    }

    /// Group to be set after going daemon
    pub fn as_group(mut self, group: Group) -> Self {
        self.group = group;
        self
    }

    /// Umask to use for daemon
    pub fn umask(mut self, umask: u16) -> Result<Self, DaemonizrError> {
        match Mode::from_bits(umask as mode_t) {
            Some(x) => {
                self.umask = x;
                Ok(self)
            }
            None => Err(DaemonizrError::InvalidUmask(umask)),
        }
    }

    /// Path for the pidfile. If path is a relative path, it is assumed
    /// to be relative to the working directory.
    pub fn pidfile(mut self, pidfile: PathBuf) -> Self {
        self.pidfile = if pidfile.is_relative() {
            self.work_dir.clone().join(pidfile)
        } else {
            pidfile
        };
        self
    }

    /// Set behaviour for standard output: close or redirect to the given path.
    pub fn stdout(mut self, s: Stdout) -> Self {
        self.stdout = match s {
            Stdout::Close => s,
            Stdout::Redirect(x) => {
                if x.is_absolute() {
                    Stdout::Redirect(x)
                } else {
                    Stdout::Redirect(self.work_dir.clone().join(x))
                }
            }
        };
        self
    }

    /// Set behaviour for standard error: close or redirect to the given path.
    pub fn stderr(mut self, s: Stderr) -> Self {
        self.stderr = match s {
            Stderr::Close => s,
            Stderr::Redirect(x) => {
                if x.is_absolute() {
                    Stderr::Redirect(x)
                } else {
                    Stderr::Redirect(self.work_dir.clone().join(x))
                }
            }
        };
        self
    }

    /// Truncates the already-open, already-locked PID file and writes the current
    /// process's PID to it.  The file descriptor in `self.fd_lock` must have been
    /// opened and had an exclusive advisory `flock` acquired on it *before* this
    /// method is called (i.e. before the `fork`, so the lock is inherited by the
    /// child and survives the parent's exit).
    fn write_pid_file(&mut self) -> Result<(), DaemonizrError> {
        // Clear previous content so no stale bytes remain after a shorter PID.
        if let Err(e) = ftruncate(self.fd_lock, 0) {
            return Err(DaemonizrError::FailedToWritePidfile(e.to_string()));
        }

        // Write the daemon's own PID.
        let pid = getpid();
        let pidb = format!("{}\n", pid.as_raw());
        if let Err(e) = write(self.fd_lock, pidb.as_bytes()) {
            return Err(DaemonizrError::FailedToWritePidfile(e.to_string()));
        }

        // Flush to storage so that the PID is visible to readers immediately.
        if let Err(e) = fsync(self.fd_lock) {
            return Err(DaemonizrError::FailedToWritePidfile(e.to_string()));
        }

        Ok(())
    }

    /// Perform the actual creation of a daemon process.
    /// In case of success, this function never returns - the parent process will exit with
    /// exit code 0 (success), the child (daemon) process will
    pub fn spawn(mut self) -> Result<(), DaemonizrError> {
        // Open the PID file and acquire an exclusive advisory lock BEFORE forking.
        //
        // Advisory flock(2) semantics: the lock is associated with an open file
        // description, not a process.  After fork(2) the child inherits the file
        // descriptor which refers to the same open file description as the parent's
        // copy.  When the parent exits and closes its copy the lock is NOT released
        // because the child still holds a reference to the same file description.
        // The lock is released automatically by the kernel only when every file
        // descriptor that refers to the file description has been closed – i.e. when
        // the daemon process terminates (normally or via a crash).
        self.fd_lock = match open(
            &self.pidfile,
            OFlag::O_CREAT | OFlag::O_RDWR,
            Mode::from_bits(0o666).expect("invalid mode 0o666"),
        ) {
            Err(e) => return Err(DaemonizrError::FailedCreatePidfile(e.to_string())),
            Ok(fd) => fd,
        };

        // Attempt a non-blocking exclusive lock.  EWOULDBLOCK means another
        // cooperating process already holds the lock → another instance is running.
        // Any other error is an unexpected locking failure.
        match flock(self.fd_lock, nix::fcntl::FlockArg::LockExclusiveNonblock) {
            Err(nix::errno::Errno::EWOULDBLOCK) => {
                let _ = close(self.fd_lock);
                return Err(DaemonizrError::AlreadyRunning);
            }
            Err(e) => {
                let _ = close(self.fd_lock);
                return Err(DaemonizrError::ErrorLockingPidfile(e.to_string()));
            }
            Ok(_) => {}
        }

        // fork daemon
        match unsafe { fork() } {
            Ok(nix::unistd::ForkResult::Parent { .. }) => {
                // Parent exits.  The child inherited fd_lock (same open file
                // description), so the advisory lock remains held by the child
                // for the entire daemon lifetime.
                std::process::exit(0)
            }
            Ok(nix::unistd::ForkResult::Child) => {
                // Child is the daemon; fd_lock is inherited and the lock is held.
            }
            Err(e) => return Err(DaemonizrError::ForkFailed(e.to_string())),
        }

        // setsuid() - obtain new process group
        if let Err(e) = setsid() {
            return Err(DaemonizrError::FailedToSetsid(e.to_string()));
        }

        // setgid()
        match self.group {
            Group::Id(g) => {
                if let Err(e) = setgid(Gid::from_raw(g)) {
                    return Err(DaemonizrError::FailedToSetGroup(g, e.to_string()));
                }
            }
        }

        // setuid()
        match self.user {
            User::Id(u) => {
                if let Err(e) = setuid(Uid::from_raw(u)) {
                    return Err(DaemonizrError::FailedToSetUser(u, e.to_string()));
                }
            }
        }

        // close stdin/stdout/stderr
        if close(STDIN_FILENO).is_err() { /* cannot be handled */ } // 0 - stdin
        if close(STDOUT_FILENO).is_err() { /* cannot be handled */ }; // 1 - stdout
        if close(STDERR_FILENO).is_err() { /* cannot be handled */ }; // 2 - stderr

        // set umask
        umask(self.umask);

        // set working directory
        if let Err(e) = set_current_dir(&self.work_dir) {
            return Err(DaemonizrError::FailedSetWorkDir(
                self.work_dir.clone().display().to_string(),
                e.to_string(),
            ));
        }

        // open stdin (always as /dev/null)
        let stdi = match open(
            &PathBuf::from("/dev/null"),
            OFlag::O_RDWR,
            Mode::from_bits(0o666).expect("invalid mode 0o666"),
        ) {
            Err(e) => {
                return Err(DaemonizrError::FailedToReopen(
                    "stdin".to_owned(),
                    e.to_string(),
                ));
            }
            Ok(x) => x,
        };

        // open stdout
        let stdo = match self.stdout {
            Stdout::Close => dup(stdi),
            Stdout::Redirect(ref f) => open(
                f,
                OFlag::O_CREAT | OFlag::O_RDWR | OFlag::O_APPEND,
                Mode::from_bits(0o666).expect("invalid mode 0o666"),
            ),
        };

        if let Err(e) = stdo {
            return Err(DaemonizrError::FailedToReopen(
                "stdout".to_owned(),
                e.to_string(),
            ));
        }

        // open stderr
        let stde = match self.stderr {
            Stderr::Close => dup(stdi),
            Stderr::Redirect(ref f) => open(
                f,
                OFlag::O_CREAT | OFlag::O_RDWR | OFlag::O_APPEND,
                Mode::from_bits(0o666).expect("invalid mode 0o666"),
            ),
        };

        if let Err(e) = stde {
            return Err(DaemonizrError::FailedToReopen(
                "stderr".to_owned(),
                e.to_string(),
            ));
        }

        // Write the daemon's own PID to the PID file.  The file descriptor is
        // already open and the exclusive advisory lock is held; just truncate,
        // write the PID, and fsync so that the PID is durable on disk.
        self.write_pid_file()?;

        Ok(())
    }

    /// Search for PID of an already spawned daemon. If one is present,
    /// its PID is returned, otherwise an error is returned.
    ///
    /// The advisory `flock(2)` lock on the PID file is the authoritative signal
    /// that a daemon is running – not the file contents.  PID contents are only
    /// read after the lock check confirms that the file is currently locked by
    /// another cooperating process.
    ///
    /// Hint: for search, you'll need to set at least absolute path with [`Self::pidfile()`],
    /// or, set absolute path using [`Self::work_dir()`] in conjuction with setting a relative
    /// path using [`Self::pidfile()`].
    pub fn search(self) -> Result<u32, DaemonizrError> {
        if !self.pidfile.exists() {
            return Err(DaemonizrError::NoDaemonFound);
        }

        let pf_fd = match open(
            &self.pidfile,
            OFlag::O_RDONLY,
            Mode::from_bits(0o666).expect("invalid mode 0o666"),
        ) {
            Err(e) => return Err(DaemonizrError::FailedToOpenPidfile(e.to_string())),
            Ok(fd) => fd,
        };

        // Try to acquire an exclusive non-blocking lock.
        //
        // * Success     → we got the lock, meaning no cooperating process holds it.
        //                 The PID file is stale (daemon has exited).  Close and report
        //                 NoDaemonFound.
        // * EWOULDBLOCK → another process holds the lock: the daemon is running.
        //                 Read the PID to report it.
        // * Other error → unexpected; propagate.
        match flock(pf_fd, nix::fcntl::FlockArg::LockExclusiveNonblock) {
            Ok(_) => {
                // Stale PID file – no daemon is running.
                let _ = close(pf_fd);
                return Err(DaemonizrError::NoDaemonFound);
            }
            Err(nix::errno::Errno::EWOULDBLOCK) => {
                // Daemon is running; fall through to read its PID.
            }
            Err(e) => {
                let _ = close(pf_fd);
                return Err(DaemonizrError::ErrorLockingPidfile(e.to_string()));
            }
        }

        // The lock is held by the daemon – read the PID it wrote.
        let mut buf: [u8; 16] = [0; 16];
        let n = match nix::unistd::read(pf_fd, &mut buf) {
            Err(e) => {
                let _ = close(pf_fd);
                return Err(DaemonizrError::FailedToReadPidfile(e.to_string()));
            }
            Ok(n) => n,
        };

        let _ = close(pf_fd);

        if n == 0 {
            return Err(DaemonizrError::FailedToReadPidfile(
                "pid file is empty".to_owned(),
            ));
        }

        let s = match std::str::from_utf8(&buf[..n]) {
            Err(e) => return Err(DaemonizrError::FailedToReadPidfile(e.to_string())),
            Ok(s) => s.trim(),
        };

        match s.parse::<u32>() {
            Err(_) => Err(DaemonizrError::FailedToReadPidfile(
                format!("invalid pid: {s}").to_owned(),
            )),
            Ok(pid) => Ok(pid),
        }
    }
}

/// Determines behaviour for "stdout" file descriptor
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum Stdout {
    /// stdout will be closed
    Close,
    /// stdout will be redirected to file
    Redirect(PathBuf),
}

/// Determines behaviour for "stderr" file descriptor
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum Stderr {
    /// stderr will be closed
    Close,
    /// stderr will be redirected to file
    Redirect(PathBuf),
}

#[doc(hidden)]
/// Internal function to determine current user and group IDs
fn whoami() -> Result<(User, Group), DaemonizrError> {
    let uid = geteuid();
    let pwraw = unsafe { getpwuid(uid.as_raw()) };
    if pwraw.is_null() {
        Err(DaemonizrError::NoUserOrGroup)
    } else {
        let gid = unsafe { (*pwraw).pw_gid };
        Ok((User::Id(uid.as_raw()), Group::Id(gid)))
    }
}

/// User object holds a valid user id (UID) to change to after child process has been daemonized.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum User {
    Id(u32),
}
/// Group object holds a valid group id (GID) to change to after child process has been daemonized.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum Group {
    Id(u32),
}

impl User {
    /// Lookup User by given uid.
    pub fn by_uid(uid: u32) -> Result<User, DaemonizrError> {
        unsafe {
            let rawpw = getpwuid(uid);
            if rawpw.is_null() {
                Err(DaemonizrError::InvalidUid(uid))
            } else {
                Ok(User::Id(uid))
            }
        }
    }

    /// Lookup User by given username.
    pub fn by_name(username: &str) -> Result<User, DaemonizrError> {
        unsafe {
            let cs = match CString::new(username) {
                Err(_) => return Err(DaemonizrError::ErrorCString),
                Ok(s) => s,
            };
            let rawpw = getpwnam(cs.as_ptr());
            if rawpw.is_null() {
                Err(DaemonizrError::InvalidUsername(username.to_string()))
            } else {
                Ok(User::Id((*rawpw).pw_uid))
            }
        }
    }
}

impl Group {
    /// Lookup Group by given gid (group id).
    pub fn by_gid(gid: u32) -> Result<Group, DaemonizrError> {
        unsafe {
            let group = getgrgid(gid);
            if group.is_null() {
                Err(DaemonizrError::InvalidGid(gid))
            } else {
                Ok(Group::Id((*group).gr_gid))
            }
        }
    }

    /// Lookup group by given group name.
    pub fn by_name(groupname: &str) -> Result<Group, DaemonizrError> {
        let cs = match CString::new(groupname) {
            Err(_) => return Err(DaemonizrError::ErrorCString),
            Ok(s) => s,
        };
        unsafe {
            let rawpw = getgrnam(cs.as_ptr());
            if rawpw.is_null() {
                Err(DaemonizrError::InvalidGroupname(groupname.to_string()))
            } else {
                Ok(Group::Id((*rawpw).gr_gid))
            }
        }
    }
}

/// Error type reported by daemonizr.
#[derive(Debug)]
pub enum DaemonizrError {
    /// Provided working directory path is not an absolute path
    WorkDirNotAbsolute(PathBuf),
    /// Provided working directory path doesn't exist
    WorkDirNotExists(PathBuf),
    /// Provided working directory path is not a directory
    WorkDirNotDir(PathBuf),
    /// Provided UID is invalid
    InvalidUid(u32),
    /// Provided GID is invalid
    InvalidGid(u32),
    /// Provided umask is invalid
    InvalidUmask(u16),
    /// Provided username is invalid
    InvalidUsername(String),
    /// Provided groupname is invalid
    InvalidGroupname(String),
    /// Internal error while converting [CString]
    ErrorCString,
    /// Failed to determine current user / group
    NoUserOrGroup,
    /// failed to daemonize (fork) process
    ForkFailed(String),
    /// failed to set working directory
    FailedSetWorkDir(String, String),
    /// failed to set user to given uid
    FailedToSetUser(u32, String),
    /// failed to set user to given gid
    FailedToSetGroup(u32, String),
    /// failed to setsid() (obtain new process group)
    FailedToSetsid(String),
    /// failed to reopened given file stream
    FailedToReopen(String, String),
    /// failed to create pidfile
    FailedCreatePidfile(String),
    /// daemon already running (holding lock over pidfile)
    AlreadyRunning,
    /// failed to lock pidfile
    ErrorLockingPidfile(String),
    /// Error while writing pidfile
    FailedToWritePidfile(String),
    /// Error while writing pidfile
    FailedToReadPidfile(String),
    /// Error while writing pidfile
    FailedToOpenPidfile(String),
    /// No daemon found
    NoDaemonFound,
}

impl std::fmt::Display for DaemonizrError {
    /// [std::fmt::Display] trait implementation for DaemonizrError
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonizrError::WorkDirNotAbsolute(m) => {
                write!(f, "working directory is not absolute: {}", m.display())
            }
            DaemonizrError::WorkDirNotExists(m) => {
                write!(f, "working directory does not exist: {}", m.display())
            }
            DaemonizrError::WorkDirNotDir(m) => {
                write!(f, "working directory is not a directory: {}", m.display())
            }
            DaemonizrError::InvalidUid(m) => write!(f, "invalid uid provided: {m}"),
            DaemonizrError::InvalidGid(m) => write!(f, "invalid gid provided: {m}"),
            DaemonizrError::InvalidUmask(u) => write!(f, "invalid umask provided: {u}"),
            DaemonizrError::InvalidUsername(s) => write!(f, "invalid username: {s}"),
            DaemonizrError::InvalidGroupname(s) => write!(f, "invalid groupname: {s}"),
            DaemonizrError::ErrorCString => write!(f, "invalid C string"),
            DaemonizrError::NoUserOrGroup => {
                write!(f, "unable to determine user or group of current user")
            }
            DaemonizrError::ForkFailed(e) => write!(f, "fork failed: {e}"),
            DaemonizrError::FailedSetWorkDir(d, e) => {
                write!(f, "failed to set current directory to {d}: {e}")
            }
            DaemonizrError::FailedToSetUser(u, e) => {
                write!(f, "failed to set user to UID {u}: {e}")
            }
            DaemonizrError::FailedToSetGroup(g, e) => {
                write!(f, "failed to set group to GID {g}: {e}")
            }
            DaemonizrError::FailedToSetsid(s) => write!(f, "failed to setsid(): {s}"),
            DaemonizrError::FailedToReopen(s, e) => write!(f, "failed to reopen {s}: {e}"),
            DaemonizrError::FailedCreatePidfile(s) => write!(f, "failed to create pid file: {s}"),
            DaemonizrError::AlreadyRunning => {
                write!(f, "another daemon is already locking pidfile")
            }
            DaemonizrError::ErrorLockingPidfile(s) => write!(f, "error locking pidfile: {s}"),
            DaemonizrError::FailedToWritePidfile(s) => write!(f, "error writing pidfile: {s}"),
            DaemonizrError::FailedToOpenPidfile(s) => write!(f, "error opening pidfile: {s}"),
            DaemonizrError::FailedToReadPidfile(s) => write!(f, "error reading pidfile: {s}"),
            DaemonizrError::NoDaemonFound => write!(f, "no existing daemon was found"),
        }
    }
}

impl Error for DaemonizrError {
    /// [Error] trait implementation for DaemonizrError
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Returns a path in the system temp directory that is unique to this test
    /// run (includes process ID and test name suffix) to avoid conflicts when
    /// tests run concurrently.
    fn tmp_pidfile(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "daemonizr_test_{}_{}.pid",
            std::process::id(),
            suffix
        ));
        p
    }

    /// Helper: build a minimal Daemonizr configured to use only the given PID file path.
    fn daemonizr_with_pidfile(path: PathBuf) -> Daemonizr {
        Daemonizr::new().pidfile(path)
    }

    /// search() on a path that does not exist at all must return NoDaemonFound.
    #[test]
    fn test_search_no_pidfile_returns_no_daemon_found() {
        let path = tmp_pidfile("nonexistent");
        // Make sure it really does not exist.
        let _ = fs::remove_file(&path);

        let result = daemonizr_with_pidfile(path).search();
        assert!(
            matches!(result, Err(DaemonizrError::NoDaemonFound)),
            "expected NoDaemonFound, got {result:?}"
        );
    }

    /// search() on an existing but *unlocked* PID file (stale after a crash) must
    /// return NoDaemonFound.  This validates the advisory-lock-first check.
    #[test]
    fn test_search_stale_pidfile_returns_no_daemon_found() {
        let path = tmp_pidfile("stale");
        fs::write(&path, "99999\n").expect("could not create stale pid file");

        let result = daemonizr_with_pidfile(path.clone()).search();
        let _ = fs::remove_file(&path);

        assert!(
            matches!(result, Err(DaemonizrError::NoDaemonFound)),
            "expected NoDaemonFound for stale file, got {result:?}"
        );
    }

    /// search() must return the correct PID when a cooperating process holds an
    /// exclusive flock on the PID file (simulating a running daemon).
    #[test]
    fn test_search_locked_pidfile_returns_pid() {
        let path = tmp_pidfile("locked");

        // Simulate a daemon: open, lock, write own PID.
        let fd = open(
            &path,
            OFlag::O_CREAT | OFlag::O_RDWR,
            Mode::from_bits(0o666).expect("invalid mode"),
        )
        .expect("could not open test pid file");
        flock(fd, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .expect("could not lock test pid file");
        let pid = getpid();
        let content = format!("{}\n", pid.as_raw());
        write(fd, content.as_bytes()).expect("could not write test pid");

        let result = daemonizr_with_pidfile(path.clone()).search();

        // Clean up before asserting so the file is removed even on failure.
        let _ = flock(fd, nix::fcntl::FlockArg::Unlock);
        let _ = close(fd);
        let _ = fs::remove_file(&path);

        assert!(
            matches!(result, Ok(p) if p == pid.as_raw() as u32),
            "expected pid {}, got {result:?}",
            pid.as_raw()
        );
    }

    /// Two concurrent calls to flock with LockExclusiveNonblock on the same file
    /// must behave as advisory: the second must fail with EWOULDBLOCK.
    #[test]
    fn test_flock_second_lock_is_ewouldblock() {
        let path = tmp_pidfile("flock");

        let fd1 = open(
            &path,
            OFlag::O_CREAT | OFlag::O_RDWR,
            Mode::from_bits(0o666).expect("invalid mode"),
        )
        .expect("open fd1");
        flock(fd1, nix::fcntl::FlockArg::LockExclusiveNonblock).expect("first lock must succeed");

        // Open a *separate* file description so flock treats it independently.
        let fd2 = open(
            &path,
            OFlag::O_RDWR,
            Mode::from_bits(0o666).expect("invalid mode"),
        )
        .expect("open fd2");
        let result = flock(fd2, nix::fcntl::FlockArg::LockExclusiveNonblock);

        let _ = close(fd2);
        let _ = flock(fd1, nix::fcntl::FlockArg::Unlock);
        let _ = close(fd1);
        let _ = fs::remove_file(&path);

        assert!(
            matches!(result, Err(nix::errno::Errno::EWOULDBLOCK)),
            "expected EWOULDBLOCK when file is already locked, got {result:?}"
        );
    }
}
