//! Integration tests for daemon search and PID-file lock lifecycle.
use daemonizr::{Daemonizr, DaemonizrError};
use nix::{
    errno::Errno,
    fcntl::{Flock, FlockArg, OFlag, open},
    sys::stat::Mode,
};
use std::{
    env, fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{self, Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn tmp_pidfile(suffix: &str) -> PathBuf {
    env::temp_dir().join(format!("daemonizr_search_{}_{}.pid", process::id(), suffix))
}

struct RunningHelper(Child);

impl RunningHelper {
    fn spawn(pidfile: &Path) -> Self {
        let _ = fs::remove_file(pidfile);
        let mut child = Command::new(env!("CARGO_BIN_EXE_pid_lock_helper"))
            .arg(pidfile)
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to spawn pid_lock_helper");

        let stdout = child.stdout.take().expect("child stdout not captured");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .expect("failed to read helper readiness signal");
        assert_eq!(line.trim(), "ready", "unexpected helper output: {line:?}");
        Self(child)
    }

    fn id(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for RunningHelper {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn search(pidfile: &Path) -> Result<u32, DaemonizrError> {
    Daemonizr::new().pidfile(pidfile.to_path_buf()).search()
}

fn lock_is_held(pidfile: &Path) -> bool {
    let fd = open(
        pidfile,
        OFlag::O_RDONLY,
        Mode::from_bits(0o444).expect("invalid mode"),
    )
    .expect("could not open pidfile to check lock");
    matches!(
        Flock::lock(fd, FlockArg::LockExclusiveNonblock),
        Err((_, Errno::EWOULDBLOCK))
    )
}

fn wait_for_lock_release(pidfile: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if matches!(search(pidfile), Err(DaemonizrError::NoDaemonFound)) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn test_daemon_search_not_running_returns_error() {
    let pidfile = tmp_pidfile("not_running");
    let _ = fs::remove_file(&pidfile);

    assert!(matches!(
        search(&pidfile),
        Err(DaemonizrError::NoDaemonFound)
    ));
}

#[test]
fn test_daemon_search_finds_running_daemon() {
    let pidfile = tmp_pidfile("finds_daemon");
    let helper = RunningHelper::spawn(&pidfile);

    assert!(
        lock_is_held(&pidfile),
        "helper should hold the PID-file lock"
    );
    assert_eq!(
        search(&pidfile).expect("search should find helper"),
        helper.id()
    );

    drop(helper);
    assert!(
        wait_for_lock_release(&pidfile),
        "lock should release after helper exits"
    );
    let _ = fs::remove_file(&pidfile);
}

#[test]
fn test_pid_content_is_valid() {
    let pidfile = tmp_pidfile("valid_pid");
    let helper = RunningHelper::spawn(&pidfile);

    let content = fs::read_to_string(&pidfile).expect("failed to read pidfile");
    let stored_pid: u32 = content.trim().parse().expect("invalid PID in pidfile");
    assert_eq!(stored_pid, helper.id());

    drop(helper);
    let _ = fs::remove_file(&pidfile);
}

#[test]
fn test_multiple_daemons_same_pidfile_second_fails() {
    let pidfile = tmp_pidfile("multiple");
    let first = RunningHelper::spawn(&pidfile);

    let second = Command::new(env!("CARGO_BIN_EXE_pid_lock_helper"))
        .arg(&pidfile)
        .output()
        .expect("failed to spawn second helper");

    assert!(
        !second.status.success(),
        "second helper should fail to acquire lock"
    );
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("flock failed"),
        "expected lock failure, got stderr: {:?}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        search(&pidfile).expect("first helper should remain running"),
        first.id()
    );

    drop(first);
    assert!(
        wait_for_lock_release(&pidfile),
        "lock should release after helper exits"
    );
    let _ = fs::remove_file(&pidfile);
}

#[test]
fn test_daemon_terminates_and_lock_released() {
    let pidfile = tmp_pidfile("terminates");
    let helper = RunningHelper::spawn(&pidfile);
    assert!(
        lock_is_held(&pidfile),
        "helper should hold the lock before exit"
    );

    drop(helper);
    assert!(
        wait_for_lock_release(&pidfile),
        "lock should release after helper exits"
    );
    let _ = fs::remove_file(&pidfile);
}
