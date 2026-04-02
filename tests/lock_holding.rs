//! Integration tests for advisory flock(2) lock-holding semantics.
//!
//! These tests verify the invariant that daemonizr relies on:
//! * While a process holds the PID file's file descriptor open (with an
//!   exclusive flock), no other cooperating process can acquire the lock.
//! * When that process exits (normally **or** via SIGKILL, simulating a crash),
//!   the kernel releases the lock and it becomes available again.
//!
//! The tests work by spawning the `pid_lock_helper` binary, which opens a PID
//! file, acquires the exclusive flock, and sleeps until killed.  The test
//! process itself checks lock availability before and after sending SIGKILL.
use nix::{
    fcntl::{Flock, FlockArg, OFlag, open},
    sys::stat::Mode,
};
use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

/// Returns a path in the system temp directory that is unique to this test
/// run to avoid conflicts with other parallel test processes.
fn tmp_pidfile(suffix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "daemonizr_inttest_{}_{}.pid",
        std::process::id(),
        suffix
    ));
    p
}

/// Verify that the advisory flock is held for the entire lifetime of the
/// process that owns the PID file, and is automatically released when that
/// process exits (even via SIGKILL, i.e. a simulated crash).
///
/// Scenario:
/// 1. `pid_lock_helper` spawns → opens PID file → acquires exclusive flock →
///    writes PID → prints "ready".
/// 2. Test asserts: trying to lock from a *separate* file description gets
///    `EWOULDBLOCK` (helper is alive and holds the lock).
/// 3. Test sends SIGKILL to helper → helper exits → kernel closes all its fds →
///    advisory lock is released.
/// 4. Test asserts: trying to lock now succeeds (lock is free).
#[test]
fn test_lock_held_for_process_lifetime() {
    let pidfile = tmp_pidfile("lifetime");
    let _ = std::fs::remove_file(&pidfile);

    // ── Step 1: spawn the helper ──────────────────────────────────────────────
    let mut child = Command::new(env!("CARGO_BIN_EXE_pid_lock_helper"))
        .arg(pidfile.as_os_str())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn pid_lock_helper; run `cargo build` first");

    // Wait until the helper signals that it has acquired the lock.
    let stdout = child.stdout.take().expect("child stdout not captured");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("failed to read readiness signal from helper");
    assert_eq!(
        line.trim(),
        "ready",
        "helper did not print 'ready'; output was: {line:?}"
    );

    // ── Step 2: assert the lock IS held ──────────────────────────────────────
    {
        let fd = open(
            &pidfile,
            OFlag::O_RDONLY,
            Mode::from_bits(0o444).expect("invalid mode"),
        )
        .expect("could not open pid file for lock check (before kill)");

        let lock_result = Flock::lock(fd, FlockArg::LockExclusiveNonblock);
        // fd is in lock_result and will be dropped here regardless of outcome.
        assert!(
            matches!(lock_result, Err((_, nix::errno::Errno::EWOULDBLOCK))),
            "expected EWOULDBLOCK while helper is alive, got {lock_result:?}"
        );
    }

    // ── Step 3: kill the helper (simulate a daemon crash) ────────────────────
    child.kill().expect("failed to send SIGKILL to helper");
    child.wait().expect("failed to wait for helper to exit");

    // ── Step 4: assert the lock IS released ──────────────────────────────────
    // Use a retry loop with a 1-second deadline so that: (a) the test passes
    // quickly when the OS releases the lock immediately (the common case), and
    // (b) the test is still robust on slow or heavily loaded CI runners.
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    let lock_acquired = loop {
        let fd = open(
            &pidfile,
            OFlag::O_RDONLY,
            Mode::from_bits(0o444).expect("invalid mode"),
        )
        .expect("could not open pid file for lock check (after kill)");

        let lock_result = Flock::lock(fd, FlockArg::LockExclusiveNonblock);
        // fd (inside lock_result) is dropped here.

        if lock_result.is_ok() {
            break true;
        }
        if std::time::Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    let _ = std::fs::remove_file(&pidfile);
    assert!(
        lock_acquired,
        "lock was not released within 1 second after helper exited"
    );
}

/// Verify that a second process attempting to lock an already-locked PID file
/// gets `EWOULDBLOCK` (not a silent success), enforcing the single-instance
/// invariant among cooperating processes.
#[test]
fn test_second_spawn_gets_ewouldblock() {
    let pidfile = tmp_pidfile("second_spawn");
    let _ = std::fs::remove_file(&pidfile);

    // ── First "daemon" acquires the lock ─────────────────────────────────────
    let mut first = Command::new(env!("CARGO_BIN_EXE_pid_lock_helper"))
        .arg(pidfile.as_os_str())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn first helper");

    let stdout = first
        .stdout
        .take()
        .expect("first child stdout not captured");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("failed to read readiness signal from first helper");
    assert_eq!(line.trim(), "ready", "first helper not ready: {line:?}");

    // ── Second "daemon" tries to acquire the same lock ───────────────────────
    let second_status = Command::new(env!("CARGO_BIN_EXE_pid_lock_helper"))
        .arg(pidfile.as_os_str())
        .output()
        .expect("failed to spawn second helper");

    // The second helper should exit non-zero because flock fails.
    assert!(
        !second_status.status.success(),
        "second helper should have failed to acquire the lock"
    );
    let stderr = String::from_utf8_lossy(&second_status.stderr);
    assert!(
        stderr.contains("flock failed"),
        "expected 'flock failed' in second helper stderr, got: {stderr:?}"
    );

    // ── Clean up ─────────────────────────────────────────────────────────────
    first.kill().ok();
    first.wait().ok();
    let _ = std::fs::remove_file(&pidfile);
}
