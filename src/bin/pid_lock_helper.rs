//! Minimal helper binary used exclusively by the `lock_holding` integration test.
//!
//! **Not part of the public API.**
//!
//! Usage: `pid_lock_helper <pidfile-path>`
//!
//! The binary:
//! 1. Opens `<pidfile-path>` and acquires an exclusive advisory flock.
//! 2. Writes its own PID to the file.
//! 3. Prints `"ready\n"` to stdout so the integration test knows the lock is held.
//! 4. Sleeps for up to 60 seconds (or until killed by the test runner).
use nix::{
    fcntl::{Flock, FlockArg, OFlag, open},
    sys::stat::Mode,
    unistd::{getpid, write},
};
use std::os::fd::AsFd;
use std::{path::PathBuf, thread, time::Duration};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: pid_lock_helper <pidfile>");
        std::process::exit(1);
    }

    let path = PathBuf::from(&args[1]);

    let fd = open(
        &path,
        OFlag::O_CREAT | OFlag::O_RDWR,
        Mode::from_bits(0o666).expect("invalid mode"),
    )
    .unwrap_or_else(|e| {
        eprintln!("open failed: {e}");
        std::process::exit(1);
    });

    let locked_fd = Flock::lock(fd, FlockArg::LockExclusiveNonblock).unwrap_or_else(|e| {
        eprintln!("flock failed: {}", e.1);
        std::process::exit(1);
    });

    let pid = getpid();
    let content = format!("{}\n", pid.as_raw());
    write(locked_fd.as_fd(), content.as_bytes()).unwrap_or_else(|e| {
        eprintln!("write failed: {e}");
        std::process::exit(1);
    });

    // Signal to the test that we hold the lock.
    println!("ready");

    // Hold the lock until killed.  The 60-second cap avoids zombie processes if
    // the test runner fails to send SIGKILL.
    thread::sleep(Duration::from_secs(60));
    // locked_fd is dropped here on normal exit, releasing the lock.
}
