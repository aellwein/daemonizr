[![Rust](https://github.com/aellwein/daemonizr/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/aellwein/daemonizr/actions/workflows/rust.yml) ![Crates.io](https://img.shields.io/crates/v/daemonizr)

daemonizr
=========

Small crate which helps with writing daemon applications in Rust.

I am aware about [daemonize](https://crates.io/crates/daemonize) and
[daemonize-me](https://crates.io/crates/daemonize-me) crates, but needed some
extended functionality like locking PID file and searching for running daemon.

A complete example:

```rust
use daemonizr::{Daemonizr, DaemonizrError, Group, Stderr, Stdout, User};
use std::{path::PathBuf, process::exit, thread::sleep, time::Duration};

fn main() {
    match Daemonizr::new()
        .work_dir(PathBuf::from("/Users/alex/git/private/daemonizr"))
        .expect("invalid path")
        .as_user(User::by_name("alex").expect("invalid user"))
        .as_group(Group::by_name("staff").expect("invalid group"))
        .pidfile(PathBuf::from("dmnzr.pid"))
        .stdout(Stdout::Redirect(PathBuf::from("dmnzr.out")))
        .stderr(Stderr::Redirect(PathBuf::from("dmnzr.err")))
        .umask(0o027)
        .expect("invalid umask")
        .spawn()
    {
        Err(DaemonizrError::AlreadyRunning) => {
            /* search for the daemon's PID  */
            match Daemonizr::new()
                .work_dir(PathBuf::from("/Users/alex/git/private/daemonizr"))
                .unwrap()
                .pidfile(PathBuf::from("dmnzr.pid"))
                .search()
            {
                Err(x) => eprintln!("error: {}", x),
                Ok(pid) => {
                    eprintln!("another daemon with pid {} is already running", pid);
                    exit(1);
                }
            };
        }
        Err(e) => eprintln!("DaemonizrError: {}", e),
        Ok(()) => { /* We are in daemon process now */ }
    };

    /* actual daemon work goes here */
    println!("write something to stdout");
    eprintln!("write something to stderr");
    sleep(Duration::from_secs(60));
    println!("Daemon exits.")
}
```

## Advisory PID file locking

daemonizr uses [`flock(2)`](https://man7.org/linux/man-pages/man2/flock.2.html)
to protect the PID file.  `flock(2)` provides **advisory** locks: they are only
effective when every process that touches the PID file also uses `flock`.

### How it works

1. Before `fork(2)`, `spawn()` opens the PID file and acquires an **exclusive
   non-blocking** lock.  If the lock is already held by another process,
   `spawn()` returns `DaemonizrError::AlreadyRunning` immediately.
2. After a successful `fork(2)`, the child (daemon) process inherits the open
   file description – and therefore the `flock` lock – from the parent.  The
   parent exits immediately; the lock is **not** released because the child
   still holds a reference to the same open file description.
3. The daemon writes its own PID to the file (truncate → write → fsync) and
   keeps the file descriptor open for its entire lifetime.
4. When the daemon exits (normally or via a crash), the kernel automatically
   closes every file descriptor the process owns, releasing the advisory lock.
   The PID file is now stale and any subsequent call to `search()` will return
   `DaemonizrError::NoDaemonFound`.

### Calling `search()`

`search()` treats the advisory lock – not the PID file contents – as the
authoritative signal that a daemon is running:

* It tries to acquire an exclusive non-blocking lock on the PID file.
* **Lock acquired** → no cooperating process holds the lock → stale file →
  `NoDaemonFound`.
* **`EWOULDBLOCK`** → another process holds the lock → daemon is running →
  the PID contents are read and returned.

> ⚠️ Because `flock(2)` is advisory, a process that does *not* use `flock` can
> still read or write the PID file without any error.  daemonizr's
> single-instance guarantee only holds among processes that honour the lock
> (i.e. all processes that use this crate).

### Recommended operational practice

* Do not modify or replace the PID file from outside the daemon (e.g. from
  scripts) while the daemon is running; doing so breaks the advisory contract.
* To stop a daemon, send it a signal (e.g. `kill $(cat dmnzr.pid)`) rather
  than deleting the PID file first.
* If the PID file is left over after a hard reboot or system crash, it will be
  unlocked (no process holds the lock) and `search()` will correctly detect it
  as stale.

Hint:

> ⚠️ This crate will only work on POSIX compatible systems,
> where the "nix" and "libc" crates are available.
