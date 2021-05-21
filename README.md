[![Rust](https://github.com/aellwein/daemonizr/actions/workflows/rust.yml/badge.svg?branch=master)](https://github.com/aellwein/daemonizr/actions/workflows/rust.yml)

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

Hint:

> ⚠️ This crate will only work on POSIX compatible systems,
> where the "nix" and "libc" crates are available.
