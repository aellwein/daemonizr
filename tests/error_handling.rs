//! Integration tests for error handling scenarios.
//!
//! These tests verify that Daemonizr returns appropriate errors for various
//! invalid configurations and edge cases.
use daemonizr::{Daemonizr, DaemonizrError, Group, User};
use std::{env, fs, path::PathBuf, process};

#[test]
fn test_invalid_work_dir_not_absolute() {
    let work_dir = PathBuf::from("relative/path");

    let result = Daemonizr::new().work_dir(work_dir.clone()).is_err();

    assert!(result, "should have failed: expected WorkDirNotAbsolute");
}

#[test]
fn test_invalid_work_dir_does_not_exist() {
    let work_dir = PathBuf::from("/nonexistent_directory_12345/");

    let result = Daemonizr::new().work_dir(work_dir.clone()).is_err();

    assert!(result, "should have failed: expected WorkDirNotExists");
}

#[test]
fn test_invalid_work_dir_is_a_file() {
    let temp_file = env::temp_dir().join(format!("daemonizr_test_file_{}.tmp", process::id()));
    fs::write(&temp_file, "I am not a directory").expect("failed to create temp file");

    let result = Daemonizr::new().work_dir(temp_file.clone()).is_err();

    assert!(result, "should have failed: expected WorkDirNotDir");

    let _ = fs::remove_file(&temp_file);
}

#[test]
fn test_invalid_umask() {
    let result = Daemonizr::new().umask(u16::MAX).is_err();

    assert!(result, "should have failed: expected InvalidUmask");
}

#[test]
fn test_invalid_username() {
    let result = User::by_name("nonexistent_user_xyz_123");

    assert!(
        result.is_err(),
        "should have failed when user doesn't exist"
    );
}

#[test]
fn test_invalid_groupname() {
    let result = Group::by_name("nonexistent_group_xyz_123");

    assert!(
        result.is_err(),
        "should have failed when group doesn't exist"
    );
}

#[test]
fn test_daemon_spawn_errors_on_invalid_config() {
    let result = Daemonizr::new()
        .work_dir(PathBuf::from("not_a_directory"))
        .is_err();

    assert!(result, "spawn should fail with invalid work_dir");
}

#[test]
fn test_daemonizrs_error_display() {
    let errors = [
        DaemonizrError::WorkDirNotAbsolute(PathBuf::from("not_absolute")),
        DaemonizrError::WorkDirNotExists(PathBuf::from("/not/existent")),
        DaemonizrError::WorkDirNotDir(PathBuf::from("/not/a/dir")),
        DaemonizrError::InvalidUid(999999),
        DaemonizrError::InvalidGid(999999),
        DaemonizrError::InvalidUmask(0o777),
        DaemonizrError::InvalidUsername("nonexistent_user".to_string()),
        DaemonizrError::InvalidGroupname("nonexistent_group".to_string()),
        DaemonizrError::NoUserOrGroup,
        DaemonizrError::ForkFailed("simulated fork error".to_string()),
        DaemonizrError::FailedToSetUser(999999, "simulated error".to_string()),
        DaemonizrError::FailedToSetGroup(999999, "simulated error".to_string()),
        DaemonizrError::FailedToSetsid("simulated setsid error".to_string()),
        DaemonizrError::FailedToReopen("file".to_string(), "simulated reopen error".to_string()),
        DaemonizrError::FailedCreatePidfile("simulated create error".to_string()),
        DaemonizrError::AlreadyRunning,
        DaemonizrError::ErrorLockingPidfile("simulated lock error".to_string()),
        DaemonizrError::FailedToWritePidfile("simulated write error".to_string()),
        DaemonizrError::FailedToReadPidfile("simulated read error".to_string()),
        DaemonizrError::FailedToOpenPidfile("simulated open error".to_string()),
        DaemonizrError::NoDaemonFound,
    ];

    for error in errors {
        let display = format!("{}", error);
        assert!(
            !display.is_empty(),
            "error display should not be empty: {:?}",
            error
        );
    }
}
