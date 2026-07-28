//! Smoke test that does not require systemd-creds on the host. The full
//! contract suite is `tests/integration.sh` (run in CI and via `make test`).

use std::process::Command;

fn cc() -> Command {
    let exe = env!("CARGO_BIN_EXE_credchain");
    Command::new(exe)
}

#[test]
fn no_args_exits_2_and_mentions_usage() {
    let out = cc().output().expect("spawn credchain");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Usage"));
}

#[test]
fn version_prints() {
    let out = cc().arg("--version").output().expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("credchain ") || stdout.contains("credchain"));
    assert!(out.status.success());
}

#[test]
fn invalid_namespace_rejected_before_running_command() {
    let out = cc().args(["bad/ns", "true"]).output().expect("spawn");
    assert_ne!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("namespace") || stderr.contains("invalid"));
}

#[test]
fn require_passphrase_rejected() {
    // No tty/stdin: still must reject the unsupported security flag.
    let out = cc()
        .args(["--set", "--require-passphrase", "nsx", "VAR"])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("spawn");
    assert_ne!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--require-passphrase"));
}

#[test]
fn list_show_value_rejected() {
    let out = cc()
        .args(["--list", "--show-value"])
        .output()
        .expect("spawn");
    assert_ne!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("show-value"));
}
