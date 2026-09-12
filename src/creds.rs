//! Wrapper around the `systemd-creds` CLI for user-scoped encrypt/decrypt.
//!
//! All encryption uses `--user` scope (key derived from UID + username +
//! machine-id). The embedded credential name is `credchain.<ns>.<VAR>` and is
//! supplied explicitly on both encrypt and decrypt so the on-disk filename is
//! never trusted as the credential identity.
//!
//! Plaintext is transported via pipes (stdin for encrypt, stdout for decrypt).
//! Nothing plaintext is ever written to a normal file. The only file touched
//! is the systemd-creds ciphertext output.
//!
//! Decrypt classifies `systemd-creds` stderr so varlink transport congestion
//! is not reported as corrupt ciphertext. Transport failures retry with
//! backoff and jitter while holding a per-user slot well under systemd's
//! `MaxConnectionsPerSource=16`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::store;

/// Exit/error type carrying a user-facing message. Messages never include
/// secret material; they only describe the failure.
#[derive(Debug)]
pub struct CredError(pub String);

/// Concurrent decrypts per UID. systemd-creds.socket uses
/// `MaxConnectionsPerSource=16`; stay well under that.
const DECRYPT_SLOTS: u32 = 4;
/// First try plus this many transport retries, then fail closed.
const TRANSPORT_ATTEMPTS: u32 = 5;
const TRANSPORT_BACKOFF_BASE_MS: u64 = 25;
const TRANSPORT_BACKOFF_CAP_MS: u64 = 400;
/// How long to wait for a decrypt slot before failing closed as transport.
/// Long enough for a cold-boot wave of decrypts to drain, short enough that a
/// wedged `systemd-creds` child cannot stall every caller indefinitely.
const DECRYPT_SLOT_WAIT_MAX_MS: u64 = 120_000;
/// Poll interval while every slot is busy.
const DECRYPT_SLOT_POLL_MS: u64 = 20;

/// Encrypt `plaintext` bytes to `out_path` under the given credential name.
/// Uses the user-scoped default key (`--with-key=auto` under `--user`).
pub fn encrypt_to_file(
    cred_name: &str,
    plaintext: &[u8],
    out_path: &Path,
) -> Result<(), CredError> {
    let mut child = Command::new("systemd-creds")
        .args([
            "encrypt",
            "--user",
            "--with-key=auto",
            "--name",
            cred_name,
            "-",
        ])
        .arg(out_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| CredError(format!("failed to run systemd-creds encrypt: {e}")))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(plaintext)
            .map_err(|e| CredError(format!("failed to pipe plaintext to systemd-creds: {e}")))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| CredError(format!("failed to wait on systemd-creds encrypt: {e}")))?;
    if !output.status.success() {
        return Err(CredError(format!(
            "systemd-creds encrypt failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Decrypt the ciphertext at `path` (opened with `O_NOFOLLOW`) and return the
/// plaintext bytes. We open the file ourselves with `O_NOFOLLOW` (refusing a
/// symlinked leaf), read the ciphertext into memory, and feed it to
/// `systemd-creds decrypt` via its stdin. systemd-creds never opens a path
/// itself, which avoids both the O_CLOEXEC child-fd problem and any TOCTOU
/// between our symlink check and its open. The secret is held only in the
/// returned `Vec<u8>` in memory; callers must not log it.
pub fn decrypt_to_memory(cred_name: &str, path: &Path) -> Result<Vec<u8>, CredError> {
    let mut file = store::open_cred_no_follow(path).map_err(|e| {
        CredError(format!(
            "failed to open credential file {}: {}",
            path.display(),
            redact(&e.to_string())
        ))
    })?;
    let mut cipher = Vec::new();
    file.read_to_end(&mut cipher).map_err(|e| {
        CredError(format!(
            "failed to read ciphertext from {}: {e}",
            path.display()
        ))
    })?;

    let _slot = acquire_decrypt_slot()?;
    decrypt_cipher_with_retry(cred_name, &cipher)
}

fn decrypt_cipher_with_retry(cred_name: &str, cipher: &[u8]) -> Result<Vec<u8>, CredError> {
    decrypt_cipher_with_retry_using(cipher, |c| decrypt_cipher_once(cred_name, c), thread::sleep)
}

fn decrypt_cipher_with_retry_using<A, S>(
    cipher: &[u8],
    mut attempt: A,
    mut sleeper: S,
) -> Result<Vec<u8>, CredError>
where
    A: FnMut(&[u8]) -> Result<Vec<u8>, DecryptAttemptError>,
    S: FnMut(Duration),
{
    let mut last_transport = String::new();
    for attempt_n in 0..TRANSPORT_ATTEMPTS {
        match attempt(cipher) {
            Ok(plain) => return Ok(plain),
            Err(DecryptAttemptError::Spawn(msg) | DecryptAttemptError::Wait(msg)) => {
                return Err(CredError(msg));
            }
            Err(DecryptAttemptError::Failed(stderr)) => {
                let class = classify_decrypt_stderr(&stderr);
                if class == DecryptClass::Transport && attempt_n + 1 < TRANSPORT_ATTEMPTS {
                    last_transport = stderr;
                    sleeper(transport_backoff(attempt_n));
                    continue;
                }
                return Err(CredError(decrypt_failure_message(class, &stderr)));
            }
        }
    }
    Err(CredError(decrypt_failure_message(
        DecryptClass::Transport,
        &last_transport,
    )))
}

enum DecryptAttemptError {
    Spawn(String),
    Wait(String),
    Failed(String),
}

fn decrypt_cipher_once(cred_name: &str, cipher: &[u8]) -> Result<Vec<u8>, DecryptAttemptError> {
    let mut child = Command::new("systemd-creds")
        .args(["decrypt", "--user", "--name", cred_name, "-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            DecryptAttemptError::Spawn(format!("failed to run systemd-creds decrypt: {e}"))
        })?;

    let write_err = if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(cipher).err()
    } else {
        None
    };
    drop(child.stdin.take());

    let output = child.wait_with_output().map_err(|e| {
        DecryptAttemptError::Wait(format!("failed to wait on systemd-creds decrypt: {e}"))
    })?;

    if !output.status.success() {
        let mut stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if stderr.trim().is_empty() && write_err.as_ref().is_some_and(is_pipe_transport) {
            stderr = "Failed to call Decrypt() varlink call.".to_string();
        }
        return Err(DecryptAttemptError::Failed(stderr));
    }
    if let Some(e) = write_err {
        if is_pipe_transport(&e) {
            return Err(DecryptAttemptError::Failed(
                "Failed to call Decrypt() varlink call.".into(),
            ));
        }
        return Err(DecryptAttemptError::Spawn(format!(
            "failed to pipe ciphertext to systemd-creds: {e}"
        )));
    }
    Ok(output.stdout)
}

fn is_pipe_transport(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecryptClass {
    Transport,
    NameMismatch,
    BadFormat,
    Crypto,
    Other,
}

fn classify_decrypt_stderr(stderr: &str) -> DecryptClass {
    if stderr.contains("Name in credential doesn't match expectations.") {
        return DecryptClass::NameMismatch;
    }
    if stderr.contains("Bad credential format.") {
        return DecryptClass::BadFormat;
    }
    if stderr.contains("Decryption failed (incorrect key?)")
        || stderr.contains("Unexpected TPM PCR state of the system.")
        || stderr.contains("dictionary lockout")
        || stderr.contains("belongs to another TPM")
        || stderr.contains("PCR signature required for decryption, but could not be found.")
        || stderr.contains("Couldn't find PCR signature file")
        || stderr.contains("Failed to unseal")
    {
        return DecryptClass::Crypto;
    }
    if stderr.contains("Failed to connect to io.systemd.Credentials")
        || stderr.contains("Failed to call Decrypt() varlink call.")
    {
        return DecryptClass::Transport;
    }
    DecryptClass::Other
}

fn decrypt_failure_message(class: DecryptClass, stderr: &str) -> String {
    let detail = redact(stderr.trim());
    match class {
        DecryptClass::Transport => format!(
            "systemd-creds decrypt failed: credentials service unavailable (varlink transport): {detail}"
        ),
        DecryptClass::NameMismatch => {
            format!("systemd-creds decrypt failed: credential name mismatch: {detail}")
        }
        DecryptClass::BadFormat => {
            format!("systemd-creds decrypt failed: bad credential format: {detail}")
        }
        DecryptClass::Crypto => format!(
            "systemd-creds decrypt failed: decryption key or TPM rejected the credential: {detail}"
        ),
        DecryptClass::Other => format!("systemd-creds decrypt failed: {detail}"),
    }
}

fn transport_backoff(attempt: u32) -> Duration {
    let exp = attempt.min(4);
    let base =
        (TRANSPORT_BACKOFF_BASE_MS.saturating_mul(1u64 << exp)).min(TRANSPORT_BACKOFF_CAP_MS);
    let mix = u64::from(std::process::id())
        ^ std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::from(d.subsec_nanos()))
            .unwrap_or(0);
    let jitter = mix % (base / 2 + 1);
    Duration::from_millis(base.saturating_add(jitter))
}

struct DecryptSlot {
    _file: File,
}

fn acquire_decrypt_slot() -> Result<Option<DecryptSlot>, CredError> {
    let Some(dir) = decrypt_lock_dir() else {
        return Ok(None);
    };
    if ensure_lock_dir(&dir).is_err() {
        return Ok(None);
    }
    acquire_decrypt_slot_in(&dir, Duration::from_millis(DECRYPT_SLOT_WAIT_MAX_MS))
}

fn acquire_decrypt_slot_in(
    dir: &Path,
    wait_max: Duration,
) -> Result<Option<DecryptSlot>, CredError> {
    let mut files = Vec::with_capacity(DECRYPT_SLOTS as usize);
    for i in 0..DECRYPT_SLOTS {
        let path = dir.join(format!("decrypt.slot.{i}"));
        let file = match open_lock_file(&path) {
            Ok(f) => f,
            Err(_) => return Ok(None),
        };
        if flock(&file, true).is_ok() {
            return Ok(Some(DecryptSlot { _file: file }));
        }
        files.push(file);
    }

    // Every slot is busy. Poll with a deadline instead of a blocking flock, so
    // a wedged `systemd-creds` child cannot stall every caller forever.
    let deadline = Instant::now() + wait_max;
    loop {
        let mut acquired: Option<usize> = None;
        for (idx, file) in files.iter().enumerate() {
            if flock(file, true).is_ok() {
                acquired = Some(idx);
                break;
            }
        }
        if let Some(idx) = acquired {
            let file = files.swap_remove(idx);
            drop(files);
            return Ok(Some(DecryptSlot { _file: file }));
        }
        if Instant::now() >= deadline {
            return Err(CredError(decrypt_failure_message(
                DecryptClass::Transport,
                &format!("per-user decrypt queue busy (waited {wait_max:?})"),
            )));
        }
        thread::sleep(Duration::from_millis(DECRYPT_SLOT_POLL_MS));
    }
}

fn decrypt_lock_dir() -> Option<PathBuf> {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(v) if !v.is_empty() => Some(PathBuf::from(v).join("credchain")),
        _ => {
            // SAFETY: getuid is always safe.
            let uid = unsafe { libc::getuid() };
            Some(PathBuf::from(format!("/run/user/{uid}/credchain")))
        }
    }
}

fn ensure_lock_dir(dir: &Path) -> io::Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(md) if md.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing symlinked decrypt lock directory",
        )),
        Ok(_) => {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn open_lock_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
}

fn flock(file: &File, nonblock: bool) -> io::Result<()> {
    let mut op = libc::LOCK_EX;
    if nonblock {
        op |= libc::LOCK_NB;
    }
    // SAFETY: `file` is an open fd owned by this process for the lock file.
    let rc = unsafe { libc::flock(file.as_raw_fd(), op) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Read a plaintext credential from `$CREDENTIALS_DIRECTORY/<name>` when that
/// service integration path is present. Returns Ok(None) if the env is not set
/// or the named credential is absent there (caller should then fall back to
/// decrypt).
pub fn read_from_credentials_directory(cred_name: &str) -> Result<Option<Vec<u8>>, CredError> {
    let dir = match std::env::var_os("CREDENTIALS_DIRECTORY") {
        Some(v) if !v.is_empty() => std::path::PathBuf::from(v),
        _ => return Ok(None),
    };
    let p = dir.join(cred_name);
    match std::fs::symlink_metadata(&p) {
        Ok(md) if md.file_type().is_symlink() => Err(CredError(format!(
            "refusing symlinked credential in CREDENTIALS_DIRECTORY: {}",
            cred_name
        ))),
        Ok(_) => {
            let mut f = store::open_cred_no_follow(&p).map_err(|e| {
                CredError(format!(
                    "failed to open {} from CREDENTIALS_DIRECTORY: {}",
                    cred_name,
                    redact(&e.to_string())
                ))
            })?;
            let mut buf = Vec::new();
            io::Read::read_to_end(&mut f, &mut buf).map_err(|e| {
                CredError(format!(
                    "failed to read {} from CREDENTIALS_DIRECTORY: {e}",
                    cred_name
                ))
            })?;
            Ok(Some(buf))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CredError(format!(
            "failed to stat {} in CREDENTIALS_DIRECTORY: {e}",
            cred_name
        ))),
    }
}

/// Redact a possibly-secret-bearing string from an error message. We do not
/// expect systemd-creds to leak plaintext in stderr, but we strip any value
/// that looks like it could be one as defense-in-depth. In practice this just
/// truncates overly long messages.
fn redact(s: &str) -> String {
    const MAX: usize = 200;
    if s.len() > MAX {
        let mut t = s[..MAX].to_string();
        t.push('…');
        t
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_truncates() {
        let long = "x".repeat(500);
        assert!(redact(&long).ends_with('…'));
        assert!(redact(&long).len() < 600);
        assert_eq!(redact("short"), "short");
    }

    #[test]
    fn transport_stderr_is_not_corrupt_or_name_mismatch() {
        let stderr = "Failed to call Decrypt() varlink call.";
        assert_eq!(classify_decrypt_stderr(stderr), DecryptClass::Transport);
        let msg = decrypt_failure_message(DecryptClass::Transport, stderr);
        assert!(
            !msg.to_lowercase().contains("corrupt"),
            "transport labeled corrupt: {msg}"
        );
        assert!(
            !msg.contains("name-mismatched") && !msg.contains("name mismatch"),
            "transport labeled name mismatch: {msg}"
        );
        assert!(msg.contains("varlink transport"), "{msg}");
    }

    #[test]
    fn connect_stderr_is_transport() {
        let stderr = "Failed to connect to io.systemd.Credentials: Connection refused";
        assert_eq!(classify_decrypt_stderr(stderr), DecryptClass::Transport);
        let msg = decrypt_failure_message(DecryptClass::Transport, stderr);
        assert!(!msg.to_lowercase().contains("corrupt"));
        assert!(!msg.contains("name-mismatched"));
    }

    #[test]
    fn name_mismatch_and_bad_format_fail_closed_without_transport() {
        assert_eq!(
            classify_decrypt_stderr("Name in credential doesn't match expectations."),
            DecryptClass::NameMismatch
        );
        assert_eq!(
            classify_decrypt_stderr("Bad credential format."),
            DecryptClass::BadFormat
        );
        assert_eq!(
            classify_decrypt_stderr("Decryption failed (incorrect key?)"),
            DecryptClass::Crypto
        );
    }

    #[test]
    fn transport_backoff_is_nonzero() {
        for attempt in 0..TRANSPORT_ATTEMPTS {
            assert!(transport_backoff(attempt) >= Duration::from_millis(TRANSPORT_BACKOFF_BASE_MS));
        }
    }

    #[test]
    fn retries_transport_then_succeeds() {
        let mut n = 0;
        let result = decrypt_cipher_with_retry_using(
            b"cipher",
            |_| {
                n += 1;
                if n < 3 {
                    Err(DecryptAttemptError::Failed(
                        "Failed to call Decrypt() varlink call.".into(),
                    ))
                } else {
                    Ok(b"plain".to_vec())
                }
            },
            |_| {},
        );
        assert_eq!(result.unwrap(), b"plain");
        assert_eq!(n, 3);
    }

    #[test]
    fn does_not_retry_name_mismatch() {
        let mut n = 0;
        let err = decrypt_cipher_with_retry_using(
            b"cipher",
            |_| {
                n += 1;
                Err(DecryptAttemptError::Failed(
                    "Name in credential doesn't match expectations.".into(),
                ))
            },
            |_| {},
        )
        .err()
        .unwrap();
        assert!(err.0.contains("name mismatch"), "{}", err.0);
        assert_eq!(n, 1);
    }

    #[test]
    fn transport_retries_exhaust_fail_closed() {
        let mut n = 0;
        let mut sleeps = 0u32;
        let err = decrypt_cipher_with_retry_using(
            b"cipher",
            |_| {
                n += 1;
                Err(DecryptAttemptError::Failed(
                    "Failed to connect to io.systemd.Credentials".into(),
                ))
            },
            |_| {
                sleeps += 1;
            },
        )
        .err()
        .unwrap();
        assert!(err.0.contains("varlink transport"), "{}", err.0);
        assert!(!err.0.to_lowercase().contains("corrupt"), "{}", err.0);
        assert_eq!(n, TRANSPORT_ATTEMPTS as i32);
        assert_eq!(sleeps, TRANSPORT_ATTEMPTS - 1);
    }

    #[test]
    fn user_scope_pcr_ipc_strings_are_crypto() {
        assert_eq!(
            classify_decrypt_stderr("Unexpected TPM PCR state of the system."),
            DecryptClass::Crypto
        );
        assert_eq!(
            classify_decrypt_stderr(
                "PCR signature required for decryption, but could not be found."
            ),
            DecryptClass::Crypto
        );
    }

    fn test_lock_dir(label: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("credchain-test-{label}-{}", std::process::id()));
        p
    }

    #[test]
    fn slot_wait_times_out_as_transport_not_corrupt() {
        let dir = test_lock_dir("slot-timeout");
        fs::create_dir_all(&dir).unwrap();
        let held: Vec<File> = (0..DECRYPT_SLOTS)
            .map(|i| open_lock_file(&dir.join(format!("decrypt.slot.{i}"))).unwrap())
            .collect();
        for f in &held {
            flock(f, true).unwrap();
        }

        let started = Instant::now();
        let err = acquire_decrypt_slot_in(&dir, Duration::from_millis(60))
            .err()
            .expect("all slots held, expected timeout");
        assert!(started.elapsed() >= Duration::from_millis(60));
        assert!(
            !err.0.to_lowercase().contains("corrupt"),
            "queue timeout labeled corrupt: {}",
            err.0
        );
        assert!(
            err.0.contains("credentials service unavailable"),
            "{}",
            err.0
        );

        drop(held);
        let slot = acquire_decrypt_slot_in(&dir, Duration::from_secs(1)).unwrap();
        assert!(slot.is_some(), "released slot should be acquired");
        drop(slot);
        let _ = fs::remove_dir_all(&dir);
    }
}
