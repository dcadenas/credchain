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
use std::time::Duration;

use crate::store;

/// Exit/error type carrying a user-facing message. Messages never include
/// secret material; they only describe the failure.
pub struct CredError(pub String);

/// Concurrent decrypts per UID. systemd-creds.socket uses
/// `MaxConnectionsPerSource=16`; stay well under that.
const DECRYPT_SLOTS: u32 = 4;
/// First try plus this many transport retries, then fail closed.
const TRANSPORT_ATTEMPTS: u32 = 5;
const TRANSPORT_BACKOFF_BASE_MS: u64 = 25;
const TRANSPORT_BACKOFF_CAP_MS: u64 = 400;

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

    let _slot = acquire_decrypt_slot();
    decrypt_cipher_with_retry(cred_name, &cipher)
}

fn decrypt_cipher_with_retry(cred_name: &str, cipher: &[u8]) -> Result<Vec<u8>, CredError> {
    let mut last_transport: Option<String> = None;
    for attempt in 0..TRANSPORT_ATTEMPTS {
        match decrypt_cipher_once(cred_name, cipher) {
            Ok(plain) => return Ok(plain),
            Err(DecryptAttemptError::Spawn(msg) | DecryptAttemptError::Wait(msg)) => {
                return Err(CredError(msg));
            }
            Err(DecryptAttemptError::Failed(stderr)) => {
                let class = classify_decrypt_stderr(&stderr);
                if class == DecryptClass::Transport && attempt + 1 < TRANSPORT_ATTEMPTS {
                    last_transport = Some(stderr);
                    thread::sleep(transport_backoff(attempt));
                    continue;
                }
                return Err(CredError(decrypt_failure_message(class, &stderr)));
            }
        }
    }
    let stderr = last_transport.unwrap_or_default();
    Err(CredError(decrypt_failure_message(
        DecryptClass::Transport,
        &stderr,
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

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(cipher).map_err(|e| {
            DecryptAttemptError::Spawn(format!("failed to pipe ciphertext to systemd-creds: {e}"))
        })?;
    }
    drop(child.stdin.take());

    let output = child.wait_with_output().map_err(|e| {
        DecryptAttemptError::Wait(format!("failed to wait on systemd-creds decrypt: {e}"))
    })?;

    if !output.status.success() {
        return Err(DecryptAttemptError::Failed(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    Ok(output.stdout)
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
        || stderr.contains("Unexpected PCR")
        || stderr.contains("dictionary lockout")
        || stderr.contains("belongs to another TPM")
        || stderr.contains("Couldn't find PCR signature")
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

fn acquire_decrypt_slot() -> Option<DecryptSlot> {
    let dir = decrypt_lock_dir()?;
    if ensure_lock_dir(&dir).is_err() {
        return None;
    }
    let mut files = Vec::with_capacity(DECRYPT_SLOTS as usize);
    for i in 0..DECRYPT_SLOTS {
        let path = dir.join(format!("decrypt.slot.{i}"));
        let file = match open_lock_file(&path) {
            Ok(f) => f,
            Err(_) => return None,
        };
        if flock(&file, true).is_ok() {
            return Some(DecryptSlot { _file: file });
        }
        files.push(file);
    }
    let idx = (std::process::id() as usize) % files.len();
    let file = files.swap_remove(idx);
    drop(files);
    flock(&file, false).ok()?;
    Some(DecryptSlot { _file: file })
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
}
