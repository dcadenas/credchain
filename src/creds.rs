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

use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use crate::store;

/// Exit/error type carrying a user-facing message. Messages never include
/// secret material; they only describe the failure.
pub struct CredError(pub String);

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

    let mut child = Command::new("systemd-creds")
        .args(["decrypt", "--user", "--name", cred_name, "-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| CredError(format!("failed to run systemd-creds decrypt: {e}")))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&cipher)
            .map_err(|e| CredError(format!("failed to pipe ciphertext to systemd-creds: {e}")))?;
    }
    // Drop stdin to signal EOF.
    drop(child.stdin.take());

    let output = child
        .wait_with_output()
        .map_err(|e| CredError(format!("failed to wait on systemd-creds decrypt: {e}")))?;

    if !output.status.success() {
        return Err(CredError(format!(
            "systemd-creds decrypt failed (credential may be corrupt or name-mismatched): {}",
            redact(&String::from_utf8_lossy(&output.stderr))
        )));
    }
    Ok(output.stdout)
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
    // Truncate to a bounded length; never echo full secret material even if a
    // downstream tool somehow included it.
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
}
