//! Storage path management, name validation, and atomic filesystem operations.
//!
//! Layout (durable, user-scoped):
//!   $XDG_DATA_HOME/credchain/<namespace>/<VAR>.cred   (0600, systemd-creds ciphertext)
//! Directories are 0700; cred files are 0600. Cred files are opened with
//! `O_NOFOLLOW` on read; staging writes use `O_CREAT|O_EXCL|O_NOFOLLOW` plus
//! an atomic `rename()`. A symlinked leaf or namespace directory is refused
//! fail-closed.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// A validated namespace name: `[A-Za-z0-9._-]{1,63}`, not `.` or `..`.
#[derive(Clone, Debug)]
pub struct Namespace(String);

/// A validated environment-variable name: `[A-Za-z_][A-Za-z0-9_]*`.
#[derive(Clone, Debug)]
pub struct VarName(String);

impl Namespace {
    pub fn parse(s: &str) -> Result<Self, String> {
        if s.is_empty() || s.len() > 63 {
            return Err("namespace name must be 1..63 chars".into());
        }
        if s == "." || s == ".." {
            return Err("namespace name may not be . or ..".into());
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
        {
            return Err("namespace name must match [A-Za-z0-9._-]".into());
        }
        Ok(Self(s.to_string()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl VarName {
    pub fn parse(s: &str) -> Result<Self, String> {
        if s.is_empty() {
            return Err("variable name must be non-empty".into());
        }
        let mut chars = s.chars();
        let first = chars.next().unwrap();
        if !(first.is_ascii_alphabetic() || first == '_') {
            return Err("variable name must start with [A-Za-z_]".into());
        }
        if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err("variable name must match [A-Za-z_][A-Za-z0-9_]*".into());
        }
        Ok(Self(s.to_string()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The systemd-creds credential name embedded in ciphertext: `credchain.<ns>.<VAR>`.
pub fn cred_name(ns: &Namespace, var: &VarName) -> String {
    format!("credchain.{}.{}", ns.as_str(), var.as_str())
}

/// Resolve the base store directory: `$XDG_DATA_HOME/credchain` or
/// `$HOME/.local/share/credchain`. Created 0700 if missing, tightened to 0700
/// if it exists with looser permissions.
pub fn base_dir() -> Result<PathBuf, io::Error> {
    let base = match std::env::var_os("XDG_DATA_HOME") {
        Some(x) if !x.is_empty() => PathBuf::from(x).join("credchain"),
        _ => {
            let home = std::env::var_os("HOME").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "HOME is not set and XDG_DATA_HOME unset",
                )
            })?;
            PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("credchain")
        }
    };
    ensure_dir_secure(&base)?;
    Ok(base)
}

/// Create or tighten a directory to 0700. Refuses a symlink at this path.
pub fn ensure_dir_secure(p: &Path) -> Result<(), io::Error> {
    use std::os::unix::fs::MetadataExt;
    match fs::symlink_metadata(p) {
        Ok(md) => {
            if md.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "refusing to use a symlinked store directory",
                ));
            }
            let mode = md.mode() & 0o777;
            if mode != 0o700 {
                fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(p)?;
            fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// The directory for a namespace: `<base>/<namespace>`, ensured 0700.
pub fn namespace_dir(ns: &Namespace) -> Result<PathBuf, io::Error> {
    let d = base_dir()?.join(ns.as_str());
    ensure_dir_secure(&d)?;
    Ok(d)
}

/// The path to a variable's ciphertext file.
pub fn cred_path(ns: &Namespace, var: &VarName) -> Result<PathBuf, io::Error> {
    Ok(namespace_dir(ns)?.join(format!("{}.cred", var.as_str())))
}

/// Open an existing cred file for reading with `O_NOFOLLOW`. A symlinked leaf
/// is refused fail-closed.
pub fn open_cred_no_follow(path: &Path) -> Result<fs::File, io::Error> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true).custom_flags(libc::O_NOFOLLOW);
    opts.open(path)
}

/// Atomically install a freshly-encrypted staging file at `target`.
/// `staging` must be in the same directory as `target`. The staging file is
/// chmod'd to 0600 and fsync'd before the rename; the parent directory is
/// fsync'd afterward for durability.
pub fn install_atomic(staging: &Path, target: &Path) -> Result<(), io::Error> {
    fs::set_permissions(staging, fs::Permissions::from_mode(0o600))?;
    let f = fs::File::open(staging)?;
    f.sync_all()?;
    fs::rename(staging, target)?;
    // Best-effort parent dir fsync.
    if let Some(parent) = target.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Create a unique staging path in `dir`. Uses the pid and a counter so it is
/// predictable in tests but unique within a process.
static STAGE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn staging_path(dir: &Path, var: &VarName) -> PathBuf {
    let n = STAGE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let pid = std::process::id();
    let mut name = OsString::from(format!(".{}.{}.tmp", var.as_str(), pid));
    name.push(format!(".{}", n));
    dir.join(name)
}

/// List namespace directory names (subdirs of base). Symlinked subdirs are
/// skipped.
pub fn list_namespaces() -> Result<Vec<String>, io::Error> {
    let base = base_dir()?;
    let mut out = Vec::new();
    for entry in fs::read_dir(&base)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            if let Some(name) = entry.file_name().to_str() {
                out.push(name.to_string());
            }
        }
    }
    out.sort();
    Ok(out)
}

/// List variable names (`<VAR>` stripped of `.cred`) in a namespace.
///
/// Fail-closed: a `.cred` entry that is a symlink or not a regular file is
/// treated as an unsafe filesystem object and causes an error rather than being
/// silently skipped. This prevents an attacker-swappped symlink from being
/// quietly ignored while a command runs with a silently-diminished secret set.
pub fn list_vars(ns: &Namespace) -> Result<Vec<String>, String> {
    let dir = namespace_dir(ns).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    match fs::read_dir(&dir) {
        Ok(rd) => {
            for entry in rd {
                let entry = entry.map_err(|e| e.to_string())?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if let Some(stripped) = name.strip_suffix(".cred") {
                    let md = entry.metadata().map_err(|e| e.to_string())?;
                    if md.file_type().is_symlink() {
                        return Err(format!(
                            "refusing symlinked credential file in namespace {}: {}",
                            ns.as_str(),
                            name
                        ));
                    }
                    if !md.is_file() {
                        return Err(format!(
                            "non-regular credential entry in namespace {}: {}",
                            ns.as_str(),
                            name
                        ));
                    }
                    out.push(stripped.to_string());
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(format!("namespace not found: {}", ns.as_str()));
        }
        Err(e) => return Err(e.to_string()),
    }
    out.sort();
    Ok(out)
}

/// Does a namespace directory exist?
pub fn namespace_exists(ns: &Namespace) -> Result<bool, io::Error> {
    let base = base_dir()?;
    let p = base.join(ns.as_str());
    match fs::symlink_metadata(&p) {
        Ok(md) => Ok(md.is_dir() && !md.file_type().is_symlink()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_validation() {
        assert!(Namespace::parse("aws").is_ok());
        assert!(Namespace::parse("a.b-c_d").is_ok());
        assert!(Namespace::parse("AWS").is_ok());
        assert!(Namespace::parse("").is_err());
        assert!(Namespace::parse("bad/ns").is_err());
        assert!(Namespace::parse("..").is_err());
        assert!(Namespace::parse(".").is_err());
        assert!(Namespace::parse("has space").is_err());
        assert!(Namespace::parse(&"x".repeat(64)).is_err());
    }

    #[test]
    fn varname_validation() {
        assert!(VarName::parse("AWS_KEY").is_ok());
        assert!(VarName::parse("_FOO").is_ok());
        assert!(VarName::parse("A1").is_ok());
        assert!(VarName::parse("").is_err());
        assert!(VarName::parse("1BAD").is_err());
        assert!(VarName::parse("has-dash").is_err());
        assert!(VarName::parse("has space").is_err());
    }

    #[test]
    fn cred_name_shape() {
        let ns = Namespace::parse("aws").unwrap();
        let v = VarName::parse("AWS_KEY").unwrap();
        assert_eq!(cred_name(&ns, &v), "credchain.aws.AWS_KEY");
    }
}
