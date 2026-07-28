//! Exec mode: load secrets from namespaces into a child environment and
//! `execvp` the target, replacing the credchain process image.

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use crate::creds;
use crate::store::{self, Namespace, VarName};

pub struct ExecError(pub String);

/// Load all variables from `namespaces` (left to right; later override) into
/// the environment and exec `argv[0]` with `argv`. The caller's environment is
/// inherited; only the selected secret variables are overridden.
pub fn run(namespaces: Vec<Namespace>, argv: Vec<String>) -> Result<(), ExecError> {
    if argv.is_empty() {
        return Err(ExecError("no command given".into()));
    }

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // Merge variables left to right: later namespaces win.
    let mut seen: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
    for ns in &namespaces {
        if !store::namespace_exists(ns).map_err(|e| ExecError(e.to_string()))? {
            return Err(ExecError(format!("namespace not found: {}", ns.as_str())));
        }
        let vars = list_namespace_vars(ns).map_err(ExecError)?;
        for var in vars {
            let v = VarName::parse(&var).map_err(ExecError)?;
            let cred_name = store::cred_name(ns, &v);
            let bytes = resolve(&cred_name, ns, &v).map_err(ExecError)?;
            seen.insert(var, bytes);
        }
    }

    use std::os::unix::ffi::OsStringExt;
    for (k, v) in seen {
        // setenv requires no NUL in name or value; names are validated to be
        // NUL-free by construction, and values were checked for NUL at --set.
        // Re-check defensively here.
        if v.contains(&0u8) {
            return Err(ExecError(format!(
                "refusing to set {k}: value contains NUL"
            )));
        }
        cmd.env(k, std::ffi::OsString::from_vec(v));
    }

    // exec replaces this process image. On success we never return.
    let err = cmd.exec();
    Err(ExecError(format!("exec failed: {err}")))
}

fn list_namespace_vars(ns: &Namespace) -> Result<Vec<String>, String> {
    store::list_vars(ns)
}

fn resolve(cred_name: &str, ns: &Namespace, var: &VarName) -> Result<Vec<u8>, String> {
    // Prefer already-materialized plaintext from $CREDENTIALS_DIRECTORY.
    if let Some(bytes) = creds::read_from_credentials_directory(cred_name).map_err(|e| e.0)? {
        return Ok(bytes);
    }
    // Otherwise decrypt the encrypted user credential.
    let path = store::cred_path(ns, var).map_err(|e| e.to_string())?;
    match creds::decrypt_to_memory(cred_name, &path) {
        Ok(b) => Ok(b),
        Err(e) => Err(e.0),
    }
}
