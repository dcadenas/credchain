//! credchain — a headless local replacement for envchain using systemd-creds.
//!
//! CLI (envchain-compatible):
//!   credchain (--set|-s) [--noecho|-n] [--require-passphrase|-p]
//!                       [--no-require-passphrase|-P] [--backend=systemd]
//!                       NAMESPACE ENV [ENV ..]
//!   credchain --list [NAMESPACE]
//!   credchain (--unset|-u) NAMESPACE ENV [ENV ..]
//!   credchain [--backend=systemd] NAMESPACE[,NAMESPACE...] COMMAND [ARG ...]
//!
//! See docs/DESIGN.md for the full design, security boundary, and intentional
//! incompatibilities.

mod creds;
mod exec;
mod input;
mod store;

use std::process::exit;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let _prog = args.first().cloned().unwrap_or_else(|| "credchain".into());
    let code = run(&args[1..]);
    exit(code);
}

/// Dispatch on argv. Returns the process exit code.
fn run(args: &[String]) -> i32 {
    if args.is_empty() {
        print_help();
        return 2;
    }

    // Top-level subcommands / options. We intentionally do not greedily parse
    // options for exec mode (envchain does not support flags there) except for
    // an optional --backend=systemd which we accept for forward-compat.
    match args[0].as_str() {
        "--set" | "-s" => cmd_set(&args[1..]),
        "--list" | "-l" => cmd_list(&args[1..]),
        "--unset" | "-u" => cmd_unset(&args[1..]),
        "--version" => {
            println!("credchain {VERSION}");
            0
        }
        "--help" | "-h" => {
            print_help();
            0
        }
        s if s.starts_with("--backend=") || s == "--backend" => {
            // Allow an optional --backend=systemd before the namespace list in
            // exec mode. Only systemd is supported.
            let rest = &args[1..];
            if rest.is_empty() {
                print_help();
                return 2;
            }
            // Re-emit a --backend=systemd on the front if needed and recurse
            // by stripping leading backend options.
            let stripped: Vec<String> = strip_backend(rest);
            cmd_exec(&stripped)
        }
        s if s.starts_with('-') && args[0] != "-" => {
            // Unknown top-level option. Flags belonging to a subcommand are a
            // common ordering mistake (envchain wants them after the
            // subcommand too), so name the fix instead of only the error.
            match misplaced_flag_owner(s) {
                Some(owner) => eprintln!(
                    "credchain: unknown option: {s}\n\
                     credchain: {s} is an option of {owner}; it must come after it, \
                     e.g. `credchain {owner} {s} ...`"
                ),
                None => eprintln!("credchain: unknown option: {s}"),
            }
            print_help();
            2
        }
        _ => cmd_exec(args),
    }
}

/// Remove leading `--backend=...` / `--backend systemd` options, validating
/// that the backend is `systemd`.
fn strip_backend(args: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    let mut skipping = true;
    while i < args.len() {
        let a = &args[i];
        if skipping {
            if a == "--backend=systemd" {
                i += 1;
                continue;
            }
            if a == "--backend" {
                if i + 1 < args.len() && args[i + 1] == "systemd" {
                    i += 2;
                    continue;
                }
                eprintln!("credchain: --backend only supports 'systemd'");
                exit(2);
            }
            if let Some(val) = a.strip_prefix("--backend=") {
                if val != "systemd" {
                    eprintln!("credchain: --backend only supports 'systemd'");
                    exit(2);
                }
                i += 1;
                continue;
            }
            skipping = false;
        }
        out.push(a.clone());
        i += 1;
    }
    out
}

/// Return the subcommand that owns `flag`, when `flag` is a valid option that
/// was merely placed before its subcommand rather than after it.
fn misplaced_flag_owner(flag: &str) -> Option<&'static str> {
    match flag {
        "-n" | "--noecho" | "-p" | "--require-passphrase" | "-P" | "--no-require-passphrase" => {
            Some("--set")
        }
        "-v" | "--show-value" => Some("--list"),
        _ => None,
    }
}

fn print_help() {
    eprintln!(
        "credchain {VERSION} — headless envchain replacement using systemd-creds\n\n\
         Usage:\n  \
           Add variables\n    \
           credchain (--set|-s) [--noecho|-n] [--require-passphrase|-p] \\\n    \
                     [--no-require-passphrase|-P] [--backend=systemd] NAMESPACE ENV [ENV ..]\n  \
           Execute with variables\n    \
           credchain [--backend=systemd] NAMESPACE[,NAMESPACE...] COMMAND [ARG ...]\n  \
           List namespaces / variables\n    \
           credchain --list [NAMESPACE]\n  \
           Remove variables\n    \
           credchain (--unset|-u) NAMESPACE ENV [ENV ..]\n\n\
         Options:\n  \
           --set (-s)        add variable(s) to NAMESPACE\n  \
           --noecho (-n)     disable echo when prompting (requires a tty)\n  \
           --require-passphrase (-p)\n    \
             parsed for interface compatibility, then rejected: the systemd\n    \
             backend has no per-item passphrase\n  \
           --no-require-passphrase (-P)\n    \
             accepted (redundant): systemd already does not ask for a passphrase\n  \
           --list (-l)       list namespaces, or variables in a namespace\n  \
           --unset (-u)      remove variable(s) from a namespace\n  \
           --backend=systemd select the storage backend (only 'systemd' is built)\n\n\
         Notes:\n  \
           credchain never prints secret values. There is no value-display\n  \
           command; --list does not decrypt. To inspect a value, run a trusted\n  \
           child through the execution path.\n  \
           Namespaces match [A-Za-z0-9._-]{{1,63}}; variables match\n  \
           [A-Za-z_][A-Za-z0-9_]*. Values may not contain NUL.\n"
    );
}

// ---- --set ------------------------------------------------------------------

fn cmd_set(args: &[String]) -> i32 {
    let mut noecho = false;
    let mut require_passphrase: Option<bool> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-n" | "--noecho" => {
                noecho = true;
                i += 1;
            }
            "-p" | "--require-passphrase" => {
                require_passphrase = Some(true);
                i += 1;
            }
            "-P" | "--no-require-passphrase" => {
                require_passphrase = Some(false);
                i += 1;
            }
            "--backend=systemd" => {
                i += 1;
            }
            _ => break,
        }
    }

    // --require-passphrase cannot be honored; reject explicitly.
    if require_passphrase == Some(true) {
        eprintln!(
            "credchain: --require-passphrase is unsupported by the systemd backend; \
             systemd-creds has no per-item passphrase. Use --no-require-passphrase \
             (the default) instead."
        );
        return 1;
    }

    let rest = &args[i..];
    if rest.is_empty() {
        eprintln!("credchain: --set requires a namespace and at least one variable");
        print_help();
        return 2;
    }
    let ns_str = &rest[0];
    let var_strs = &rest[1..];
    if var_strs.is_empty() {
        eprintln!("credchain: --set requires at least one variable name");
        return 2;
    }

    let ns = match store::Namespace::parse(ns_str) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("credchain: invalid namespace: {e}");
            return 1;
        }
    };
    let mut vars = Vec::new();
    for s in var_strs {
        match store::VarName::parse(s) {
            Ok(v) => vars.push(v),
            Err(e) => {
                eprintln!("credchain: invalid variable name '{s}': {e}");
                return 1;
            }
        }
    }

    // 1. Prompt and collect every plaintext value. Secrets live only in memory.
    let mut collected: Vec<(store::VarName, Vec<u8>)> = Vec::new();
    for v in &vars {
        let prompt = format!("{}.{}", ns.as_str(), v.as_str());
        match input::read_value(&prompt, noecho) {
            Ok(pr) => {
                if pr.eof {
                    eprintln!(
                        "credchain: aborting --set: no value provided (EOF) for {}",
                        v.as_str()
                    );
                    return 1;
                }
                if pr.value.contains(&0u8) {
                    eprintln!(
                        "credchain: value for {} contains a NUL byte; \
                         environment variables cannot contain NUL",
                        v.as_str()
                    );
                    return 1;
                }
                collected.push((v.clone(), pr.value));
            }
            Err(e) => {
                eprintln!("credchain: failed to read value for {}: {e}", v.as_str());
                return 1;
            }
        }
    }

    // 2. Encrypt each to a staging file in the namespace directory.
    let ns_dir = match store::namespace_dir(&ns) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("credchain: failed to prepare namespace directory: {e}");
            return 1;
        }
    };
    let mut staged: Vec<(std::path::PathBuf, std::path::PathBuf)> = Vec::new();
    for (var, plaintext) in &collected {
        let cred_name = store::cred_name(&ns, var);
        let staging = store::staging_path(&ns_dir, var);
        if let Err(e) = creds::encrypt_to_file(&cred_name, plaintext, &staging) {
            eprintln!("credchain: {}", e.0);
            // Clean up any staging files created so far, then abort.
            for (s, _) in &staged {
                let _ = std::fs::remove_file(s);
            }
            let _ = std::fs::remove_file(&staging);
            return 1;
        }
        let target = ns_dir.join(format!("{}.cred", var.as_str()));
        staged.push((staging, target));
    }

    // 3. Atomically install every staged file. Per-variable atomicity; a crash
    //    between two renames leaves a partial namespace (documented).
    for (staging, target) in &staged {
        if let Err(e) = store::install_atomic(staging, target) {
            eprintln!("credchain: failed to install credential: {e}");
            for (s, _) in &staged {
                let _ = std::fs::remove_file(s);
            }
            return 1;
        }
    }
    0
}

// ---- --list -----------------------------------------------------------------

fn cmd_list(args: &[String]) -> i32 {
    let mut show_value = false;
    let mut target: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-v" | "--show-value" => {
                show_value = true;
                i += 1;
            }
            "--backend=systemd" => {
                i += 1;
            }
            s if s.starts_with('-') => {
                eprintln!("credchain: --list: unknown option: {s}");
                return 2;
            }
            s => {
                if target.is_some() {
                    eprintln!("credchain: --list takes at most one namespace argument");
                    return 2;
                }
                target = Some(s.to_string());
                i += 1;
            }
        }
    }

    if show_value {
        eprintln!(
            "credchain: --show-value / -v is deliberately unsupported. \
             credchain never decrypts or prints secret values. To inspect a \
             value, run a trusted child via the execution path."
        );
        return 1;
    }

    match target {
        None => match store::list_namespaces() {
            Ok(ns) => {
                for n in ns {
                    println!("{n}");
                }
                0
            }
            Err(e) => {
                eprintln!("credchain: failed to list namespaces: {e}");
                1
            }
        },
        Some(ns_str) => match store::Namespace::parse(&ns_str) {
            Ok(ns) => match store::list_vars(&ns) {
                Ok(vars) => {
                    for v in vars {
                        println!("{v}");
                    }
                    0
                }
                Err(e) => {
                    eprintln!("credchain: {e}");
                    1
                }
            },
            Err(e) => {
                eprintln!("credchain: invalid namespace: {e}");
                1
            }
        },
    }
}

// ---- --unset ----------------------------------------------------------------

fn cmd_unset(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("credchain: --unset requires a namespace and at least one variable");
        return 2;
    }
    let ns_str = &args[0];
    let var_strs = &args[1..];
    let ns = match store::Namespace::parse(ns_str) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("credchain: invalid namespace: {e}");
            return 1;
        }
    };
    for s in var_strs {
        let var = match store::VarName::parse(s) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("credchain: invalid variable name '{s}': {e}");
                return 1;
            }
        };
        let path = match store::cred_path(&ns, &var) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("credchain: {e}");
                return 1;
            }
        };
        // Fail-closed: do not decrypt; refuse symlink; missing -> error.
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        let open = opts.write(true).custom_flags(libc::O_NOFOLLOW).open(&path);
        match open {
            Ok(_f) => {
                // We have a non-symlink file we can write; remove it.
                drop(_f);
                if let Err(e) = std::fs::remove_file(&path) {
                    eprintln!("credchain: failed to remove {}: {e}", path.display());
                    return 1;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!(
                    "credchain: variable not found: {}.{}",
                    ns.as_str(),
                    var.as_str()
                );
                return 1;
            }
            Err(e) => {
                eprintln!(
                    "credchain: refusing to unset {}:{} {e}",
                    ns.as_str(),
                    var.as_str()
                );
                return 1;
            }
        }
    }
    0
}

// ---- exec -------------------------------------------------------------------

fn cmd_exec(args: &[String]) -> i32 {
    // Strip leading --backend options in exec form too.
    let args = strip_backend(args);
    if args.is_empty() {
        print_help();
        return 2;
    }
    let ns_field = &args[0];
    let command: Vec<String> = args[1..].to_vec();
    if command.is_empty() {
        eprintln!("credchain: no command given");
        print_help();
        return 2;
    }

    let mut namespaces = Vec::new();
    for part in ns_field.split(',') {
        let part = part.trim();
        if part.is_empty() {
            eprintln!("credchain: empty namespace in list");
            return 2;
        }
        match store::Namespace::parse(part) {
            Ok(n) => namespaces.push(n),
            Err(e) => {
                eprintln!("credchain: invalid namespace '{part}': {e}");
                return 2;
            }
        }
    }

    match exec::run(namespaces, command) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("credchain: {}", e.0);
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_args_helps() {
        assert_eq!(run(&[]), 2);
    }

    #[test]
    fn misplaced_set_flags_name_their_owner() {
        assert_eq!(misplaced_flag_owner("--noecho"), Some("--set"));
        assert_eq!(misplaced_flag_owner("-n"), Some("--set"));
        assert_eq!(misplaced_flag_owner("--require-passphrase"), Some("--set"));
        assert_eq!(misplaced_flag_owner("--show-value"), Some("--list"));
        assert_eq!(misplaced_flag_owner("--nonsense"), None);
    }

    #[test]
    fn misplaced_flag_still_exits_two() {
        assert_eq!(run(&["--noecho".into(), "ns".into(), "VAR".into()]), 2);
    }

    #[test]
    fn strip_backend_keeps_rest() {
        let v = strip_backend(&["--backend=systemd".into(), "ns".into(), "env".into()]);
        assert_eq!(v, vec!["ns".to_string(), "env".to_string()]);
    }

    #[test]
    fn strip_backend_rejects_unknown() {
        // strip_backend calls exit(2) on unknown backend; we can only test the
        // happy path here.
        let v = strip_backend(&["--backend=systemd".into(), "x".into()]);
        assert_eq!(v, vec!["x".to_string()]);
    }
}
