# credchain — design

A headless, local replacement for [envchain](https://github.com/sorah/envchain) that
preserves envchain's namespace-and-command workflow but stores secrets in
user-scoped **systemd-creds** encrypted credentials instead of GNOME Keyring /
D-Bus Secret Service. Works from terminals, SSH sessions, and unattended user
services without a graphical login.

## Goals (non-negotiable)

- Envchain-compatible CLI shape: `--set`, `--list`, `--unset`, and exec mode
  `NAMESPACE[,NAMESPACE...] COMMAND [ARG ...]`, plus `--noecho`.
- Storage backend: `systemd-creds --user` (TPM2 + host key when available; at
  minimum the user-scoped host key). No GNOME, Secret Service, desktop keyring,
  cloud, or interactive graphical dependency.
- Headless: no polkit prompt, no `systemd-creds setup` (that's a root-only,
  system-scope operation). The `--user` scope derives its key from UID +
  username + machine-id, so no root-only key file is read.
- Secret safety: plaintext never persisted to a normal file; secrets never in
  argv, logs, process titles, diagnostics, or filenames; failure paths redact.
- Fail-closed on invalid names, NUL values, malformed ciphertext, missing
  variables, ambiguous command boundaries, and unsafe filesystem objects.

## Interface (envchain-compatible)

```
credchain (--set|-s) [--noecho|-n] [--require-passphrase|-p]
                    [--no-require-passphrase|-P] [--backend=systemd]
                    NAMESPACE ENV [ENV ..]

credchain --list            # list namespaces
credchain --list NAMESPACE  # list variable names in a namespace
credchain (--unset|-u) NAMESPACE ENV [ENV ..]

credchain [--backend=systemd] NAMESPACE[,NAMESPACE...] COMMAND [ARG ...]
```

### Intentional incompatibilities (documented)

- `--require-passphrase` / `-p`: **parsed, then rejected** with a nonzero exit
  and an explicit "unsupported by systemd backend" message. systemd-creds has
  no per-item passphrase concept, so silently accepting a security flag we
  cannot honor would be dishonest.
- `--no-require-passphrase` / `-P`: **accepted silently** as redundant — it
  asks for the behavior the systemd backend already provides. No warning.
- `--list` with a value-display option (`-v` / `--show-value`): **parsed, then
  rejected** with a nonzero exit and an explicit "deliberately unsupported"
  message. credchain never decrypts or prints secret values. To inspect a
  value, run a trusted child through the normal execution path.
- No `cat`/`reveal` command exists and none will be added.
- Namespace names are constrained to `^[A-Za-z0-9._-]{1,63}$` (path-safe;
  rejects `/`, `..`, empty). Envchain's keychain "account" names are looser.
- Variable names must match `^[A-Za-z_][A-Za-z0-9_]*$` (POSIX `setenv` shape).
- Values may not contain NUL (cannot be passed to `setenv`); other bytes are
  binary-safe through systemd-creds.
- Exec mode fails with a nonzero exit if a named namespace directory does not
  exist (fail-closed against typos). envchain silently skips an unknown
  namespace; this is the one behavior change that protects against silently
  running a command *without* the intended secrets.

## Storage layout

Base directory (durable, user-scoped):

- `$XDG_DATA_HOME/credchain/`, or `$HOME/.local/share/credchain/` when
  `XDG_DATA_HOME` is unset.

Under it:

```
credchain/
  <namespace>/          # 0700
    <VAR>.cred          # 0600, systemd-creds ciphertext
```

The systemd-creds name embedded in each ciphertext file is
`credchain.<namespace>.<VAR>` — unambiguous and filename-safe given the name
validation above. Decryption always passes `--name=credchain.<ns>.<VAR>`
explicitly, so the file's on-disk basename is never trusted as the credential
identity.

**Durable unit is one variable**, not a namespace-wide transaction. For a
multi-variable `--set`, credchain:

1. validates every name,
2. prompts and collects every plaintext value,
3. encrypts each to a staging temp file in the namespace directory
   (`O_CREAT|O_EXCL|O_NOFOLLOW`),
4. only after all succeed, atomically renames each staging file over its live
   target, then fsyncs.

If any step before (4) fails, all staging files are unlinked and no live file
is touched. A crash between two renames leaves a partial namespace; that is
documented as the per-variable atomicity boundary.

## Runtime / exec contract

- credchain merges variables from the listed namespaces **left to right**;
  later namespaces override earlier ones for the same variable name, matching
  envchain.
- credchain **inherits the caller environment** and only overrides the
  selected secret variables, like envchain. No clean-environment option is
  provided (would need a well-specified, tested design; out of scope).
- The target is run **directly** via `execvp` semantics (`std::os::unix::
  process::CommandExt::exec`): the credchain process image is replaced by the
  target. Consequences, all matching envchain:
  - PATH lookup is performed (execvp semantics).
  - No shell (`/bin/sh -c`) is involved; argv is passed verbatim.
  - The child's exit status and Unix signals propagate directly to the parent
    (there is no separate credchain wrapper process left to mask them).
  - If exec fails (e.g. command not found), credchain prints to stderr and
    exits nonzero (1), like envchain.
- Secrets reach the child only via its environment block. They are never
  placed in argv, in the command line, in logs, or in diagnostics.

## systemd service integration

When `$CREDENTIALS_DIRECTORY` is set (credchain is running inside a systemd
user service that materialized credentials via `LoadCredentialEncrypted=`),
credchain prefers reading already-decrypted plaintext from
`$CREDENTIALS_DIRECTORY/credchain.<namespace>.<VAR>` instead of shelling out
to `systemd-creds decrypt`. Terminal execution decrypts the encrypted user
credentials directly. This does **not** provide per-binary isolation — the
target and its descendants can read any injected environment variable; it only
changes the storage/unlock path, not runtime environment semantics.

## Filesystem / race safety

- Base and namespace directories are created `0700`; existing ones are
  tightened to `0700`. Cred files are `0600`.
- Cred files are opened for read with `O_NOFOLLOW` (symlink leaf → fail-closed).
- Staging writes use `O_CREAT|O_EXCL|O_NOFOLLOW` + atomic `rename()`.
- Namespace directories that are symlinks are rejected.
- Malformed ciphertext, name mismatches, and missing files are all refused
  with a nonzero exit; no secret is rendered in any error.

## Implementation language

Rust, chosen for memory safety, a single compiled binary, and direct access to
the POSIX primitives needed (`exec`, `O_NOFOLLOW`, `termios` for noecho). The
only external crate is `libc` (constants/primitives).

## Testing strategy

Black-box. `tests/integration.sh` drives the built `credchain` binary as a
subprocess using only conspicuously fake values
(`credchain-test-secret-not-real-FAKE`) inside isolated `$XDG_DATA_HOME`
temp dirs. Scenarios covered include:

1. CLI shape (`--set`, `-s`, `--list`, `--unset`, exec, `--noecho`).
2. Multiple namespaces and left-to-right precedence/override.
3. Exact argv preserved to the child.
4. Inherited (non-secret) environment passes through.
5. Child exit status propagated.
6. Unix signals propagated (execvp, no wrapper).
7. No-shell behavior (argv verbatim, no `/bin/sh -c`).
8. No-echo input disables echo on a tty.
9. Atomic multi-variable `--set` (no live file touched on partial failure).
10. Restrictive permissions (dir 0700, files 0600).
11. Corrupt / missing / name-mismatched credential refusal (nonzero exit).
12. Symlink/race safety (symlinked cred file → refused).
13. Secret redaction in failure paths (stderr never contains the secret).
14. Subprocess observation: the fake secret is present in the child's
    environment and absent from credchain's argv/stdout/stderr.
15. Headless: no GNOME/DBus dependency (inherent — only `systemd-creds`).
16. `--require-passphrase` and `--list -v` fail explicitly.
17. Invalid namespace / variable names rejected.
18. NUL-containing values rejected.

Rust unit tests cover pure logic (name validation, path encoding). The
integration suite is the contract.

## Security boundary — honest limits

- credchain protects secrets **at rest** (encrypted with the user-scoped
  systemd-creds key) and **in transit to the child** (environment only, never
  argv/logs/filenames).
- It does **not** isolate the running target from its own descendants: any
  child process can read the injected environment variables. This matches
  envchain. It is a storage/unlock improvement, not a sandbox.
- Decryption requires the same user, the same machine (machine-id), and the
  host key or TPM2 key that systemd-creds selected when the credential was
  encrypted.
