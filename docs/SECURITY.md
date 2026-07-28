# credchain security model

This document is the authoritative security boundary for credchain. It is
intentionally narrower than a general secrets manager.

## Threat model and what credchain protects

- **At rest:** secrets are encrypted with the user-scoped `systemd-creds` key.
  The key is derived from the calling user's UID + username + machine-id (and,
  when available, the TPM2 chip and/or the host key). The encrypted credential
  files are `0600` and live in a `0700` tree under
  `$XDG_DATA_HOME/credchain/`.
- **In transit to the child:** secrets reach the target process only via its
  environment block. credchain never writes a secret to argv, the command
  line, a log, a diagnostic, a process title, or a filename.

## What credchain does NOT protect against

- **The target and its descendants.** Any process the target spawns can read
  the injected environment variables. This matches envchain. credchain is a
  storage/unlock improvement, not a sandbox. Do not run credchain with a
  command you do not trust.
- **A compromised user account or root on the same host.** Anyone who can
  become you can run `credchain <ns> <cmd>` and obtain the secrets in the
  child environment. The encryption protects against offline disk theft (and
  TPM2 binding raises that bar further), not against online compromise of the
  owning user.
- **Loss of the host key / TPM2.** Decryption requires the same user, the same
  machine-id, and (when used) the same TPM2 chip. Migrating the
  `$XDG_DATA_HOME/credchain` tree to another machine does not bring the keys
  with it; re-set the secrets on the new machine.

## Fail-closed behavior

credchain exits nonzero and does **not** run the child when:

- a namespace name is invalid (`[A-Za-z0-9._-]{1,63}`, not `.`/`..`),
- a variable name is invalid (`[A-Za-z_][A-Za-z0-9_]*`),
- a value contains a NUL byte (cannot be passed to `setenv`),
- a named namespace directory does not exist (typo guard in exec mode),
- a `.cred` entry is a symlink or non-regular file,
- ciphertext is malformed, the embedded name does not match, or the file is
  missing,
- the target command cannot be `execvp`'d.

In none of these cases is secret material rendered in the error message.

## Secret never-rendered guarantees

- `--list` lists namespace names and variable names only. It never decrypts.
- `--unset` removes a credential file without decrypting or displaying it.
- `--list -v` / `--show-value` are **rejected**; no value-display command
  exists and none will be added. To inspect a value, run a trusted child via
  the execution path.
- Error messages are bounded in length and never echo plaintext. systemd-creds
  stderr is forwarded only after redaction/truncation.

## Atomicity

The durable unit is one variable, not a namespace. A multi-variable `--set`:

1. validates every name,
2. prompts and collects every plaintext value (memory only),
3. encrypts each to a `O_CREAT|O_EXCL|O_NOFOLLOW` staging file,
4. only after all succeed, atomically `rename()`s each into place and fsyncs.

A failure before step 4 unlinks all staging files and touches no live file. A
crash between two `rename()`s leaves a partial namespace (documented).

## Filesystem / race defenses

- Base and namespace directories are created `0700`; existing ones are
  tightened to `0700`. A symlinked store/namespace directory is refused.
- Cred files are opened for read with `O_NOFOLLOW`; a symlinked leaf is
  refused.
- The decrypt path opens the file itself (with `O_NOFOLLOW`), reads the
  ciphertext into memory, and feeds it to `systemd-creds decrypt` via a pipe.
  systemd-creds never opens a path itself, eliminating the O_CLOEXEC child-fd
  and TOCTOU between a symlink check and an open.
- Staging writes use `O_CREAT|O_EXCL|O_NOFOLLOW` and `rename()`.

## Subprocess observation

Because credchain uses `execvp` semantics, the credchain process image is
replaced by the target. Consequently:

- the target's exit status and Unix signals propagate directly to the parent
  (no wrapper to mask them), matching envchain;
- the credchain command line contains only `credchain <ns[,ns...]> <cmd> [args]`
  — never a secret. Secrets live only in the child's environment.

## systemd-creds backend notes

- Encryption uses `--user` (user-scoped key). No `systemd-creds setup` (that is
  a root-only, system-scope operation) and no polkit prompt.
- On this host (`systemd 261`), under `--user`, the `auto`/`host`/`host+tpm2`
  keys succeed; `tpm2`-only and `null` are refused in uid-scoped mode. credchain
  uses `--with-key=auto` under `--user`.
- The embedded credential name `credchain.<ns>.<VAR>` is passed explicitly on
  both encrypt and decrypt, so the on-disk filename is never trusted as the
  credential identity.

## Why no `--require-passphrase`

`--require-passphrase` is an envchain keychain ACL concept with no analogue in
systemd-creds. Silently accepting a security flag we cannot honor would be
dishonest, so credchain parses it (for interface clarity) and then fails with an
explicit nonzero exit and explanation. `--no-require-passphrase` is accepted
silently as redundant: it asks for the behavior systemd already provides.
