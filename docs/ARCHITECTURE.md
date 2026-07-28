# credchain architecture

```
                ┌──────────────────────────────────────────────┐
                │  credchain (one Rust executable, no GNOME/dbus deps) │
                │                                              │
   --set ─────► │  input.rs  ──prompt (termios noecho)──► Vec<u8>│
                │     │                                        │
                │     ▼                                        │
                │  store.rs ──validate names, 0700/0600,      │
                │             O_NOFOLLOW, atomic staging+rename │
                │     │                                        │
                │     ▼                                        │
                │  creds.rs ──spawn──► systemd-creds encrypt    │
                │     │                 --user --with-key=auto  │
                │     │                 --name=credchain.<ns>.<VAR>│
                │     ▼                                        │
                │  $XDG_DATA_HOME/credchain/<ns>/<VAR>.cred     │
                │                                              │
   exec  ─────► │  store.rs ──list_vars (fail-closed on symlink)│
                │     │                                        │
                │     ▼                                        │
                │  creds.rs ──open O_NOFOLLOW ─► read ciphertext│
                │     │         ──pipe──► systemd-creds decrypt│
                │     ▼                                        │
                │  exec.rs ──Command::env(k,v) + exec()       │
                │     │         (execvp: PATH lookup, no shell,│
                │     │          replaces process image)       │
                │     ▼                                        │
                │   target process (secrets only in env)       │
                └──────────────────────────────────────────────┘

   $CREDENTIALS_DIRECTORY present? ──► creds.rs reads already-decrypted
                                       plaintext from there instead of
                                       decrypting (service integration).
```

## Modules

- `main.rs` — CLI parsing and dispatch (`--set`, `--list`, `--unset`, exec).
  Validates the three intentional incompatibilities (`--require-passphrase`,
  `--list -v`, etc.).
- `store.rs` — name validation, path resolution, secure directory creation,
  `O_NOFOLLOW` opens, atomic staging+rename, fail-closed variable listing.
- `creds.rs` — `systemd-creds` wrapper: encrypt-to-file (plaintext via stdin
  pipe), decrypt-to-memory (ciphertext read by credchain with `O_NOFOLLOW`,
  piped to `systemd-creds decrypt`), and the `$CREDENTIALS_DIRECTORY` service
  integration read.
- `input.rs` — value prompting. Echo mode reads a line from stdin; noecho mode
  disables terminal echo via `termios`, reads, restores.
- `exec.rs` — merges namespaces left-to-right (later override), resolves each
  variable, sets them on a `Command`, and `exec()`s the target (replacing the
  credchain process image → execvp semantics).

## Data flow guarantees

- Plaintext is transported only via pipes and held only in memory buffers.
  It is never written to a normal file.
- The only files credchain creates are systemd-creds ciphertext outputs and
  the staging files that are immediately renamed into place.
- The single external dependency is the `libc` crate (constants/primitives).
  There is no link dependency on libsecret, GNOME, or D-Bus.

## See also

- [SECURITY.md](SECURITY.md) — threat model, fail-closed behavior, limits.
- [superpowers/specs/2026-07-27-credchain-design.md](superpowers/specs/2026-07-27-credchain-design.md)
  — full design and decision rationale.
