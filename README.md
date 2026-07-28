# credchain

A headless, local replacement for [envchain](https://github.com/sorah/envchain)
that preserves envchain's namespace-and-command workflow but stores secrets in
user-scoped **systemd-creds** encrypted credentials instead of GNOME Keyring /
D-Bus Secret Service. Works from terminals, SSH sessions, and unattended user
services — no graphical login, no polkit prompt, no desktop keyring.

## Why

envchain is convenient: you save secrets under a *namespace* and run a command
that injects just those variables into its environment. But envchain's Linux
backend needs the D-Bus Secret Service (GNOME Keyring / KeePassXC), which does
not run headless and does not work over plain SSH or inside unattended user
services.

credchain keeps envchain's interface and replaces the vault with
[`systemd-creds --user`](https://www.freedesktop.org/software/systemd/man/systemd-creds.html):
encrypted credentials whose key is derived from your UID, username, and
machine-id. No `setup`, no root, no polkit, no D-Bus.

## Requirements

- Linux with systemd ≥ 256 (user-scoped credentials; `--user` encryption). This
  host runs systemd 261.
- `systemd-creds` on `$PATH`.
- A Rust toolchain to build (or use a released binary).

## Install

```
cargo install --path .
# or
cargo build --release && cp target/release/credchain ~/.local/bin/
```

`credchain` is one executable with no GNOME/libsecret/D-Bus runtime dependency.
On the default GNU target it is dynamically linked to the ordinary platform
runtime (`libc`, `libgcc_s`); it is not a static/musl artifact unless a musl
build is explicitly produced and tested.

## Usage

Save variables (you are prompted for each value, like envchain):

```
$ credchain --set aws AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
aws.AWS_ACCESS_KEY_ID: <typed value>
aws.AWS_SECRET_ACCESS_KEY: <typed value>
```

Hide what you type with `--noecho` (requires a terminal):

```
$ credchain --set --noecho aws AWS_SECRET_ACCESS_KEY
aws.AWS_SECRET_ACCESS_KEY (noecho): <not echoed>
```

Run a command with those variables injected:

```
$ credchain aws env | grep AWS_
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
$ credchain aws s3cmd ...
```

Multiple namespaces, comma-separated, merged left to right (later override):

```
$ credchain aws,github env | grep -E 'AWS_|GITHUB_'
```

List namespaces / variables (never decrypts or prints values):

```
$ credchain --list
aws
github
$ credchain --list aws
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
```

Remove variables (does not decrypt or display the removed value):

```
$ credchain --unset aws AWS_SECRET_ACCESS_KEY
```

## Interface compatibility with envchain

| envchain                                | credchain                                           |
|-----------------------------------------|-----------------------------------------------------|
| `--set`/`-s` NAMESPACE ENV [ENV ..]     | same                                                |
| `--list` / `-l`                         | same                                                |
| `--list NAMESPACE`                      | same (lists variable names)                         |
| `--unset NAMESPACE ENV [ENV ..]`        | same                                                |
| `NAMESPACE[,NS...] COMMAND [ARG ...]`   | same (execvp, PATH lookup, no shell, inherits env)  |
| `--noecho`/`-n`                         | same (disables terminal echo; needs a tty)          |
| `--require-passphrase`/`-p`             | **rejected**: the systemd backend has no per-item passphrase |
| `--no-require-passphrase`/`-P`         | **accepted (redundant)**: systemd already behaves this way |
| `--list -v` / `--show-value`            | **rejected**: credchain never decrypts/prints values; run a trusted child to inspect a value |

Namespace names must match `[A-Za-z0-9._-]{1,63}` (path-safe; no `/`, no `..`).
Variable names must match `[A-Za-z_][A-Za-z0-9_]*`. Values may not contain NUL.

In exec mode, a named namespace that does not exist causes a nonzero exit
(fail-closed against typos); envchain silently skipped unknown namespaces.

## Storage layout

```
$XDG_DATA_HOME/credchain/        # or ~/.local/share/credchain/  (0700)
  <namespace>/                  # 0700
    <VAR>.cred                  # 0600, systemd-creds ciphertext
```

Each `<VAR>.cred` is a systemd-creds encrypted credential whose embedded name is
`credchain.<namespace>.<VAR>`. Decryption always passes that name explicitly, so
the on-disk filename is never trusted as the credential identity.

The durable unit is **one variable**, not a namespace-wide transaction. A
multi-variable `--set` validates every name, prompts and collects every value,
encrypts each to a staging file, and only then atomically renames all staging
files into place. A crash between two renames leaves a partial namespace.

## systemd service integration

When credchain runs inside a systemd user service that materialized credentials
via `LoadCredentialEncrypted=`, it prefers reading already-decrypted plaintext
from `$CREDENTIALS_DIRECTORY/credchain.<namespace>.<VAR>` instead of shelling
out to `systemd-creds decrypt`. Terminal execution decrypts the encrypted user
credentials directly. Example drop-in:

```ini
# ~/.config/systemd/user/myjob.service.d/creds.conf
[Service]
LoadCredentialEncrypted=credchain.aws.AWS_ACCESS_KEY_ID:%h/.local/share/credchain/aws/AWS_ACCESS_KEY_ID.cred
LoadCredentialEncrypted=credchain.aws.AWS_SECRET_ACCESS_KEY:%h/.local/share/credchain/aws/AWS_SECRET_ACCESS_KEY.cred
ExecStart=credchain aws /usr/local/bin/myjob
```

## Security boundary (honest limits)

- **At rest:** secrets are encrypted with the user-scoped systemd-creds key
  (TPM2 + host key when available; the user-scoped host key otherwise). The
  encrypted files are 0600 in a 0700 tree.
- **In transit to the child:** secrets reach the target only via its
  environment block. They are never placed in argv, the command line, logs,
  diagnostics, process titles, or filenames.
- **Not a sandbox:** the target process and its descendants can read any
  injected environment variable. This matches envchain. credchain improves
  storage/unlock, not runtime isolation.
- **Filesystem/race safety:** cred files are opened with `O_NOFOLLOW`; a
  symlinked `.cred` entry is refused fail-closed. Staging writes use
  `O_CREAT|O_EXCL|O_NOFOLLOW` plus an atomic `rename()`. Malformed ciphertext,
  name mismatches, missing files, NUL values, and invalid names all produce a
  nonzero exit with no secret rendered.

See [docs/SECURITY.md](docs/SECURITY.md) and
[docs/superpowers/specs/2026-07-27-credchain-design.md](docs/superpowers/specs/2026-07-27-credchain-design.md)
for the full design.

## Migrating from envchain

`scripts/migrate-from-envchain.sh` copies every envchain namespace/variable
into credchain under the **same** namespace and variable name. The plaintext
secret transits only through a kernel pipe from `envchain <ns> printenv <VAR>`
into `credchain --set <ns> <VAR>` — it is never displayed, written to disk,
placed in argv, or logged (only namespace/variable *names* are printed to
stderr).

```
# dry-run: list what would be migrated, copy nothing
scripts/migrate-from-envchain.sh --dry-run

# migrate everything from `envchain --list`
scripts/migrate-from-envchain.sh

# migrate only specific namespaces
scripts/migrate-from-envchain.sh aws github
```

**Limitations:**
- A value that itself contains a newline is truncated to its first line
  (credchain reads one line per `--set`). Most envchain secrets (API keys,
  tokens) are single-line; PEM/private-key blocks are not and must be
  re-entered by hand with `--noecho`.
- envchain's `--require-passphrase` per-item ACL does **not** carry over — the
  systemd backend has no per-item passphrase concept (see README § Interface
  compatibility).

## Testing

```
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test                     # unit + smoke tests
bash tests/integration.sh      # black-box contract tests (43 scenarios)
```

The integration suite requires systemd ≥ 256 (for `systemd-creds --user`
encryption); it does **not** run on Ubuntu 24.04 / `ubuntu-latest`
(systemd 255.4). In CI it runs on `ubuntu-26.04` (currently a
[public-preview](https://github.com/actions/runner-images) runner image,
systemd 259.5) after asserting the version. The build/clippy/unit/smoke/release
job runs on `ubuntu-latest`.

The integration suite uses only conspicuously fake values
(`credchain-test-secret-not-real-FAKE`) inside isolated `$XDG_DATA_HOME`
temp dirs. It never touches real host credential state.

## License

MIT. See [LICENSE](LICENSE).
