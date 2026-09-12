#!/usr/bin/env bash
# migrate-from-envchain.sh — copy every envchain namespace/variable into
# credchain, same namespace and variable name.
#
# Safety model
#   The plaintext secret transits ONLY through a kernel pipe between two
#   processes: `envchain <ns> printenv <VAR>` (which decrypts from the keyring
#   and writes the value to its stdout) piped directly into
#   `credchain --set <ns> <VAR>` (which reads the value from its stdin and
#   re-encrypts it under the systemd-creds user key). The value is never:
#     - printed to the terminal (no echo; credchain --set reads the pipe
#       silently — it does NOT echo piped input),
#     - written to a file on disk,
#     - placed in any process's argv,
#     - logged. Only namespace/variable NAMES are printed, to stderr.
#
# Limitations (read before relying on this)
#   1. Multi-line values: credchain --set reads ONE LINE from stdin per
#      variable (it strips a trailing newline). A value that itself contains a
#      newline will be TRUNCATED to its first line. Most envchain secrets are
#      single-line (API keys, tokens); PEM/private-key blocks are multi-line
#      and will NOT migrate correctly with this script. For those, wait for a
#      binary-safe credchain input mode or paste them by hand with --noecho.
#   2. `--require-passphrase` envchain items: envchain may prompt you to unlock
#      the keyring for them. That is expected. credchain stores the re-encrypted
#      value WITHOUT a per-item passphrase gate (the systemd backend has none);
#      the envchain ACL does not carry over. This is the documented
#      incompatibility in credchain's README.
#   3. If a variable already exists in credchain under the same namespace, it
#      is overwritten (atomic per-variable rename).
#
# Usage
#   migrate-from-envchain.sh                 # all namespaces from `envchain --list`
#   migrate-from-envchain.sh nsA nsB          # only the listed namespaces
#   migrate-from-envchain.sh --dry-run       # list what would be migrated, copy nothing
#   migrate-from-envchain.sh --namespace NS  # limit to one namespace
#
# Exit status: 0 if everything migrated; non-zero if any variable failed.
set -euo pipefail

# Bounded, value-free diagnostic files. mktemp keeps them out of a predictable
# shared path; the trap removes them on every exit.
ENVCHAIN_ERR="$(mktemp "${TMPDIR:-/tmp}/envchain-migrate.XXXXXX")"
CREDCHAIN_ERR="$(mktemp "${TMPDIR:-/tmp}/credchain-migrate.XXXXXX")"
trap 'rm -f "$ENVCHAIN_ERR" "$CREDCHAIN_ERR"' EXIT

DRY_RUN=0
EXPLICIT_NS=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift;;
    --namespace)
      [ "$#" -ge 2 ] || { echo "--namespace requires a value" >&2; exit 2; }
      EXPLICIT_NS+=("$2"); shift 2;;
    -h|--help)
      sed -n '2,38p' "$0"; exit 0;;
    --) shift; break;;
    -*) echo "unknown option: $1" >&2; exit 2;;
    *) EXPLICIT_NS+=("$1"); shift;;
  esac
done

# Locate the binaries. Override with ENVOCHAIN=... / CREDCHAIN=... if needed.
ENVCHAIN_BIN="${ENVCHAIN_BIN:-envchain}"
CREDCHAIN_BIN="${CREDCHAIN_BIN:-credchain}"

command -v "$ENVCHAIN_BIN" >/dev/null 2>&1 || { echo "envchain not found on PATH" >&2; exit 127; }
command -v "$CREDCHAIN_BIN" >/dev/null 2>&1 || { echo "credchain not found on PATH" >&2; exit 127; }

# Do NOT enable `set -x` — it would log pipe contents indirectly. Keep it off.
fail=0
total=0

migrate_var() {
  local ns="$1" var="$2"
  total=$((total+1))
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "dry-run: would migrate $ns/$var" >&2
    return 0
  fi
  # The pipe: envchain decrypts the value to stdout; credchain reads it from
  # stdin and re-encrypts. No tmpfile, no echo, no argv carries the value.
  # `printenv <VAR>` prints `VALUE\n`; credchain --set reads one line and strips
  # the trailing newline.
  if ! "$ENVCHAIN_BIN" "$ns" printenv "$var" 2>"$ENVCHAIN_ERR" \
        | "$CREDCHAIN_BIN" --set "$ns" "$var" >/dev/null 2>"$CREDCHAIN_ERR"; then
    echo "FAIL: $ns/$var (envchain or credchain error)" >&2
    # Surface a bounded, value-free error snippet.
    head -3 "$ENVCHAIN_ERR" 2>/dev/null >&2 || true
    head -3 "$CREDCHAIN_ERR" 2>/dev/null >&2 || true
    fail=$((fail+1))
    return 1
  fi
  echo "ok: $ns/$var" >&2
  return 0
}

if [ "${#EXPLICIT_NS[@]}" -gt 0 ]; then
  namespaces=("${EXPLICIT_NS[@]}")
else
  mapfile -t namespaces < <("$ENVCHAIN_BIN" --list 2>/dev/null)
fi

for ns in "${namespaces[@]:-}"; do
  [ -n "$ns" ] || continue
  mapfile -t vars < <("$ENVCHAIN_BIN" --list "$ns" 2>/dev/null)
  if [ "${#vars[@]}" -eq 0 ]; then
    echo "skip: namespace $ns has no variables (or envchain could not list it)" >&2
    continue
  fi
  for var in "${vars[@]}"; do
    [ -n "$var" ] || continue
    migrate_var "$ns" "$var" || true
  done
done

echo "migrated $((total-fail))/$total variables ($fail failed)" >&2
[ "$fail" -eq 0 ]
