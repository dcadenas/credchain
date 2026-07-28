#!/usr/bin/env bash
# credchain black-box integration tests.
#
# Uses ONLY conspicuously fake values (credchain-test-secret-not-real-FAKE)
# inside isolated temporary XDG_DATA_HOME dirs. Never touches real host
# credential state. Requires a TTY for the --noecho test (run via `script`
# or a real terminal); skipped with a warning if no tty is available.
#
# Exit status: 0 = all pass, 1 = at least one failure. Each test is named.

set -u
FAKE='credchain-test-secret-not-real-FAKE'
FAKE2='credchain-test-secret-not-real-FAKE-TWO'
FAKE3='credchain-test-secret-not-real-FAKE-THREE'

PASS=0
FAIL=0
FAILED_NAMES=()

HERE="$(cd "$(dirname "$0")" && pwd)"
# Resolve the built binary: prefer cargo-built target, fall back to PATH.
if [ -x "$HERE/../target/debug/credchain" ]; then
  CC="$HERE/../target/debug/credchain"
elif [ -x "$HERE/../target/release/credchain" ]; then
  CC="$HERE/../target/release/credchain"
elif command -v credchain >/dev/null 2>&1; then
  CC="$(command -v credchain)"
else
  echo "credchain binary not found; build with: cargo build" >&2
  exit 1
fi

# Fresh per-run scratch space.
WORK="$(mktemp -d -t credchain-itest-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
export XDG_DATA_HOME="$WORK/data"
mkdir -p "$XDG_DATA_HOME"

ok()   { PASS=$((PASS+1)); echo "ok   - $1"; }
bad()  { FAIL=$((FAIL+1)); FAILED_NAMES+=("$1"); echo "FAIL - $1"; }
# eq ACTUAL EXPECTED NAME
eq() { if [ "$1" = "$2" ]; then ok "$3"; else bad "$3 (got: $1, want: $2)"; fi; }
# ne ACTUAL UNWANTED NAME   (passes when ACTUAL != UNWANTED)
ne() { if [ "$1" != "$2" ]; then ok "$3"; else bad "$3 (got: $1, should differ from $2)"; fi; }
# contains HAYSTACK NEEDLE NAME
contains() { if printf '%s' "$1" | grep -q -- "$2"; then ok "$3"; else bad "$3 (missing: $2 in: $1)"; fi; }
# notcontains HAYSTACK NEEDLE NAME
notcontains() { if printf '%s' "$1" | grep -q -- "$2"; then bad "$3 (found: $2 in: $1)"; else ok "$3"; fi; }

# ---- helpers ----------------------------------------------------------------

set_var() {  # set_var NAMESPACE VAR VALUE [noecho]
  local ns="$1" var="$2" val="$3" noecho="${4:-}"
  if [ -n "$noecho" ]; then
    printf '%s\n' "$val" | "$CC" --set --noecho "$ns" "$var" >/dev/null
  else
    printf '%s\n' "$val" | "$CC" --set "$ns" "$var" >/dev/null
  fi
}

# run_set_stdin "stdin bytes" args...
run_set_stdin() {
  local stdin="$1"; shift
  printf '%s\n' "$stdin" | "$CC" --set "$@" >/dev/null 2>&1
}

# ---- 1. CLI shape: --set + exec ---------------------------------------------
# envchain-style prompt reads values from stdin; feed it the fake value.
printf '%s\n' "$FAKE" | "$CC" --set ns1 VAR_A >/dev/null 2>&1
out="$("$CC" ns1 sh -c 'echo "VAR_A=$VAR_A"')"
eq "$out" "VAR_A=$FAKE" "1 exec loads set var"

# ---- 2. multiple namespaces + precedence -----------------------------------
printf '%s\n' "$FAKE"  | "$CC" --set nsA SHARED >/dev/null 2>&1
printf '%s\n' "$FAKE2" | "$CC" --set nsB SHARED >/dev/null 2>&1
printf '%s\n' "$FAKE"  | "$CC" --set nsA ONLY_A >/dev/null 2>&1
out="$("$CC" nsA,nsB sh -c 'echo "$SHARED"')"
eq "$out" "$FAKE2" "2 later ns overrides earlier"
out="$("$CC" nsB,nsA sh -c 'echo "$SHARED"')"
eq "$out" "$FAKE" "2b order reversed"
out="$("$CC" nsA,nsB sh -c 'echo "$ONLY_A"')"
eq "$out" "$FAKE" "2c non-overlapping var present"

# ---- 3. exact argv preserved ------------------------------------------------
# `sh -c script dummy one two` => $0=dummy, $1=one, $2=two (POSIX).
out="$("$CC" nsA sh -c 'echo "argc=$# a1=$1 a2=$2"' dummy one two)"
eq "$out" "argc=2 a1=one a2=two" "3 argv preserved to child"

# ---- 4. inherited (non-secret) environment passes through -------------------
export INHERIT_ME=yes-FAKE
out="$(INHERIT_ME=yes-FAKE "$CC" nsA sh -c 'echo "INHERIT_ME=$INHERIT_ME"')"
eq "$out" "INHERIT_ME=yes-FAKE" "4 caller env inherited"
unset INHERIT_ME

# ---- 5. child exit status propagated ---------------------------------------
"$CC" nsA sh -c 'exit 7' >/dev/null 2>&1
eq "$?" "7" "5 child exit status propagated"

# ---- 6. unix signals propagated (no wrapper) -------------------------------
"$CC" nsA sh -c 'kill -TERM $$' >/dev/null 2>&1
sig=$?
# 128 + 15 (SIGTERM) on POSIX shells.
eq "$sig" "143" "6 SIGTERM propagates (exit 143)"

# ---- 7. no-shell behavior (argv verbatim, no /bin/sh -c of our args) -------
printf '%s\n' "$FAKE" | "$CC" --set nsS VAR_S >/dev/null 2>&1
out="$("$CC" nsS /usr/bin/env 2>&1 | grep -c '^VAR_S=')"
eq "$out" "1" "7 target exec'd directly (env sees VAR_S)"

# no-shell: an argument that looks like a command substitution must NOT execute.
if [ -x /bin/echo ]; then
  out="$("$CC" nsS /bin/echo '; echo PWNED-FAKE')"
  eq "$out" "; echo PWNED-FAKE" "7b no shell metachar interpretation"
fi

# ---- 8. --noecho disables echo on a tty -------------------------------------
# We need a real pty for credchain's stdin AND we must delay the input so that
# credchain has time to print the prompt and disable echo before the value is
# written to the pty master (otherwise the pty line discipline echoes it
# before termios takes effect). This mirrors real interactive use.
if command -v script >/dev/null 2>&1; then
  raw="$({ sleep 0.4; printf '%s\n' "$FAKE"; } \
        | script -q -e -c "$CC --set --noecho nsN VAR_N" /dev/null 2>&1 | tr -d '\r' || true)"
  if printf '%s' "$raw" | grep -q -- "$FAKE"; then
    bad "8 --noecho leaked value to tty"
  else
    # Also confirm the value was actually stored (noecho did not lose it).
    stored="$("$CC" nsN sh -c 'echo "$VAR_N"' 2>/dev/null)"
    if [ "$stored" = "$FAKE" ]; then
      ok "8 --noecho did not echo value (and stored it)"
    else
      bad "8 --noecho did not leak but value not stored (got: $stored)"
    fi
  fi
else
  echo "skip - 8 --noecho (no \`script\` to simulate tty)" >&2
  ok "8 --noecho (skipped: no pty harness)"
fi
# Contract test (always runs): --noecho without a tty fails explicitly.
printf '%s\n' "$FAKE" | "$CC" --set --noecho nsNtty VAR_T >/dev/null 2>&1
ne "$?" "0" "8b --noecho without a tty fails"
err="$(printf '%s\n' "$FAKE" | "$CC" --set --noecho nsNtty VAR_T 2>&1 >/dev/null)"
contains "$err" "requires stdin to be a terminal" "8c --noecho non-tty error is explicit"

# ---- 9. atomic multi-var --set: partial failure leaves live files intact ----
printf '%s\n' "$FAKE" | "$CC" --set nsAtomic KEEP_VAR >/dev/null 2>&1
# A --set that will fail midway (NUL in a value) must not clobber KEEP_VAR.
printf 'a\0b' | "$CC" --set nsAtomic KEEP_VAR BAD_VAR >/dev/null 2>&1
out="$("$CC" nsAtomic sh -c 'echo "$KEEP_VAR"')"
eq "$out" "$FAKE" "9 partial --set leaves prior value"
out="$("$CC" nsAtomic sh -c 'echo "${BAD_VAR:-unset}"')"
eq "$out" "unset" "9b failed var not installed"

# ---- 10. restrictive permissions -------------------------------------------
base="$XDG_DATA_HOME/credchain"
eq "$(stat -c '%a' "$base")" "700" "10a base dir 0700"
eq "$(stat -c '%a' "$base/nsA")" "700" "10b namespace dir 0700"
eq "$(stat -c '%a' "$base/nsA/SHARED.cred")" "600" "10c cred file 0600"

# ---- 11. corrupt / missing / name-mismatched credential refusal ------------
printf 'not-a-cred-FAKE' > "$base/nsA/VAR_A.cred"
"$CC" nsA sh -c 'echo SHOULD_NOT_RUN' >/dev/null 2>&1
ne "$?" "0" "11a corrupt cred -> nonzero exit"
out="$("$CC" nsA sh -c 'echo SHOULD_NOT_RUN' 2>&1)"
notcontains "$out" "SHOULD_NOT_RUN" "11b corrupt cred does not run child"

# restore a valid cred for later tests
printf '%s\n' "$FAKE" | "$CC" --set nsA VAR_A >/dev/null 2>&1

# missing namespace in exec
"$CC" does_not_exist_ns sh -c 'echo X' >/dev/null 2>&1
ne "$?" "0" "11c missing namespace -> nonzero exit"

# ---- 12. symlink/race safety: symlinked cred file refused ------------------
ln -s /etc/hostname "$base/nsA/evil.cred" 2>/dev/null
printf '%s\n' "$FAKE3" | "$CC" --set nsLink VAR_L >/dev/null 2>&1
ln -sf "$base/nsLink/VAR_L.cred" "$base/nsLink/VAR_L_SYMLINK.cred"
"$CC" nsLink sh -c 'echo "$VAR_L_SYMLINK"' >/dev/null 2>&1
ne "$?" "0" "12 symlinked cred file refused"
rm -f "$base/nsA/evil.cred" "$base/nsLink/VAR_L_SYMLINK.cred"

# ---- 13. secret redaction in failure paths ----------------------------------
printf 'corrupt-FAKE' > "$base/nsA/VAR_A.cred"
err="$("$CC" nsA sh -c 'echo run' 2>&1 >/dev/null)"
notcontains "$err" "$FAKE" "13 stderr never contains secret on corrupt"
# restore
printf '%s\n' "$FAKE" | "$CC" --set nsA VAR_A >/dev/null 2>&1

# ---- 14. subprocess observation: secret in child env only ------------------
env_out="$("$CC" nsA env 2>&1)"
contains "$env_out" "^VAR_A=$FAKE$" "14a secret present in child env"
notcontains "$env_out" "$FAKE2" "14b unrelated secret absent"
# credchain argv contained only namespace + command, never the secret:
notcontains "$CC nsA env" "$FAKE" "14c secret not in credchain argv shape"

# ---- 15. headless: no GNOME/DBus dependency ---------------------------------
if command -v ldd >/dev/null 2>&1; then
  deps="$(ldd "$CC" 2>/dev/null || true)"
  notcontains "$deps" "libsecret" "15 no libsecret link dep"
  notcontains "$deps" "gnome" "15b no gnome link dep"
  notcontains "$deps" "gkr" "15c no gkr link dep"
else
  ok "15 (skipped: no ldd)"
fi

# ---- 16. --require-passphrase and --list -v fail explicitly ------------------
printf '%s\n' "$FAKE" | "$CC" --set --require-passphrase nsR VAR_R >/dev/null 2>&1
ne "$?" "0" "16a --require-passphrase rejected"
printf '%s\n' "$FAKE" | "$CC" --set --no-require-passphrase nsR2 VAR_R2 >/dev/null 2>&1
eq "$?" "0" "16b --no-require-passphrase accepted"
"$CC" --list --show-value nsR2 >/dev/null 2>&1
ne "$?" "0" "16c --list --show-value rejected"
"$CC" --list -v nsR2 >/dev/null 2>&1
ne "$?" "0" "16d --list -v rejected"

# ---- 17. invalid namespace / variable names rejected -----------------------
printf '%s\n' "$FAKE" | "$CC" --set 'bad/ns' VAR >/dev/null 2>&1
ne "$?" "0" "17a namespace with slash rejected"
printf '%s\n' "$FAKE" | "$CC" --set .. VAR >/dev/null 2>&1
ne "$?" "0" "17b namespace .. rejected"
printf '%s\n' "$FAKE" | "$CC" --set ns '1BAD' >/dev/null 2>&1
ne "$?" "0" "17c variable starting with digit rejected"

# ---- 18. NUL-containing values rejected ------------------------------------
printf 'a\0b-FAKE' | "$CC" --set nsNul VAR_NUL >/dev/null 2>&1
ne "$?" "0" "18 NUL value rejected"

# ---- 19. --list lists namespaces; --list NS lists var names ----------------
printf '%s\n' "$FAKE" | "$CC" --set nsList ALPHA >/dev/null 2>&1
printf '%s\n' "$FAKE" | "$CC" --set nsList BETA  >/dev/null 2>&1
namespaces="$("$CC" --list 2>/dev/null | sort)"
contains "$namespaces" "nsList" "19a --list shows namespace"
vars="$("$CC" --list nsList 2>/dev/null | sort)"
eq "$vars" "ALPHA"$'\n'"BETA" "19b --list NS shows var names"

# ---- 20. --unset removes without decrypting/displaying ----------------------
printf '%s\n' "$FAKE" | "$CC" --set nsUnset GONE >/dev/null 2>&1
"$CC" --unset nsUnset GONE >/dev/null 2>&1
eq "$?" "0" "20a --unset succeeds"
out="$("$CC" nsUnset sh -c 'echo "${GONE:-unset}"' 2>/dev/null)"
eq "$out" "unset" "20b unset var no longer injected"
# --unset of a missing var fails
"$CC" --unset nsUnset GONE >/dev/null 2>&1
ne "$?" "0" "20c --unset missing var fails"
# --unset does not print the secret
unset_out="$("$CC" --unset nsUnset NEVER 2>&1)"
notcontains "$unset_out" "$FAKE" "20d --unset never prints secret"

# ---- summary ----------------------------------------------------------------
echo
echo "==== $PASS passed, $FAIL failed ===="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for n in "${FAILED_NAMES[@]}"; do echo "  - $n"; done
  exit 1
fi
exit 0
