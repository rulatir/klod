#!/bin/bash
#
# Test suite for klod — verifies that .agentsdeny entries actually BLOCK
# access to the named files/dirs inside the bwrap sandbox.
#
# Focus: path-style entries like ".env" and "apps/cms/.env".
#
# The invariant we assert is content-based, not error-string based:
#   - A DENIED file's secret content must never be visible inside the sandbox.
#   - A file that is NOT listed must remain readable.
# (klod surfaces a denial as EACCES "Permission denied" because it binds
# /dev/null / a mode-000 dir over the target, but we don't rely on the exact
# error text — locale-dependent — only on the secret never leaking.)

set -u

KLOD="${KLOD:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/klod}"

if [[ ! -x "$KLOD" ]]; then
  echo "FATAL: klod not found or not executable at: $KLOD" >&2
  exit 2
fi
if ! command -v bwrap >/dev/null 2>&1; then
  echo "FATAL: bwrap (bubblewrap) is not installed — klod cannot run." >&2
  exit 2
fi

PASS=0
FAIL=0
FAILED_NAMES=()

# --- helpers ---------------------------------------------------------------

# run_klod <project_dir> <shell-commands>
# Feeds shell-commands to the bash launched inside the klod sandbox and
# echoes the combined stdout+stderr.
run_klod() {
  local dir="$1" cmds="$2"
  printf '%s\n' "$cmds" | "$KLOD" "$dir" 2>&1
}

ok()   { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
nope() { FAIL=$((FAIL+1)); FAILED_NAMES+=("$1"); printf '  FAIL %s\n     %s\n' "$1" "$2"; }

# assert_blocked <name> <project_dir> <relpath> <marker>
# Passes iff reading <relpath> inside the sandbox does NOT reveal <marker>.
assert_blocked() {
  local name="$1" dir="$2" rel="$3" marker="$4"
  local out
  out=$(run_klod "$dir" "cat -- '$rel'")
  if [[ "$out" == *"$marker"* ]]; then
    nope "$name" "secret marker '$marker' LEAKED from '$rel' — block failed. Output: $out"
  else
    ok "$name"
  fi
}

# assert_readable <name> <project_dir> <relpath> <marker>
# Passes iff reading <relpath> inside the sandbox DOES reveal <marker>.
assert_readable() {
  local name="$1" dir="$2" rel="$3" marker="$4"
  local out
  out=$(run_klod "$dir" "cat -- '$rel'")
  if [[ "$out" == *"$marker"* ]]; then
    ok "$name"
  else
    nope "$name" "expected marker '$marker' from '$rel' but did not see it. Output: $out"
  fi
}

# Make a fresh fixture project. Echoes its path.
# Layout:
#   .env                  -> marker SECRET_ROOT
#   apps/cms/.env         -> marker SECRET_CMS
#   apps/web/.env         -> marker SECRET_WEB   (same basename, different dir)
#   apps/cms/config.txt   -> marker PUBLIC_CMS
#   README.md             -> marker PUBLIC_ROOT
make_fixture() {
  local d
  d=$(mktemp -d "${TMPDIR:-/tmp}/klod-test.XXXXXX")
  mkdir -p "$d/apps/cms" "$d/apps/web"
  printf 'SECRET_ROOT\n'  > "$d/.env"
  printf 'SECRET_CMS\n'   > "$d/apps/cms/.env"
  printf 'SECRET_WEB\n'   > "$d/apps/web/.env"
  printf 'PUBLIC_CMS\n'   > "$d/apps/cms/config.txt"
  printf 'PUBLIC_ROOT\n'  > "$d/README.md"
  printf '%s\n' "$d"
}

# fixtures created here are tracked for cleanup
FIXTURES=()
new_fixture() { local d; d=$(make_fixture); FIXTURES+=("$d"); printf '%s\n' "$d"; }

cleanup() {
  local d
  for d in "${FIXTURES[@]:-}"; do
    [[ -n "$d" && -d "$d" ]] || continue
    # .bwrap-deny is mode 000; restore perms so rm can recurse.
    chmod -R u+rwx "$d" 2>/dev/null
    rm -rf "$d"
  done
}
trap cleanup EXIT

# --- tests -----------------------------------------------------------------

echo "klod test suite"
echo "  KLOD=$KLOD"
echo

# Group 1: the core requirement — path entries .env and apps/cms/.env block.
echo "[core] .agentsdeny with: .env  +  apps/cms/.env"
D=$(new_fixture)
printf '.env\napps/cms/.env\n' > "$D/.agentsdeny"
assert_blocked  "root .env is blocked"                 "$D" ".env"               "SECRET_ROOT"
assert_blocked  "nested apps/cms/.env is blocked"      "$D" "apps/cms/.env"      "SECRET_CMS"
assert_readable "non-listed apps/cms/config.txt reads" "$D" "apps/cms/config.txt" "PUBLIC_CMS"
assert_readable "non-listed README.md reads"           "$D" "README.md"          "PUBLIC_ROOT"
# Path-specificity: a same-basename .env in a dir that is NOT listed must
# stay readable. Guards against accidental basename-only matching.
assert_readable "non-listed apps/web/.env stays open"  "$D" "apps/web/.env"      "SECRET_WEB"
echo

# Group 2: negative control — without a deny entry, .env IS readable.
# Proves a "blocked" result elsewhere is real blocking, not a broken sandbox.
echo "[control] no .agentsdeny entry => .env readable"
D=$(new_fixture)
: > "$D/.agentsdeny"   # empty deny list
assert_readable "empty deny list leaves .env readable" "$D" ".env" "SECRET_ROOT"
echo

# Group 3: absolute-path entry blocks the same nested file.
echo "[absolute] absolute path entry for apps/cms/.env"
D=$(new_fixture)
printf '%s\n' "$D/apps/cms/.env" > "$D/.agentsdeny"
assert_blocked  "absolute apps/cms/.env is blocked"    "$D" "apps/cms/.env"      "SECRET_CMS"
assert_readable "sibling apps/web/.env still readable"  "$D" "apps/web/.env"      "SECRET_WEB"
echo

# Group 4: writes to a blocked file are denied too (no exfil/modify).
echo "[write] blocked .env cannot be written"
D=$(new_fixture)
printf '.env\n' > "$D/.agentsdeny"
out=$(run_klod "$D" "echo PWNED > .env; echo done")
# The real file on disk (outside the sandbox) must still hold the original.
if grep -q 'PWNED' "$D/.env"; then
  nope "write to blocked .env is denied" "host .env was modified to: $(cat "$D/.env")"
else
  ok "write to blocked .env is denied"
fi
echo

# Group 5: directory entry blocks everything beneath it.
echo "[dir] listing a directory blocks its contents"
D=$(new_fixture)
printf 'apps/cms\n' > "$D/.agentsdeny"
assert_blocked  "apps/cms/.env blocked via dir entry"   "$D" "apps/cms/.env"      "SECRET_CMS"
assert_blocked  "apps/cms/config.txt blocked via dir"   "$D" "apps/cms/config.txt" "PUBLIC_CMS"
assert_readable "apps/web/.env outside dir is readable"  "$D" "apps/web/.env"      "SECRET_WEB"
echo

# Group 6: comments, blank lines and trailing whitespace are ignored/handled.
echo "[parse] comments, blanks, trailing whitespace"
D=$(new_fixture)
printf '# a comment\n\n.env   \n   # indented comment\napps/cms/.env\t\n' > "$D/.agentsdeny"
assert_blocked  "entry with trailing spaces still blocks" "$D" ".env"          "SECRET_ROOT"
assert_blocked  "entry with trailing tab still blocks"    "$D" "apps/cms/.env" "SECRET_CMS"
assert_readable "commented-out lines do not block reads"  "$D" "README.md"     "PUBLIC_ROOT"
echo

# Group 7: leaked-access defense — try alternative read paths for .env.
echo "[robust] blocked .env stays secret via multiple read methods"
D=$(new_fixture)
printf '.env\n' > "$D/.agentsdeny"
for method in "cat .env" "head -n1 .env" "grep . .env" "read x < .env; echo \$x"; do
  out=$(run_klod "$D" "$method" )
  if [[ "$out" == *"SECRET_ROOT"* ]]; then
    nope "method leaks: $method" "leaked via '$method': $out"
  else
    ok "no leak via: $method"
  fi
done
echo

# Group 8: entries that do not exist yet are created, then masked.
# bwrap binds onto an existing path only, so a target that is absent when the
# sandbox starts gets no mask at all — and whatever creates it later, inside
# the sandbox, gets a fully readable file. klod must create it first.
echo "[missing] deny entries that do not exist yet are created and masked"
D=$(new_fixture)
printf '.env-secrets\nlater/dir/\n' > "$D/.agentsdeny"

run_klod "$D" "true" >/dev/null
if [[ -f "$D/.env-secrets" ]]; then
  ok "missing file entry is created on the host"
else
  nope "missing file entry is created on the host" "$D/.env-secrets was not created"
fi
if [[ -d "$D/later/dir" ]]; then
  ok "missing entry with a trailing slash becomes a directory"
else
  nope "missing entry with a trailing slash becomes a directory" "$D/later/dir is not a directory"
fi

# The regression itself: a secret written to the once-missing path inside the
# sandbox must not read back, because the path is bound to /dev/null.
out=$(run_klod "$D" "echo SECRET_LATER > .env-secrets; cat -- .env-secrets")
if [[ "$out" == *"SECRET_LATER"* ]]; then
  nope "once-missing .env-secrets is masked" "secret read back from a path that did not exist at mask time: $out"
else
  ok "once-missing .env-secrets is masked"
fi
if grep -q 'SECRET_LATER' "$D/.env-secrets" 2>/dev/null; then
  nope "write to a once-missing entry does not reach the host" "host .env-secrets holds: $(cat "$D/.env-secrets")"
else
  ok "write to a once-missing entry does not reach the host"
fi

# Missing targets outside the project are never created: they belong to the
# system (/run/docker.sock appears when docker runs). A relative entry must not
# escape the project with ".." either.
D2=$(new_fixture)
OUTSIDE="$(dirname "$D2")/klod-outside-$$.txt"
rm -f "$OUTSIDE"
printf '%s\n../klod-outside-%s.txt\n' "/run/klod-nonexistent-$$.sock" "$$" > "$D2/.agentsdeny"
run_klod "$D2" "true" >/dev/null
if [[ -e "/run/klod-nonexistent-$$.sock" ]]; then
  nope "absolute path outside the project is not created" "klod created /run/klod-nonexistent-$$.sock"
else
  ok "absolute path outside the project is not created"
fi
if [[ -e "$OUTSIDE" ]]; then
  nope "relative entry cannot escape the project with .." "klod created $OUTSIDE"
  rm -f "$OUTSIDE"
else
  ok "relative entry cannot escape the project with .."
fi

# A directory created from a trailing-slash entry blocks what is put in it.
out=$(run_klod "$D" "echo SECRET_INDIR > later/dir/f 2>/dev/null; cat -- later/dir/f 2>/dev/null; echo done")
if [[ "$out" == *"SECRET_INDIR"* ]]; then
  nope "once-missing directory entry is masked" "secret readable under later/dir: $out"
else
  ok "once-missing directory entry is masked"
fi
echo

# Group 9: "~" and environment variables in entries are expanded.
echo "[expand] ~ and environment variables"
D=$(new_fixture)
mkdir -p "$D/fakehome"
printf 'SECRET_HOME\n' > "$D/fakehome/.netrc"
printf 'SECRET_DOLLAR\n' > "$D/price\$"
printf '%s\n' '~/.netrc' '$KLOD_T_DIR/apps/cms/.env' '${KLOD_T_DIR}/apps/web/.env' \
  'price$' '$KLOD_T_UNSET/README.md' '$(touch pwned)' > "$D/.agentsdeny"
export KLOD_T_DIR="$D"
unset KLOD_T_UNSET
run_out=$(HOME="$D/fakehome" run_klod "$D" "cat -- '$D/fakehome/.netrc' apps/cms/.env apps/web/.env 'price\$' README.md")
[[ "$run_out" != *SECRET_HOME* ]] && ok "~/ entry is blocked" \
  || nope "~/ entry is blocked" "$run_out"
[[ "$run_out" != *SECRET_CMS* ]] && ok "\$VAR entry is blocked" \
  || nope "\$VAR entry is blocked" "$run_out"
[[ "$run_out" != *SECRET_WEB* ]] && ok "\${VAR} entry is blocked" \
  || nope "\${VAR} entry is blocked" "$run_out"
[[ "$run_out" != *SECRET_DOLLAR* ]] && ok "\$ without a name stays literal" \
  || nope "\$ without a name stays literal" "$run_out"
[[ "$run_out" == *PUBLIC_ROOT* && ! -e "$D/\$KLOD_T_UNSET" ]] \
  && ok "entry with an unset variable is skipped" \
  || nope "entry with an unset variable is skipped" "$run_out"
[[ "$run_out" == *"unset variable KLOD_T_UNSET"* ]] && ok "unset variable produces a warning" \
  || nope "unset variable produces a warning" "$run_out"
[[ ! -e "$D/pwned" ]] && ok "command substitution is not run" \
  || nope "command substitution is not run" "$D/pwned exists"
unset KLOD_T_DIR
echo

# --- summary ---------------------------------------------------------------

echo "============================================"
echo "PASS: $PASS   FAIL: $FAIL"
if (( FAIL > 0 )); then
  printf 'Failed:\n'
  printf '  - %s\n' "${FAILED_NAMES[@]}"
  exit 1
fi
echo "All tests passed."
exit 0
