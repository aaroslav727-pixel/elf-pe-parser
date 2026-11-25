#!/usr/bin/env bash
# Verify binsec's checksec verdicts on the binaries built by samples/build.sh.
# usage: samples/check.sh [path/to/binsec]
set -uo pipefail
BINSEC=${1:-build/binsec}
DIR="$(dirname "$0")/bin"
fail=0

expect() {
  local f=$1
  shift
  [ -f "$DIR/$f" ] || { echo "skip $f (not built)"; return; }
  local out
  if ! out=$("$BINSEC" "$DIR/$f" --checksec --json); then
    echo "FAIL $f: binsec exited with an error"
    fail=1
    return
  fi
  local p
  for p in "$@"; do
    if ! grep -qF -- "$p" <<<"$out"; then
      echo "FAIL $f: expected $p"
      fail=1
      return
    fi
  done
  echo "ok   $f"
}

expect full       '"relro": "full"' '"pie": "pie"' '"nx": true' '"canary": true' '"fortify": true' '"stripped": false'
expect partial    '"relro": "partial"' '"pie": "pie"'
expect nopie      '"relro": "full"' '"pie": "no"'
expect norelro    '"relro": "none"'
expect execstack  '"nx": false'
expect nocanary   '"canary": false' '"fortify": false'
expect canary     '"canary": true'
expect rpath      '"rpath": "/opt/binsec/lib"' '"runpath": null'
expect runpath    '"runpath": "$ORIGIN/lib"' '"rpath": null'
expect stripped   '"stripped": true'
expect libdemo.so '"pie": "dso"'
expect hello64.exe '"format": "PE"' '"class": "PE32+"'
expect hello32.exe '"format": "PE"' '"class": "PE32"'
exit $fail
