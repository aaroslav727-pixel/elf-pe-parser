#!/usr/bin/env bash
# Build sample ELF binaries with different hardening flags into samples/bin/.
# Linux only. PE samples are built too when a MinGW cross compiler is installed.
set -euo pipefail
cd "$(dirname "$0")"
CC=${CC:-cc}
OUT=bin
mkdir -p "$OUT"

b() {
  local name=$1
  shift
  echo "  $name: $*"
  "$CC" "$@" -o "$OUT/$name"
}

echo "building samples with $CC"
b full       hello.c -O2 -fPIE -pie -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now -Wl,-z,noexecstack
b partial    hello.c -O2 -fPIE -pie -fstack-protector-strong -Wl,-z,relro,-z,lazy
b nopie      hello.c -O2 -fno-pie -no-pie -fstack-protector-strong -Wl,-z,relro,-z,now
b norelro    hello.c -O2 -fno-pie -no-pie -Wl,-z,norelro
b execstack  hello.c -O2 -Wl,-z,execstack
b nocanary   hello.c -O2 -fno-stack-protector -U_FORTIFY_SOURCE
b canary     hello.c -O0 -fstack-protector-all -U_FORTIFY_SOURCE
b rpath      hello.c -O2 -Wl,--disable-new-dtags,-rpath,/opt/binsec/lib
b runpath    hello.c -O2 '-Wl,--enable-new-dtags,-rpath,$ORIGIN/lib'
b stripped   hello.c -O2 -s
b libdemo.so libdemo.c -O2 -fPIC -shared

if command -v x86_64-w64-mingw32-gcc >/dev/null; then
  echo "  hello64.exe (MinGW)"
  x86_64-w64-mingw32-gcc hello.c -O2 -o "$OUT/hello64.exe"
fi
if command -v i686-w64-mingw32-gcc >/dev/null; then
  echo "  hello32.exe (MinGW)"
  i686-w64-mingw32-gcc hello.c -O2 -o "$OUT/hello32.exe"
fi
echo "done: $(ls "$OUT" | wc -l) file(s) in samples/$OUT"
