# binsec: ELF/PE parser with checksec and fuzzing

`binsec` is a small C++20 tool (standard library only) that parses ELF and PE
binaries and reports which exploit mitigations they were built with, the same
way `checksec` does. The parser is fuzzed with libFuzzer, ASan and UBSan.

## The story

1. **Parser.** Binaries are untrusted input, so the parser treats every byte
   as hostile. All reads go through a bounds-checked `Reader`/`Cursor`. A read
   outside the buffer becomes an error value, never UB or a crash. Errors come
   back as `Result<T>` (a C++20 stand-in for `std::expected`). Nothing throws
   across the API, and the library never calls `exit()`. It parses ELF32/ELF64
   in both byte orders: header, program headers, section headers, `.symtab`,
   `.dynsym` and the dynamic section.
2. **Checksec.** The parsed model answers the usual hardening questions. For
   ELF: RELRO, PIE, NX, stack canary, FORTIFY_SOURCE, RPATH/RUNPATH and
   stripped. Output is a readable table or `--json`. The verdicts were
   cross-checked against `readelf` and `objdump -p`.
3. **Fuzzing.** `fuzz/fuzz_parser.cpp` sends arbitrary bytes through format
   detection, the parsers, checksec and both renderers under
   ASan+UBSan. Every saved crash input and every corpus seed is replayed by the
   unit tests as a regression test.
4. **PE.** The same design extends to PE/COFF: DOS header (`e_lfanew` is
   bounds-checked), PE signature, COFF header, optional header PE32/PE32+,
   sections, imports and exports. PE checksec covers ASLR, HighEntropyVA,
   DEP/NX, CFG, SafeSEH, /GS and Authenticode. The format is detected from the
   magic bytes (`\x7fELF` or `MZ`). Anything else gets a clear
   `unknown-format` error.

How each verdict is computed: [docs/checks.md](docs/checks.md).

## Build (Linux / WSL2)

The supported build platform is **Linux** (for example WSL2 Ubuntu 24.04) with
**Clang 18+** and **CMake 3.25+**. libFuzzer and ASan don't work properly with
MinGW on Windows, so build the fuzzer on Linux or WSL.

```sh
cmake -S . -B build -DCMAKE_CXX_COMPILER=clang++
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Options: `BINSEC_BUILD_TESTS=ON` (default) and `BINSEC_BUILD_FUZZER=OFF`
(default; Clang only).

## Windows app

`binsec-gui.exe` is a native Win32 window over the same library (no external
dependencies, statically linked, a single file):

- open a file with **Open file...** (Ctrl+O), drag-and-drop, or
  `binsec-gui.exe <file>` (works with Explorer's *Open with*);
- views: **Checksec**, **Sections**, **Symbols / imports**, **All**, and a
  **JSON** switch that shows exactly what `binsec --json` prints;
- **Save report...** (Ctrl+S) writes the current view to `.txt` or `.json`.

Download `binsec-gui.exe` (and the console `binsec.exe`) from
[Releases](../../releases). The binaries are not code-signed, so SmartScreen
may ask for confirmation on the first run.

Build them yourself with MSYS2 (CLANG64 shell, packages
`mingw-w64-clang-x86_64-{clang,cmake,ninja}`):

```sh
cmake -S . -B build-release -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXE_LINKER_FLAGS=-static
cmake --build build-release
```

## Usage

```
binsec <file> [--checksec] [--sections] [--symbols] [--all] [--json]
```

| flag | shows |
|------|-------|
| *(none)* / `--checksec` | header summary + hardening audit |
| `--sections` | ELF program and section headers / PE sections |
| `--symbols` | ELF `.dynsym` and `.symtab` / PE imports and exports |
| `--all` | everything, plus the ELF dynamic section / PE data directories |
| `--json` | the same information as JSON |

Exit codes: `0` ok, `1` I/O or parse error (with `--json` the error is printed
as JSON), `2` usage error.

### Example: hardened x86-64 ELF

The ELF was built from `samples/` code with
`-fPIE -pie -fstack-protector-strong -Wl,-z,relro,-z,now`:

```
$ binsec hello-hardened
File:        hello-hardened
Format:      ELF64, little-endian
Type:        DYN (Shared object / PIE)
Machine:     AMD x86-64
Entry point: 0x13d0
Interpreter: /lib64/ld-linux-x86-64.so.2
Headers:     9 program, 18 section

Checksec
  RELRO         Full RELRO
  Canary        Canary found
  NX            NX enabled
  PIE           PIE enabled
  Fortify       Yes (1 fortified function)
  RPATH         No RPATH
  RUNPATH       No RUNPATH
  Stripped      No
```

### Example: `/bin/ls` on the `ubuntu-latest` CI runner

```
$ binsec /bin/ls
File:        /bin/ls
Format:      ELF64, little-endian
Type:        DYN (Shared object / PIE)
Machine:     AMD x86-64
Entry point: 0x109930
Interpreter: /lib64/ld-linux-x86-64.so.2
Headers:     15 program, 34 section

Checksec
  RELRO         Full RELRO
  Canary        Canary found
  NX            NX enabled
  PIE           PIE enabled
  Fortify       Yes (3 fortified functions)
  RPATH         No RPATH
  RUNPATH       No RUNPATH
  Stripped      Yes (no .symtab)
```

### Example: test PE (`samples/hello.c` built with MinGW clang)

```
$ binsec hello.exe
File:        hello.exe
Format:      PE32+ (64-bit)
Type:        Executable
Machine:     AMD x86-64
Subsystem:   Windows CUI
Image base:  0x140000000
Entry point: 0x13d0 (RVA)
Sections:    6

Checksec
  ASLR          Yes (DYNAMIC_BASE)
  HighEntropyVA Yes
  DEP/NX        Yes (NX_COMPAT)
  CFG           No (GUARD_CF)
  SafeSEH       N/A (64-bit: table-based exception handling)
  /GS           No
  Authenticode  No
```

```
$ binsec hello.exe --json
{
  "file": "hello.exe",
  "format": "PE",
  "header": {
    "class": "PE32+",
    "type": "Executable",
    "machine": "AMD x86-64",
    "subsystem": "Windows CUI",
    "image_base": "0x140000000",
    "entry_point_rva": "0x13d0",
    "dll_characteristics": "0x8160",
    "sections": 6
  },
  "checksec": {
    "aslr": true,
    "high_entropy_va": true,
    "dep": true,
    "cfg": false,
    "safeseh": "n/a",
    "gs": false,
    "authenticode": false
  },
  "warnings": []
}
```

## Tests

```sh
ctest --test-dir build --output-on-failure   # all tests
./build/binsec_tests elf                      # only tests whose name contains "elf"
```

The unit tests build their own ELF and PE images in memory
(`tests/elf_builder.hpp`, `tests/pe_builder.hpp`), so they don't depend on the
host toolchain. They cover:

- valid ELF64, ELF32 and big-endian ELF (32 and 64)
- valid PE32 and PE32+
- truncation at **every** length, one byte at a time from the end
- garbage input and wrong magic
- corrupted header fields
- checksec verdicts for each mitigation, and JSON/text rendering

`samples/` holds small C programs and a script that builds them with different
hardening flags (PIE on/off, Full/Partial/No RELRO, executable stack, canary
on/off, RPATH/RUNPATH, stripped, shared library). `samples/check.sh` asserts
binsec's verdict for each one. CI runs both:

```sh
samples/build.sh && samples/check.sh build/binsec
```

## Fuzzing

```sh
cmake -S . -B build-fuzz -DCMAKE_CXX_COMPILER=clang++ -DBINSEC_BUILD_FUZZER=ON -DBINSEC_BUILD_TESTS=OFF
cmake --build build-fuzz --target binsec_fuzz -j
./build-fuzz/binsec_fuzz fuzz/corpus -max_total_time=60 -artifact_prefix=fuzz/crashes/
```

- The harness is built with `-fsanitize=fuzzer,address,undefined -g`. The
  parser library also gets sanitizer instrumentation plus coverage
  instrumentation (`-fsanitize=fuzzer-no-link`).
- **Seed corpus** (`fuzz/corpus/`) is generated by script, not by hand.
  `fuzz/gen_corpus.py` takes valid binaries and writes the file itself,
  truncations, and deterministic mutations (bit flips, extreme values in
  header fields). The valid inputs are the ELF/PE images from
  `binsec_tests --write-seeds DIR`, small cross-linked ELF executables
  (x86-64, i386, big-endian PPC64) and a MinGW PE. CI also adds freshly built
  `samples/bin/*`:
  ```sh
  samples/build.sh && python3 fuzz/gen_corpus.py -o fuzz/corpus samples/bin/*
  ```
- **Crashes.** Save every crash input in `fuzz/crashes/`.
  `binsec_tests` replays everything in `fuzz/crashes/` and `fuzz/corpus/`
  through the fuzz target, so a crash input becomes a regression test once it
  is committed.
- **CI** runs a 60-second libFuzzer smoke test on every push.
- `fuzz/standalone_main.cpp` is a replay and mutation driver for toolchains
  without libFuzzer. It was used for the Windows (MSYS2 clang64) ASan+UBSan
  runs below.

Fuzzing log:

| run | engine | time | execs | crashes |
|-----|--------|------|-------|---------|
| ELF parser (231 seeds) | standalone mutator, ASan+UBSan, MSYS2 clang 22 | 90 s | 1.2 M | 0 |
| ELF+PE parser (498 seeds) | standalone mutator, ASan+UBSan, MSYS2 clang 22 | 120 s | 1.4 M | 0 |
| ELF+PE parser (902 seeds incl. gcc-built samples) | libFuzzer, ASan+UBSan, Clang 21.1, GitHub Actions | 61 s | 148 K | 0 |

A fuzzing-driven review led to one hardening change: only the first
`SHT_SYMTAB` and the first `SHT_DYNSYM` are parsed. Without that, crafted files
with many aliased symbol tables take quadratic time. Import thunks and exports
are also capped.

## Project layout

```
include/binsec/   public headers: result, reader, elf, pe, binary, checksec, report
src/              library sources (binsec_lib) and the CLI (main.cpp -> binsec)
src/gui/          Win32 GUI (binsec-gui.exe): window, icon, manifest, version resource
tests/            self-contained test harness, ELF/PE image builders, tests
fuzz/             libFuzzer harness, standalone driver, corpus generator, corpus/, crashes/
samples/          C programs, build.sh (hardening matrix), check.sh (expected verdicts)
docs/             how each checksec verdict is computed
.github/workflows CI: build + ctest + samples check, 60 s libFuzzer smoke run
```

CMake targets: `binsec_lib` (static parser library), `binsec` (CLI),
`binsec_tests`, `binsec_fuzz`.

## Known limitations

- Authenticode: binsec only checks that a certificate is present. It does not
  verify the signature or the chain. Catalog-signed system files show "No".
- /GS is detected through the load config `SecurityCookie`, which MSVC sets.
  MinGW/GCC binaries use `__stack_chk_*` instead and show `/GS: No`.
- PE: COFF object files, .NET metadata, resources, delay-load imports and
  forwarded exports are not parsed. The RVA→offset mapping ignores the loader's
  `FileAlignment` round-down quirk.
- ELF: relocations, notes, symbol versioning and DWARF are not parsed. The
  dynamic symbol table is read from section headers. Binaries without section
  headers (`sstrip`) still get RELRO/PIE/NX/RPATH from program headers, but
  not canary/fortify.
- Fortify reports the `__*_chk` functions that are used. It does not report
  how many functions could have been fortified, which needs a libc symbol list.
- The fuzzer needs Linux (WSL works). On Windows, use `standalone_main.cpp`
  with MSYS2 clang64 for ASan/UBSan replay.

## License

MIT, see [LICENSE](LICENSE).
