#!/usr/bin/env python3
"""Generate the fuzz seed corpus from valid binaries.

For every input file writes into the output directory:
  * the file itself,
  * truncated variants (header boundaries and fractions of the file),
  * deterministic mutations (bit flips, extreme values in header fields).
Files are named by SHA-1 of their content, like libFuzzer does.

usage: gen_corpus.py [-o fuzz/corpus] [-n 24] [--seed 1] FILE...
"""
import argparse
import hashlib
import random
import struct
import sys
from pathlib import Path

# header field offsets worth hammering (ELF64/ELF32 header, PE DOS/COFF/optional header)
ELF_FIELDS = [4, 5, 6, 16, 18, 24, 28, 32, 40, 44, 48, 52, 54, 56, 58, 60, 62]
PE_FIELDS = [0x3C]
EXTREMES = [0, 1, 0x7F, 0x80, 0xFF, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
MAX_SIZE = 64 * 1024  # keep seeds small for the fuzzer


def write(out: Path, data: bytes) -> bool:
    if not data or len(data) > MAX_SIZE:
        return False
    path = out / hashlib.sha1(data).hexdigest()
    if path.exists():
        return False
    path.write_bytes(data)
    return True


def truncations(data: bytes):
    cuts = {4, 16, 52, 63, 64, 0x40, 0x80, 0x100}
    cuts |= {len(data) * k // 8 for k in range(1, 8)}
    cuts.add(len(data) - 1)
    return [data[:c] for c in sorted(cuts) if 0 < c < len(data)]


def field_offsets(data: bytes):
    if data[:2] == b"MZ" and len(data) >= 0x40:
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        pe = [lfanew + o for o in (4, 6, 20, 24, 24 + 92, 24 + 108)]  # COFF + optional header
        return PE_FIELDS + [o for o in pe if o + 4 <= len(data)]
    return [o for o in ELF_FIELDS if o + 4 <= len(data)]


def mutations(data: bytes, rng: random.Random, count: int):
    fields = field_offsets(data) or [0]
    for _ in range(count):
        buf = bytearray(data)
        for _ in range(rng.randint(1, 4)):
            kind = rng.randrange(3)
            if kind == 0:  # bit flip anywhere
                pos = rng.randrange(len(buf))
                buf[pos] ^= 1 << rng.randrange(8)
            elif kind == 1:  # extreme value in a header field
                pos = rng.choice(fields)
                width = rng.choice((1, 2, 4))
                val = rng.choice(EXTREMES) & ((1 << (8 * width)) - 1)
                buf[pos:pos + width] = val.to_bytes(width, rng.choice(("little", "big")))
                del buf[len(data):]
            else:  # random byte in the first KiB (tables live near the header)
                pos = rng.randrange(min(len(buf), 1024))
                buf[pos] = rng.randrange(256)
        yield bytes(buf)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--out", default="fuzz/corpus")
    ap.add_argument("-n", "--mutations", type=int, default=24)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("files", nargs="+")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)
    written = 0
    for name in args.files:
        data = Path(name).read_bytes()
        if len(data) > MAX_SIZE:
            print(f"skip {name}: larger than {MAX_SIZE} bytes", file=sys.stderr)
            continue
        written += write(out, data)
        written += sum(write(out, t) for t in truncations(data))
        written += sum(write(out, m) for m in mutations(data, rng, args.mutations))
    print(f"{written} new corpus file(s) in {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
