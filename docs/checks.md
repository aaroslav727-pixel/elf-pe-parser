# How binsec decides each checksec verdict

## ELF

| Check    | Rule |
|----------|------|
| RELRO    | `PT_GNU_RELRO` present → **Partial**; plus `DT_BIND_NOW`, `DT_FLAGS & DF_BIND_NOW` or `DT_FLAGS_1 & DF_1_NOW` → **Full**; no `PT_GNU_RELRO` → **None** |
| PIE      | `ET_DYN` with `PT_INTERP` (or `DF_1_PIE`, static-pie) → **PIE**; `ET_DYN` without → **DSO**; `ET_EXEC` → **No PIE**; `ET_REL` → **REL** |
| NX       | `PT_GNU_STACK` without `PF_X` → enabled; with `PF_X` (RWE) or missing → disabled; no program headers → N/A |
| Canary   | `__stack_chk_fail` / `__stack_chk_guard` / `__stack_chk_fail_local` / `__intel_security_cookie` in `.dynsym` (`.symtab` for static binaries) |
| Fortify  | any `__*_chk` function in `.dynsym` (`.symtab` for static binaries); the list is reported |
| RPATH / RUNPATH | `DT_RPATH` / `DT_RUNPATH` strings from the dynamic string table |
| Stripped | no `SHT_SYMTAB` section |

## PE

| Check         | Rule |
|---------------|------|
| ASLR          | `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` (0x0040) |
| HighEntropyVA | `HIGH_ENTROPY_VA` (0x0020), PE32+ only |
| DEP/NX        | `NX_COMPAT` (0x0100) |
| CFG           | `GUARD_CF` (0x4000) |
| SafeSEH       | `NO_SEH` (0x0400) → N/A (no handlers); PE32+ → N/A (table-based EH); PE32 → **Yes** if the load config has a non-empty `SEHandlerTable` |
| /GS           | load config `SecurityCookie` ≠ 0 (address of `__security_cookie`), or a `__security_cookie` import/export |
| Authenticode  | security data directory points to a certificate blob inside the file (signature is **not** verified) |
