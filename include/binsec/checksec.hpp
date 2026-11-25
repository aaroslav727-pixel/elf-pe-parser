// Security-hardening audit of a parsed binary (in the spirit of checksec.sh).
#pragma once
#include <string>
#include <string_view>
#include <vector>

#include "binsec/elf.hpp"
#include "binsec/pe.hpp"

namespace binsec {

enum class Relro { None, Partial, Full };
enum class Pie { No, Yes, Dso, Rel };  // Dso: shared library, Rel: relocatable object
enum class Nx { Enabled, Disabled, NotApplicable };

struct ElfChecksec {
  Relro relro = Relro::None;  // PT_GNU_RELRO (+ BIND_NOW for Full)
  Pie pie = Pie::No;          // ET_DYN + PT_INTERP (or DF_1_PIE)
  Nx nx = Nx::Disabled;       // PT_GNU_STACK without PF_X
  bool canary = false;        // __stack_chk_fail / __stack_chk_guard referenced
  bool fortify = false;       // any __*_chk function referenced
  std::vector<std::string> fortified;  // names of the __*_chk functions
  std::string rpath;                   // DT_RPATH, empty if absent
  std::string runpath;                 // DT_RUNPATH, empty if absent
  bool stripped = true;                // no .symtab section
};

ElfChecksec checksec_elf(const ElfFile& f);

enum class SafeSeh { Yes, No, NoSeh, NotApplicable };  // NotApplicable: PE32+ (table-based unwinding)

struct PeChecksec {
  bool aslr = false;             // DYNAMIC_BASE
  bool high_entropy_va = false;  // HIGH_ENTROPY_VA (PE32+ only)
  bool dep = false;              // NX_COMPAT
  bool cfg = false;              // GUARD_CF
  SafeSeh safeseh = SafeSeh::No;  // NO_SEH flag / load config SEHandlerTable (PE32)
  bool gs = false;                // load config SecurityCookie (__security_cookie)
  bool authenticode = false;      // certificate in the security directory (not verified)
};

PeChecksec checksec_pe(const PeFile& f);

std::string_view to_string(Relro v) noexcept;
std::string_view to_string(Pie v) noexcept;
std::string_view to_string(Nx v) noexcept;
std::string_view to_string(SafeSeh v) noexcept;

}  // namespace binsec
