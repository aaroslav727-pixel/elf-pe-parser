#include <algorithm>
#include <string>

#include "binsec/checksec.hpp"

namespace binsec {

namespace {

bool is_fortified_name(std::string_view n) {
  // glibc fortified wrappers: __memcpy_chk, __printf_chk, __sprintf_chk, ...
  return n.size() > 6 && n.starts_with("__") && n.ends_with("_chk");
}

bool is_canary_name(std::string_view n) {
  return n == "__stack_chk_fail" || n == "__stack_chk_guard" || n == "__stack_chk_fail_local" ||
         n == "__intel_security_cookie";
}

}  // namespace

ElfChecksec checksec_elf(const ElfFile& f) {
  ElfChecksec c;

  // RELRO
  const bool bind_now = f.dynamic_value(elf::DT_BIND_NOW).has_value() ||
                        (f.dynamic_value(elf::DT_FLAGS).value_or(0) & elf::DF_BIND_NOW) != 0 ||
                        (f.dynamic_value(elf::DT_FLAGS_1).value_or(0) & elf::DF_1_NOW) != 0;
  if (f.find_segment(elf::PT_GNU_RELRO)) c.relro = bind_now ? Relro::Full : Relro::Partial;

  // PIE
  switch (f.header.type) {
    case elf::ET_DYN: {
      const bool pie_flag = (f.dynamic_value(elf::DT_FLAGS_1).value_or(0) & elf::DF_1_PIE) != 0;
      c.pie = (f.find_segment(elf::PT_INTERP) || pie_flag) ? Pie::Yes : Pie::Dso;
      break;
    }
    case elf::ET_REL: c.pie = Pie::Rel; break;
    default: c.pie = Pie::No; break;
  }

  // NX: no program headers at all (object files) -> not applicable
  if (f.segments.empty()) {
    c.nx = Nx::NotApplicable;
  } else if (const auto* stack = f.find_segment(elf::PT_GNU_STACK)) {
    c.nx = (stack->flags & elf::PF_X) ? Nx::Disabled : Nx::Enabled;
  } else {
    c.nx = Nx::Disabled;  // no PT_GNU_STACK: kernel defaults to an executable stack
  }

  // Canary / Fortify: imports in .dynsym. .symtab is used only for static binaries
  // (no .dynsym), so local PLT stubs such as __plt___printf_chk are not counted.
  const auto& table = f.dynamic_symbols.empty() ? f.symbols : f.dynamic_symbols;
  for (const auto& s : table) {
    if (is_canary_name(s.name)) c.canary = true;
    if (is_fortified_name(s.name) && std::find(c.fortified.begin(), c.fortified.end(), s.name) == c.fortified.end())
      c.fortified.push_back(s.name);
  }
  std::sort(c.fortified.begin(), c.fortified.end());
  c.fortify = !c.fortified.empty();

  for (const auto& d : f.dynamic) {
    if (d.tag == elf::DT_RPATH && c.rpath.empty()) c.rpath = d.str;
    if (d.tag == elf::DT_RUNPATH && c.runpath.empty()) c.runpath = d.str;
  }

  c.stripped = !f.has_section_type(elf::SHT_SYMTAB);
  return c;
}

std::string_view to_string(Relro v) noexcept {
  switch (v) {
    case Relro::None: return "No RELRO";
    case Relro::Partial: return "Partial RELRO";
    case Relro::Full: return "Full RELRO";
  }
  return "?";
}

std::string_view to_string(Pie v) noexcept {
  switch (v) {
    case Pie::No: return "No PIE";
    case Pie::Yes: return "PIE enabled";
    case Pie::Dso: return "DSO";
    case Pie::Rel: return "REL";
  }
  return "?";
}

std::string_view to_string(Nx v) noexcept {
  switch (v) {
    case Nx::Enabled: return "NX enabled";
    case Nx::Disabled: return "NX disabled";
    case Nx::NotApplicable: return "N/A";
  }
  return "?";
}

}  // namespace binsec
