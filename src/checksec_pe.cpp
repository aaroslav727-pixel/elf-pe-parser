#include "binsec/checksec.hpp"

namespace binsec {

PeChecksec checksec_pe(const PeFile& f) {
  PeChecksec c;
  const auto dc = f.dll_characteristics;
  c.aslr = (dc & pe::DLL_DYNAMIC_BASE) != 0;
  c.high_entropy_va = f.pe32_plus && (dc & pe::DLL_HIGH_ENTROPY_VA) != 0;
  c.dep = (dc & pe::DLL_NX_COMPAT) != 0;
  c.cfg = (dc & pe::DLL_GUARD_CF) != 0;

  if (dc & pe::DLL_NO_SEH) c.safeseh = SafeSeh::NoSeh;
  else if (f.pe32_plus) c.safeseh = SafeSeh::NotApplicable;
  else if (f.load_config.se_handler_table != 0 && f.load_config.se_handler_count != 0) c.safeseh = SafeSeh::Yes;
  else c.safeseh = SafeSeh::No;

  // MSVC /GS registers __security_cookie in the load config; also accept the symbol by name.
  c.gs = f.load_config.security_cookie != 0;
  for (const auto& imp : f.imports)
    for (const auto& fn : imp.functions)
      if (fn == "__security_cookie" || fn == "__security_init_cookie") c.gs = true;
  for (const auto& e : f.exports)
    if (e.name == "__security_cookie") c.gs = true;

  c.authenticode = f.has_certificate;
  return c;
}

std::string_view to_string(SafeSeh v) noexcept {
  switch (v) {
    case SafeSeh::Yes: return "Yes";
    case SafeSeh::No: return "No";
    case SafeSeh::NoSeh: return "N/A (NO_SEH: image has no SEH handlers)";
    case SafeSeh::NotApplicable: return "N/A (64-bit: table-based exception handling)";
  }
  return "?";
}

}  // namespace binsec
