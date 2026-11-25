#include "binsec/pe.hpp"

#include <algorithm>
#include <limits>
#include <string>

#include "binsec/reader.hpp"
#include "util.hpp"

namespace binsec {

namespace {

constexpr std::size_t kMaxWarnings = 64;
constexpr std::size_t kMaxNameLen = 4096;
constexpr std::size_t kMaxImportDescriptors = 4096;
constexpr std::size_t kMaxImportedFunctions = 1 << 16;  // total, guards against aliased thunk arrays
constexpr std::size_t kMaxExports = 1 << 16;

void warn(PeFile& f, std::string msg) {
  if (f.warnings.size() < kMaxWarnings) f.warnings.push_back(std::move(msg));
}

std::optional<std::string> string_at_rva(const Reader& r, const PeFile& f, std::uint64_t rva) {
  const auto off = f.rva_to_offset(rva);
  if (!off) return std::nullopt;
  auto s = r.cstring(*off, kMaxNameLen);
  if (!s) return std::nullopt;
  return std::move(*s);
}

Result<std::uint64_t> u32_at_rva(const Reader& r, const PeFile& f, std::uint64_t rva) {
  const auto off = f.rva_to_offset(rva);
  if (!off) return make_error(ErrorCode::OutOfBounds, "RVA " + hex(rva) + " is not mapped");
  BINSEC_TRY(const std::uint32_t v, r.u32(*off));
  return std::uint64_t{v};
}

Result<std::uint64_t> word_at_rva(const Reader& r, const PeFile& f, std::uint64_t rva) {
  if (!f.pe32_plus) return u32_at_rva(r, f, rva);
  const auto off = f.rva_to_offset(rva);
  if (!off) return make_error(ErrorCode::OutOfBounds, "RVA " + hex(rva) + " is not mapped");
  return r.u64(*off);
}

void parse_imports(const Reader& r, PeFile& f) {
  const auto dir = f.directory(pe::DIR_IMPORT);
  if (dir.rva == 0 || dir.size == 0) return;
  const std::uint64_t thunk_size = f.pe32_plus ? 8 : 4;
  const std::uint64_t ordinal_flag = f.pe32_plus ? (1ull << 63) : (1ull << 31);
  std::size_t total = 0;

  for (std::size_t i = 0; i < kMaxImportDescriptors; ++i) {
    const std::uint64_t desc = static_cast<std::uint64_t>(dir.rva) + i * 20;
    const auto off = f.rva_to_offset(desc);
    if (!off) {
      warn(f, "import descriptor " + std::to_string(i) + " is not mapped");
      return;
    }
    Cursor c(r, *off);
    const std::uint32_t original_first_thunk = c.u32();
    c.skip(8);  // TimeDateStamp, ForwarderChain
    const std::uint32_t name_rva = c.u32();
    const std::uint32_t first_thunk = c.u32();
    if (c.failed()) {
      warn(f, "import descriptor " + std::to_string(i) + " is truncated");
      return;
    }
    if (original_first_thunk == 0 && name_rva == 0 && first_thunk == 0) return;  // terminator

    PeImport imp;
    imp.dll = string_at_rva(r, f, name_rva).value_or("<invalid>");
    const std::uint64_t thunks = original_first_thunk ? original_first_thunk : first_thunk;
    for (std::uint64_t j = 0; total < kMaxImportedFunctions; ++j, ++total) {
      auto t = word_at_rva(r, f, thunks + j * thunk_size);
      if (!t) {
        warn(f, "import thunk table of '" + imp.dll + "' is not terminated inside the file");
        break;
      }
      const std::uint64_t v = *t;
      if (v == 0) break;
      if (v & ordinal_flag) {
        imp.functions.push_back("#" + std::to_string(v & 0xffff));
      } else {
        imp.functions.push_back(string_at_rva(r, f, (v & 0x7fffffff) + 2).value_or("<invalid>"));
      }
    }
    f.imports.push_back(std::move(imp));
  }
  warn(f, "too many import descriptors, list truncated");
}

void parse_exports(const Reader& r, PeFile& f) {
  const auto dir = f.directory(pe::DIR_EXPORT);
  if (dir.rva == 0 || dir.size == 0) return;
  const auto off = f.rva_to_offset(dir.rva);
  if (!off) {
    warn(f, "export directory is not mapped");
    return;
  }
  Cursor c(r, *off);
  c.skip(12);
  const std::uint32_t name_rva = c.u32();
  const std::uint32_t base = c.u32();
  const std::uint32_t n_functions = c.u32();
  const std::uint32_t n_names = c.u32();
  const std::uint32_t functions_rva = c.u32();
  const std::uint32_t names_rva = c.u32();
  const std::uint32_t ordinals_rva = c.u32();
  if (c.failed()) {
    warn(f, "export directory is truncated");
    return;
  }
  f.export_dll_name = string_at_rva(r, f, name_rva).value_or("");

  const std::uint32_t count = std::min<std::uint32_t>(n_names, kMaxExports);
  for (std::uint32_t i = 0; i < count; ++i) {
    auto name_ptr = u32_at_rva(r, f, static_cast<std::uint64_t>(names_rva) + 4ull * i);
    const auto ord_off = f.rva_to_offset(static_cast<std::uint64_t>(ordinals_rva) + 2ull * i);
    if (!name_ptr || !ord_off || !r.u16(*ord_off)) {
      warn(f, "export name table is out of bounds");
      return;
    }
    const std::uint16_t index = *r.u16(*ord_off);
    PeExport e;
    e.name = string_at_rva(r, f, *name_ptr).value_or("<invalid>");
    e.ordinal = base + index;
    if (index < n_functions) {
      if (auto rva = u32_at_rva(r, f, static_cast<std::uint64_t>(functions_rva) + 4ull * index))
        e.rva = static_cast<std::uint32_t>(*rva);
    }
    f.exports.push_back(std::move(e));
  }
}

void parse_load_config(const Reader& r, PeFile& f) {
  const auto dir = f.directory(pe::DIR_LOAD_CONFIG);
  if (dir.rva == 0 || dir.size == 0) return;
  const auto off = f.rva_to_offset(dir.rva);
  if (!off || !r.u32(*off)) {
    warn(f, "load config directory is not mapped");
    return;
  }
  auto& lc = f.load_config;
  lc.present = true;
  lc.size = *r.u32(*off);
  // read a field only if the structure (by its own Size) covers it
  auto field = [&](std::uint64_t at, unsigned width) -> std::uint64_t {
    if (at + width > lc.size) return 0;
    if (width == 8) return r.u64(*off + at).value_or(0);
    return r.u32(*off + at).value_or(0);
  };
  if (f.pe32_plus) {
    lc.security_cookie = field(88, 8);
    lc.se_handler_table = field(96, 8);
    lc.se_handler_count = field(104, 8);
    lc.guard_flags = static_cast<std::uint32_t>(field(144, 4));
  } else {
    lc.security_cookie = field(60, 4);
    lc.se_handler_table = field(64, 4);
    lc.se_handler_count = field(68, 4);
    lc.guard_flags = static_cast<std::uint32_t>(field(88, 4));
  }
}

void parse_certificate(const Reader& r, PeFile& f) {
  const auto dir = f.directory(pe::DIR_SECURITY);  // rva is a raw file offset here
  if (dir.rva == 0 || dir.size == 0) return;
  if (r.in_bounds(dir.rva, dir.size) && dir.size >= 8) f.has_certificate = true;
  else warn(f, "security directory points outside the file");
}

}  // namespace

PeDataDirectory PeFile::directory(std::size_t index) const noexcept {
  return index < directories.size() ? directories[index] : PeDataDirectory{};
}

std::optional<std::uint64_t> PeFile::rva_to_offset(std::uint64_t rva) const noexcept {
  for (const auto& s : sections) {
    const std::uint64_t span = std::max(s.virtual_size, s.raw_size);
    if (rva >= s.virtual_address && rva - s.virtual_address < span) {
      const std::uint64_t delta = rva - s.virtual_address;
      if (delta >= s.raw_size) return std::nullopt;  // in .bss-like tail, not backed by file data
      return static_cast<std::uint64_t>(s.raw_offset) + delta;
    }
  }
  if (rva < size_of_headers) return rva;
  return std::nullopt;
}

bool is_pe(std::span<const std::uint8_t> data) noexcept {
  return data.size() >= 2 && data[0] == 'M' && data[1] == 'Z';
}

Result<PeFile> parse_pe(std::span<const std::uint8_t> data) {
  if (data.size() < 2) return make_error(ErrorCode::OutOfBounds, "file too small to be a PE");
  if (!is_pe(data)) return make_error(ErrorCode::BadMagic, "bad DOS magic (expected 'MZ')");
  const Reader r(data, Endian::Little);
  PeFile f;

  // DOS header -> e_lfanew
  auto lfanew = r.u32(0x3c);
  if (!lfanew) return make_error(ErrorCode::OutOfBounds, "truncated DOS header (e_lfanew at 0x3c)");
  f.e_lfanew = *lfanew;
  if (!r.in_bounds(f.e_lfanew, 4 + 20))
    return make_error(ErrorCode::OutOfBounds, "e_lfanew " + hex(f.e_lfanew) + " points outside the file");
  if (r.u32(f.e_lfanew).value_or(0) != 0x00004550) return make_error(ErrorCode::BadMagic, "missing PE signature 'PE\\0\\0'");

  // COFF header
  const std::uint64_t coff = static_cast<std::uint64_t>(f.e_lfanew) + 4;
  Cursor c(r, coff);
  f.machine = c.u16();
  f.number_of_sections = c.u16();
  f.timestamp = c.u32();
  c.skip(8);  // PointerToSymbolTable, NumberOfSymbols
  f.size_of_optional_header = c.u16();
  f.characteristics = c.u16();
  if (c.failed()) return make_error(ErrorCode::OutOfBounds, "truncated COFF header");

  // Optional header
  const std::uint64_t opt = coff + 20;
  if (f.size_of_optional_header < 2)
    return make_error(ErrorCode::Malformed, "no optional header (object files are not supported)");
  if (!r.in_bounds(opt, f.size_of_optional_header))
    return make_error(ErrorCode::OutOfBounds, "optional header exceeds file size");
  BINSEC_TRY(f.magic, r.u16(opt));
  if (f.magic != pe::MAGIC_PE32 && f.magic != pe::MAGIC_PE32_PLUS)
    return make_error(ErrorCode::Unsupported, "unknown optional header magic " + hex(f.magic));
  f.pe32_plus = f.magic == pe::MAGIC_PE32_PLUS;
  const std::uint64_t fixed = f.pe32_plus ? 112 : 96;
  if (f.size_of_optional_header < fixed)
    return make_error(ErrorCode::Malformed, "optional header too small: " + std::to_string(f.size_of_optional_header));

  Cursor o(r, opt + 16);
  f.entry_point = o.u32();
  if (f.pe32_plus) {
    o.skip(4);  // BaseOfCode
    f.image_base = o.u64();
  } else {
    o.skip(8);  // BaseOfCode, BaseOfData
    f.image_base = o.u32();
  }
  o.skip(24);  // alignments + versions (offset 32..55)
  f.size_of_image = o.u32();
  f.size_of_headers = o.u32();
  o.skip(4);  // CheckSum
  f.subsystem = o.u16();
  f.dll_characteristics = o.u16();
  const std::uint32_t n_rva = r.u32(opt + fixed - 4).value_or(0);  // in bounds: fixed <= size_of_optional_header
  if (o.failed()) return make_error(ErrorCode::OutOfBounds, "truncated optional header");

  const std::uint64_t max_dirs = (f.size_of_optional_header - fixed) / 8;
  const std::uint64_t n_dirs = std::min<std::uint64_t>({n_rva, 16, max_dirs});
  for (std::uint64_t i = 0; i < n_dirs; ++i) {
    Cursor d(r, opt + fixed + i * 8);
    PeDataDirectory dd;
    dd.rva = d.u32();
    dd.size = d.u32();
    f.directories.push_back(dd);
  }

  // Section table
  const std::uint64_t sec = opt + f.size_of_optional_header;
  if (!r.in_bounds(sec, static_cast<std::uint64_t>(f.number_of_sections) * 40))
    return make_error(ErrorCode::OutOfBounds, "section table (" + std::to_string(f.number_of_sections) +
                                                  " entries at " + hex(sec) + ") exceeds file size");
  for (std::uint32_t i = 0; i < f.number_of_sections; ++i) {
    const std::uint64_t at = sec + i * 40ull;
    PeSection s;
    BINSEC_TRY(s.name, r.fixed_string(at, 8));
    Cursor sc(r, at + 8);
    s.virtual_size = sc.u32();
    s.virtual_address = sc.u32();
    s.raw_size = sc.u32();
    s.raw_offset = sc.u32();
    sc.skip(12);
    s.characteristics = sc.u32();
    if (sc.failed()) return make_error(ErrorCode::OutOfBounds, "truncated section header");
    if (s.raw_size != 0 && !r.in_bounds(s.raw_offset, s.raw_size))
      warn(f, "section '" + s.name + "' raw data exceeds file size");
    f.sections.push_back(std::move(s));
  }

  parse_imports(r, f);
  parse_exports(r, f);
  parse_load_config(r, f);
  parse_certificate(r, f);
  return f;
}

std::string pe_machine_name(std::uint16_t machine) {
  switch (machine) {
    case 0x014c: return "Intel 386";
    case 0x8664: return "AMD x86-64";
    case 0x01c0: return "ARM";
    case 0x01c4: return "ARMv7 Thumb-2";
    case 0xaa64: return "ARM64";
    case 0x0200: return "Intel Itanium";
  }
  return "Unknown (" + hex(machine) + ")";
}

std::string pe_subsystem_name(std::uint16_t subsystem) {
  switch (subsystem) {
    case 1: return "Native";
    case 2: return "Windows GUI";
    case 3: return "Windows CUI";
    case 9: return "Windows CE GUI";
    case 10: return "EFI application";
    case 11: return "EFI boot service driver";
    case 12: return "EFI runtime driver";
    case 16: return "Windows boot application";
  }
  return "Unknown (" + std::to_string(subsystem) + ")";
}

std::string pe_section_flags(std::uint32_t ch) {
  std::string s;
  s += (ch & pe::SCN_MEM_READ) ? 'R' : '-';
  s += (ch & pe::SCN_MEM_WRITE) ? 'W' : '-';
  s += (ch & pe::SCN_MEM_EXECUTE) ? 'X' : '-';
  if (ch & pe::SCN_CNT_CODE) s += " CODE";
  if (ch & pe::SCN_CNT_INITIALIZED_DATA) s += " IDATA";
  if (ch & pe::SCN_CNT_UNINITIALIZED_DATA) s += " UDATA";
  return s;
}

}  // namespace binsec
