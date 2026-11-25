#include "binsec/elf.hpp"

#include <algorithm>
#include <limits>
#include <string>

#include "util.hpp"

namespace binsec {

namespace {

constexpr std::size_t kMaxWarnings = 64;
constexpr std::size_t kMaxStringLen = 64 * 1024;

void warn(ElfFile& f, std::string msg) {
  if (f.warnings.size() < kMaxWarnings) f.warnings.push_back(std::move(msg));
}

// Reader over a section's file contents, or nullopt if absent/out of bounds.
std::optional<Reader> section_reader(const Reader& r, const ElfSection& s) {
  if (s.type == elf::SHT_NOBITS || s.type == elf::SHT_NULL) return std::nullopt;
  auto sub = r.sub(s.offset, s.size);
  if (!sub) return std::nullopt;
  return *sub;
}

Result<ElfHeader> parse_header(const Reader& r) {
  ElfHeader h;
  BINSEC_TRY(const std::uint8_t cls, r.u8(4));
  BINSEC_TRY(const std::uint8_t data, r.u8(5));
  BINSEC_TRY(const std::uint8_t ver, r.u8(6));
  BINSEC_TRY(h.os_abi, r.u8(7));
  if (cls != 1 && cls != 2) return make_error(ErrorCode::Unsupported, "unsupported ELF class " + std::to_string(cls));
  if (data != 1 && data != 2)
    return make_error(ErrorCode::Unsupported, "unsupported ELF data encoding " + std::to_string(data));
  if (ver != 1) return make_error(ErrorCode::Unsupported, "unsupported ELF ident version " + std::to_string(ver));
  h.bits = cls == 2 ? 64 : 32;
  h.endian = data == 1 ? Endian::Little : Endian::Big;

  const bool is64 = h.bits == 64;
  const std::uint64_t hdr_size = is64 ? 64 : 52;
  if (!r.in_bounds(0, hdr_size))
    return make_error(ErrorCode::OutOfBounds, "truncated ELF header: need " + std::to_string(hdr_size) +
                                                  " bytes, have " + std::to_string(r.size()));
  Reader er(r.data(), h.endian);
  Cursor c(er, 16);
  h.type = c.u16();
  h.machine = c.u16();
  h.version = c.u32();
  h.entry = c.word(is64);
  h.phoff = c.word(is64);
  h.shoff = c.word(is64);
  h.flags = c.u32();
  h.ehsize = c.u16();
  h.phentsize = c.u16();
  h.phnum = c.u16();
  h.shentsize = c.u16();
  h.shnum = c.u16();
  h.shstrndx = c.u16();
  if (c.failed()) return make_error(ErrorCode::OutOfBounds, "truncated ELF header");
  return h;
}

Result<ElfSection> parse_section_header(const Reader& r, std::uint64_t off, bool is64) {
  Cursor c(r, off);
  ElfSection s;
  s.name_offset = c.u32();
  s.type = c.u32();
  s.flags = c.word(is64);
  s.addr = c.word(is64);
  s.offset = c.word(is64);
  s.size = c.word(is64);
  s.link = c.u32();
  s.info = c.u32();
  s.addralign = c.word(is64);
  s.entsize = c.word(is64);
  if (c.failed()) return make_error(ErrorCode::OutOfBounds, "truncated section header at " + hex(off));
  return s;
}

Result<ElfSegment> parse_program_header(const Reader& r, std::uint64_t off, bool is64) {
  Cursor c(r, off);
  ElfSegment p;
  p.type = c.u32();
  if (is64) {
    p.flags = c.u32();
    p.offset = c.u64();
    p.vaddr = c.u64();
    p.paddr = c.u64();
    p.filesz = c.u64();
    p.memsz = c.u64();
    p.align = c.u64();
  } else {
    p.offset = c.u32();
    p.vaddr = c.u32();
    p.paddr = c.u32();
    p.filesz = c.u32();
    p.memsz = c.u32();
    p.flags = c.u32();
    p.align = c.u32();
  }
  if (c.failed()) return make_error(ErrorCode::OutOfBounds, "truncated program header at " + hex(off));
  return p;
}

// Section headers, including extended numbering (e_shnum == 0, e_shstrndx == SHN_XINDEX, e_phnum == PN_XNUM).
Result<std::vector<ElfSection>> parse_sections(const Reader& r, ElfHeader& h) {
  std::vector<ElfSection> out;
  const bool is64 = h.bits == 64;
  const std::uint16_t min_ent = is64 ? 64 : 40;
  if (h.shoff == 0) {
    h.shnum = 0;
    return out;
  }
  if (h.shentsize < min_ent)
    return make_error(ErrorCode::Malformed, "e_shentsize " + std::to_string(h.shentsize) + " is too small");

  if (h.shnum == 0 || h.shstrndx == elf::SHN_XINDEX || h.phnum == elf::PN_XNUM) {
    BINSEC_TRY(const ElfSection first, parse_section_header(r, h.shoff, is64));
    if (h.shnum == 0) {
      if (first.size > std::numeric_limits<std::uint32_t>::max())
        return make_error(ErrorCode::Malformed, "extended section count too large");
      h.shnum = static_cast<std::uint32_t>(first.size);
    }
    if (h.shstrndx == elf::SHN_XINDEX) h.shstrndx = first.link;
    if (h.phnum == elf::PN_XNUM) h.phnum = first.info;
  }

  const std::uint64_t table = static_cast<std::uint64_t>(h.shnum) * h.shentsize;
  if (!r.in_bounds(h.shoff, table))
    return make_error(ErrorCode::OutOfBounds, "section header table (" + std::to_string(h.shnum) + " x " +
                                                  std::to_string(h.shentsize) + " at " + hex(h.shoff) +
                                                  ") exceeds file size " + std::to_string(r.size()));
  out.reserve(h.shnum);
  for (std::uint32_t i = 0; i < h.shnum; ++i) {
    BINSEC_TRY(ElfSection s, parse_section_header(r, h.shoff + static_cast<std::uint64_t>(i) * h.shentsize, is64));
    out.push_back(std::move(s));
  }
  return out;
}

Result<std::vector<ElfSegment>> parse_segments(const Reader& r, const ElfHeader& h) {
  std::vector<ElfSegment> out;
  if (h.phoff == 0 || h.phnum == 0) return out;
  const bool is64 = h.bits == 64;
  const std::uint16_t min_ent = is64 ? 56 : 32;
  if (h.phentsize < min_ent)
    return make_error(ErrorCode::Malformed, "e_phentsize " + std::to_string(h.phentsize) + " is too small");
  const std::uint64_t table = static_cast<std::uint64_t>(h.phnum) * h.phentsize;
  if (!r.in_bounds(h.phoff, table))
    return make_error(ErrorCode::OutOfBounds, "program header table (" + std::to_string(h.phnum) + " x " +
                                                  std::to_string(h.phentsize) + " at " + hex(h.phoff) +
                                                  ") exceeds file size " + std::to_string(r.size()));
  out.reserve(h.phnum);
  for (std::uint32_t i = 0; i < h.phnum; ++i) {
    BINSEC_TRY(ElfSegment p, parse_program_header(r, h.phoff + static_cast<std::uint64_t>(i) * h.phentsize, is64));
    out.push_back(p);
  }
  return out;
}

void resolve_section_names(const Reader& r, ElfFile& f) {
  const auto idx = f.header.shstrndx;
  if (idx == elf::SHN_UNDEF || f.sections.empty()) return;
  if (idx >= f.sections.size()) {
    warn(f, "e_shstrndx " + std::to_string(idx) + " is out of range");
    return;
  }
  const auto strtab = section_reader(r, f.sections[idx]);
  if (!strtab) {
    warn(f, "section name string table is out of bounds");
    return;
  }
  for (auto& s : f.sections) {
    if (auto name = strtab->cstring(s.name_offset, kMaxStringLen)) {
      s.name = std::move(*name);
    } else if (s.type != elf::SHT_NULL || s.name_offset != 0) {
      warn(f, "invalid section name offset " + hex(s.name_offset));
    }
  }
}

void parse_symbol_table(const Reader& r, ElfFile& f, const ElfSection& sec, std::vector<ElfSymbol>& out) {
  const bool is64 = f.header.bits == 64;
  const std::uint64_t ent = is64 ? 24 : 16;
  if (sec.entsize != 0 && sec.entsize < ent) {
    warn(f, "symbol table '" + sec.name + "' has invalid entsize " + std::to_string(sec.entsize));
    return;
  }
  const std::uint64_t stride = sec.entsize != 0 ? sec.entsize : ent;
  const auto table = section_reader(r, sec);
  if (!table) {
    warn(f, "symbol table '" + sec.name + "' is out of bounds");
    return;
  }
  std::optional<Reader> strtab;
  if (sec.link < f.sections.size()) strtab = section_reader(r, f.sections[sec.link]);
  if (!strtab) warn(f, "symbol table '" + sec.name + "' has no valid string table");

  const std::uint64_t count = table->size() / stride;
  out.reserve(static_cast<std::size_t>(count));
  for (std::uint64_t i = 0; i < count; ++i) {
    Cursor c(*table, i * stride);
    ElfSymbol s;
    std::uint32_t name_off = c.u32();
    if (is64) {
      s.info = c.u8();
      s.other = c.u8();
      s.shndx = c.u16();
      s.value = c.u64();
      s.size = c.u64();
    } else {
      s.value = c.u32();
      s.size = c.u32();
      s.info = c.u8();
      s.other = c.u8();
      s.shndx = c.u16();
    }
    if (c.failed()) break;  // cannot happen: count derived from table size
    if (strtab && name_off != 0) {
      if (auto name = strtab->cstring(name_off, kMaxStringLen)) s.name = std::move(*name);
    }
    out.push_back(std::move(s));
  }
}

void parse_dynamic(const Reader& r, ElfFile& f) {
  const bool is64 = f.header.bits == 64;
  const std::uint64_t ent = is64 ? 16 : 8;

  std::optional<Reader> table;
  const ElfSection* dyn_section = nullptr;
  for (const auto& s : f.sections)
    if (s.type == elf::SHT_DYNAMIC) {
      dyn_section = &s;
      break;
    }
  if (const auto* seg = f.find_segment(elf::PT_DYNAMIC)) {
    if (auto sub = r.sub(seg->offset, seg->filesz)) table = *sub;
    else warn(f, "PT_DYNAMIC segment is out of bounds");
  }
  if (!table && dyn_section) table = section_reader(r, *dyn_section);
  if (!table) return;

  const std::uint64_t count = table->size() / ent;
  for (std::uint64_t i = 0; i < count; ++i) {
    Cursor c(*table, i * ent);
    ElfDynamic d;
    d.tag = is64 ? static_cast<std::int64_t>(c.u64()) : static_cast<std::int32_t>(c.u32());
    d.value = c.word(is64);
    if (c.failed() || d.tag == elf::DT_NULL) break;
    f.dynamic.push_back(std::move(d));
  }

  // Dynamic string table: DT_STRTAB (virtual address) first, linked section as fallback.
  std::optional<Reader> dynstr;
  if (const auto strtab = f.dynamic_value(elf::DT_STRTAB)) {
    if (const auto off = f.vaddr_to_offset(*strtab); off && *off < r.size()) {
      const std::uint64_t avail = r.size() - *off;
      const std::uint64_t len = std::min(avail, f.dynamic_value(elf::DT_STRSZ).value_or(avail));
      if (auto sub = r.sub(*off, len)) dynstr = *sub;
    }
  }
  if (!dynstr && dyn_section && dyn_section->link < f.sections.size())
    dynstr = section_reader(r, f.sections[dyn_section->link]);

  for (auto& d : f.dynamic) {
    if (d.tag != elf::DT_NEEDED && d.tag != elf::DT_SONAME && d.tag != elf::DT_RPATH && d.tag != elf::DT_RUNPATH)
      continue;
    if (!dynstr) {
      warn(f, "dynamic string table not found");
      break;
    }
    if (auto s = dynstr->cstring(d.value, kMaxStringLen)) d.str = std::move(*s);
    else warn(f, "invalid dynamic string offset " + hex(d.value));
  }
}

void parse_interpreter(const Reader& r, ElfFile& f) {
  const auto* seg = f.find_segment(elf::PT_INTERP);
  if (!seg) return;
  auto sub = r.sub(seg->offset, seg->filesz);
  if (!sub) {
    warn(f, "PT_INTERP segment is out of bounds");
    return;
  }
  if (auto s = sub->cstring(0, kMaxStringLen)) f.interpreter = std::move(*s);
  else warn(f, "PT_INTERP string is not terminated");
}

}  // namespace

bool ElfFile::has_section_type(std::uint32_t type) const noexcept {
  return std::any_of(sections.begin(), sections.end(), [type](const ElfSection& s) { return s.type == type; });
}

const ElfSegment* ElfFile::find_segment(std::uint32_t type) const noexcept {
  for (const auto& s : segments)
    if (s.type == type) return &s;
  return nullptr;
}

std::optional<std::uint64_t> ElfFile::dynamic_value(std::int64_t tag) const noexcept {
  for (const auto& d : dynamic)
    if (d.tag == tag) return d.value;
  return std::nullopt;
}

std::optional<std::uint64_t> ElfFile::vaddr_to_offset(std::uint64_t vaddr) const noexcept {
  for (const auto& s : segments) {
    if (s.type != elf::PT_LOAD || vaddr < s.vaddr) continue;
    const std::uint64_t delta = vaddr - s.vaddr;
    if (delta < s.filesz && delta <= std::numeric_limits<std::uint64_t>::max() - s.offset) return s.offset + delta;
  }
  return std::nullopt;
}

bool is_elf(std::span<const std::uint8_t> data) noexcept {
  return data.size() >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F';
}

Result<ElfFile> parse_elf(std::span<const std::uint8_t> data) {
  if (data.size() < 4) return make_error(ErrorCode::OutOfBounds, "file too small to be an ELF");
  if (!is_elf(data)) return make_error(ErrorCode::BadMagic, "bad ELF magic (expected 7f 45 4c 46)");

  ElfFile f;
  BINSEC_TRY(f.header, parse_header(Reader(data)));
  const Reader r(data, f.header.endian);

  BINSEC_TRY(f.sections, parse_sections(r, f.header));
  BINSEC_TRY(f.segments, parse_segments(r, f.header));
  resolve_section_names(r, f);

  for (const auto& s : f.sections) {
    if (s.type == elf::SHT_SYMTAB) parse_symbol_table(r, f, s, f.symbols);
    else if (s.type == elf::SHT_DYNSYM) parse_symbol_table(r, f, s, f.dynamic_symbols);
  }
  parse_dynamic(r, f);
  parse_interpreter(r, f);
  return f;
}

// ---- names -----------------------------------------------------------------

std::string elf_type_name(std::uint16_t type) {
  switch (type) {
    case elf::ET_NONE: return "NONE";
    case elf::ET_REL: return "REL (Relocatable file)";
    case elf::ET_EXEC: return "EXEC (Executable file)";
    case elf::ET_DYN: return "DYN (Shared object / PIE)";
    case elf::ET_CORE: return "CORE (Core file)";
  }
  return "UNKNOWN (" + hex(type) + ")";
}

std::string elf_machine_name(std::uint16_t machine) {
  switch (machine) {
    case 0: return "None";
    case 2: return "SPARC";
    case 3: return "Intel 80386";
    case 8: return "MIPS";
    case 20: return "PowerPC";
    case 21: return "PowerPC64";
    case 22: return "IBM S/390";
    case 40: return "ARM";
    case 62: return "AMD x86-64";
    case 183: return "AArch64";
    case 243: return "RISC-V";
    case 258: return "LoongArch";
  }
  return "Unknown (" + std::to_string(machine) + ")";
}

std::string elf_segment_type_name(std::uint32_t type) {
  switch (type) {
    case elf::PT_NULL: return "NULL";
    case elf::PT_LOAD: return "LOAD";
    case elf::PT_DYNAMIC: return "DYNAMIC";
    case elf::PT_INTERP: return "INTERP";
    case elf::PT_NOTE: return "NOTE";
    case elf::PT_SHLIB: return "SHLIB";
    case elf::PT_PHDR: return "PHDR";
    case elf::PT_TLS: return "TLS";
    case elf::PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
    case elf::PT_GNU_STACK: return "GNU_STACK";
    case elf::PT_GNU_RELRO: return "GNU_RELRO";
    case elf::PT_GNU_PROPERTY: return "GNU_PROPERTY";
  }
  return hex(type);
}

std::string elf_segment_flags(std::uint32_t flags) {
  std::string s;
  s += (flags & elf::PF_R) ? 'R' : ' ';
  s += (flags & elf::PF_W) ? 'W' : ' ';
  s += (flags & elf::PF_X) ? 'E' : ' ';
  return s;
}

std::string elf_section_type_name(std::uint32_t type) {
  switch (type) {
    case elf::SHT_NULL: return "NULL";
    case elf::SHT_PROGBITS: return "PROGBITS";
    case elf::SHT_SYMTAB: return "SYMTAB";
    case elf::SHT_STRTAB: return "STRTAB";
    case elf::SHT_RELA: return "RELA";
    case elf::SHT_HASH: return "HASH";
    case elf::SHT_DYNAMIC: return "DYNAMIC";
    case elf::SHT_NOTE: return "NOTE";
    case elf::SHT_NOBITS: return "NOBITS";
    case elf::SHT_REL: return "REL";
    case elf::SHT_DYNSYM: return "DYNSYM";
    case elf::SHT_INIT_ARRAY: return "INIT_ARRAY";
    case elf::SHT_FINI_ARRAY: return "FINI_ARRAY";
    case elf::SHT_GNU_HASH: return "GNU_HASH";
    case elf::SHT_GNU_VERDEF: return "VERDEF";
    case elf::SHT_GNU_VERNEED: return "VERNEED";
    case elf::SHT_GNU_VERSYM: return "VERSYM";
  }
  return hex(type);
}

std::string elf_section_flags(std::uint64_t flags) {
  std::string s;
  if (flags & elf::SHF_WRITE) s += 'W';
  if (flags & elf::SHF_ALLOC) s += 'A';
  if (flags & elf::SHF_EXECINSTR) s += 'X';
  if (flags & elf::SHF_MERGE) s += 'M';
  if (flags & elf::SHF_STRINGS) s += 'S';
  if (flags & elf::SHF_INFO_LINK) s += 'I';
  if (flags & elf::SHF_TLS) s += 'T';
  return s;
}

std::string elf_dynamic_tag_name(std::int64_t tag) {
  switch (tag) {
    case elf::DT_NULL: return "NULL";
    case elf::DT_NEEDED: return "NEEDED";
    case 2: return "PLTRELSZ";
    case 3: return "PLTGOT";
    case 4: return "HASH";
    case elf::DT_STRTAB: return "STRTAB";
    case elf::DT_SYMTAB: return "SYMTAB";
    case 7: return "RELA";
    case 8: return "RELASZ";
    case 9: return "RELAENT";
    case elf::DT_STRSZ: return "STRSZ";
    case 11: return "SYMENT";
    case 12: return "INIT";
    case 13: return "FINI";
    case elf::DT_SONAME: return "SONAME";
    case elf::DT_RPATH: return "RPATH";
    case 16: return "SYMBOLIC";
    case 17: return "REL";
    case 18: return "RELSZ";
    case 19: return "RELENT";
    case 20: return "PLTREL";
    case 21: return "DEBUG";
    case 22: return "TEXTREL";
    case 23: return "JMPREL";
    case elf::DT_BIND_NOW: return "BIND_NOW";
    case 25: return "INIT_ARRAY";
    case 26: return "FINI_ARRAY";
    case 27: return "INIT_ARRAYSZ";
    case 28: return "FINI_ARRAYSZ";
    case elf::DT_RUNPATH: return "RUNPATH";
    case elf::DT_FLAGS: return "FLAGS";
    case 0x6ffffef5: return "GNU_HASH";
    case 0x6ffffff0: return "VERSYM";
    case 0x6ffffff9: return "RELACOUNT";
    case 0x6ffffffa: return "RELCOUNT";
    case elf::DT_FLAGS_1: return "FLAGS_1";
    case 0x6ffffffe: return "VERNEED";
    case 0x6fffffff: return "VERNEEDNUM";
  }
  return hex(static_cast<std::uint64_t>(tag));
}

std::string elf_symbol_type_name(std::uint8_t type) {
  switch (type) {
    case 0: return "NOTYPE";
    case 1: return "OBJECT";
    case 2: return "FUNC";
    case 3: return "SECTION";
    case 4: return "FILE";
    case 5: return "COMMON";
    case 6: return "TLS";
    case 10: return "IFUNC";
  }
  return std::to_string(type);
}

std::string elf_symbol_bind_name(std::uint8_t bind) {
  switch (bind) {
    case 0: return "LOCAL";
    case 1: return "GLOBAL";
    case 2: return "WEAK";
    case 10: return "UNIQUE";
  }
  return std::to_string(bind);
}

}  // namespace binsec
