// ELF parser: header, program headers, section headers, symbols, dynamic section.
// Supports ELF32/ELF64, little- and big-endian. All reads are bounds-checked.
#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "binsec/reader.hpp"
#include "binsec/result.hpp"

namespace binsec {

namespace elf {
// e_type
inline constexpr std::uint16_t ET_NONE = 0, ET_REL = 1, ET_EXEC = 2, ET_DYN = 3, ET_CORE = 4;
// p_type
inline constexpr std::uint32_t PT_NULL = 0, PT_LOAD = 1, PT_DYNAMIC = 2, PT_INTERP = 3, PT_NOTE = 4, PT_SHLIB = 5,
                               PT_PHDR = 6, PT_TLS = 7, PT_GNU_EH_FRAME = 0x6474e550, PT_GNU_STACK = 0x6474e551,
                               PT_GNU_RELRO = 0x6474e552, PT_GNU_PROPERTY = 0x6474e553;
// p_flags
inline constexpr std::uint32_t PF_X = 1, PF_W = 2, PF_R = 4;
// sh_type
inline constexpr std::uint32_t SHT_NULL = 0, SHT_PROGBITS = 1, SHT_SYMTAB = 2, SHT_STRTAB = 3, SHT_RELA = 4,
                               SHT_HASH = 5, SHT_DYNAMIC = 6, SHT_NOTE = 7, SHT_NOBITS = 8, SHT_REL = 9,
                               SHT_DYNSYM = 11, SHT_INIT_ARRAY = 14, SHT_FINI_ARRAY = 15, SHT_GNU_HASH = 0x6ffffff6,
                               SHT_GNU_VERDEF = 0x6ffffffd, SHT_GNU_VERNEED = 0x6ffffffe,
                               SHT_GNU_VERSYM = 0x6fffffff;
// sh_flags
inline constexpr std::uint64_t SHF_WRITE = 0x1, SHF_ALLOC = 0x2, SHF_EXECINSTR = 0x4, SHF_MERGE = 0x10,
                               SHF_STRINGS = 0x20, SHF_INFO_LINK = 0x40, SHF_TLS = 0x400;
// special section indices
inline constexpr std::uint16_t SHN_UNDEF = 0, SHN_XINDEX = 0xffff;
inline constexpr std::uint16_t PN_XNUM = 0xffff;
// d_tag
inline constexpr std::int64_t DT_NULL = 0, DT_NEEDED = 1, DT_STRTAB = 5, DT_SYMTAB = 6, DT_STRSZ = 10,
                              DT_SONAME = 14, DT_RPATH = 15, DT_BIND_NOW = 24, DT_RUNPATH = 29, DT_FLAGS = 30,
                              DT_FLAGS_1 = 0x6ffffffb;
inline constexpr std::uint64_t DF_BIND_NOW = 0x8, DF_1_NOW = 0x1, DF_1_PIE = 0x08000000;
}  // namespace elf

struct ElfHeader {
  unsigned bits = 64;  // 32 or 64
  Endian endian = Endian::Little;
  std::uint8_t os_abi = 0;
  std::uint16_t type = 0;
  std::uint16_t machine = 0;
  std::uint32_t version = 0;
  std::uint64_t entry = 0;
  std::uint64_t phoff = 0;
  std::uint64_t shoff = 0;
  std::uint32_t flags = 0;
  std::uint16_t ehsize = 0;
  std::uint16_t phentsize = 0;
  std::uint32_t phnum = 0;  // after PN_XNUM resolution
  std::uint16_t shentsize = 0;
  std::uint32_t shnum = 0;     // after extended-numbering resolution
  std::uint32_t shstrndx = 0;  // after SHN_XINDEX resolution
};

struct ElfSegment {
  std::uint32_t type = 0;
  std::uint32_t flags = 0;
  std::uint64_t offset = 0, vaddr = 0, paddr = 0, filesz = 0, memsz = 0, align = 0;
};

struct ElfSection {
  std::string name;
  std::uint32_t name_offset = 0;
  std::uint32_t type = 0;
  std::uint64_t flags = 0, addr = 0, offset = 0, size = 0;
  std::uint32_t link = 0, info = 0;
  std::uint64_t addralign = 0, entsize = 0;
};

struct ElfSymbol {
  std::string name;
  std::uint64_t value = 0, size = 0;
  std::uint8_t info = 0, other = 0;
  std::uint16_t shndx = 0;
  std::uint8_t bind() const noexcept { return info >> 4; }
  std::uint8_t type() const noexcept { return info & 0xf; }
};

struct ElfDynamic {
  std::int64_t tag = 0;
  std::uint64_t value = 0;
  std::string str;  // resolved for DT_NEEDED / DT_SONAME / DT_RPATH / DT_RUNPATH
};

struct ElfFile {
  ElfHeader header;
  std::vector<ElfSegment> segments;
  std::vector<ElfSection> sections;
  std::vector<ElfSymbol> symbols;          // .symtab
  std::vector<ElfSymbol> dynamic_symbols;  // .dynsym
  std::vector<ElfDynamic> dynamic;         // PT_DYNAMIC / .dynamic, without DT_NULL
  std::string interpreter;                 // PT_INTERP
  std::vector<std::string> warnings;       // non-fatal inconsistencies

  bool has_section_type(std::uint32_t type) const noexcept;
  const ElfSegment* find_segment(std::uint32_t type) const noexcept;
  std::optional<std::uint64_t> dynamic_value(std::int64_t tag) const noexcept;
  // Maps a virtual address to a file offset through PT_LOAD segments.
  std::optional<std::uint64_t> vaddr_to_offset(std::uint64_t vaddr) const noexcept;
};

// True if data starts with "\x7fELF".
bool is_elf(std::span<const std::uint8_t> data) noexcept;

Result<ElfFile> parse_elf(std::span<const std::uint8_t> data);

// Human-readable names.
std::string elf_type_name(std::uint16_t type);
std::string elf_machine_name(std::uint16_t machine);
std::string elf_segment_type_name(std::uint32_t type);
std::string elf_segment_flags(std::uint32_t flags);
std::string elf_section_type_name(std::uint32_t type);
std::string elf_section_flags(std::uint64_t flags);
std::string elf_dynamic_tag_name(std::int64_t tag);
std::string elf_symbol_type_name(std::uint8_t type);
std::string elf_symbol_bind_name(std::uint8_t bind);

}  // namespace binsec
