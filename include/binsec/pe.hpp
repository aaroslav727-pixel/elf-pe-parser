// PE/COFF parser: DOS header, PE signature, COFF header, optional header
// (PE32 / PE32+), sections, imports, exports, load config. Bounds-checked.
#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "binsec/result.hpp"

namespace binsec {

namespace pe {
inline constexpr std::uint16_t MAGIC_PE32 = 0x10b, MAGIC_PE32_PLUS = 0x20b;
// COFF characteristics
inline constexpr std::uint16_t FILE_RELOCS_STRIPPED = 0x0001, FILE_EXECUTABLE_IMAGE = 0x0002,
                               FILE_LARGE_ADDRESS_AWARE = 0x0020, FILE_DLL = 0x2000;
// DllCharacteristics
inline constexpr std::uint16_t DLL_HIGH_ENTROPY_VA = 0x0020, DLL_DYNAMIC_BASE = 0x0040,
                               DLL_FORCE_INTEGRITY = 0x0080, DLL_NX_COMPAT = 0x0100, DLL_NO_SEH = 0x0400,
                               DLL_GUARD_CF = 0x4000;
// data directory indices
inline constexpr std::size_t DIR_EXPORT = 0, DIR_IMPORT = 1, DIR_SECURITY = 4, DIR_LOAD_CONFIG = 10;
// section characteristics
inline constexpr std::uint32_t SCN_CNT_CODE = 0x20, SCN_CNT_INITIALIZED_DATA = 0x40,
                               SCN_CNT_UNINITIALIZED_DATA = 0x80, SCN_MEM_EXECUTE = 0x20000000,
                               SCN_MEM_READ = 0x40000000, SCN_MEM_WRITE = 0x80000000;
}  // namespace pe

struct PeDataDirectory {
  std::uint32_t rva = 0;  // for DIR_SECURITY this is a file offset
  std::uint32_t size = 0;
};

struct PeSection {
  std::string name;
  std::uint32_t virtual_size = 0, virtual_address = 0, raw_size = 0, raw_offset = 0, characteristics = 0;
};

struct PeImport {
  std::string dll;
  std::vector<std::string> functions;  // by-ordinal imports are "#<ordinal>"
};

struct PeExport {
  std::string name;
  std::uint32_t ordinal = 0;
  std::uint32_t rva = 0;
};

struct PeLoadConfig {
  bool present = false;
  std::uint32_t size = 0;
  std::uint64_t security_cookie = 0;   // VA of __security_cookie (/GS)
  std::uint64_t se_handler_table = 0;  // PE32 SafeSEH table
  std::uint64_t se_handler_count = 0;
  std::uint32_t guard_flags = 0;
};

struct PeFile {
  std::uint32_t e_lfanew = 0;
  // COFF header
  std::uint16_t machine = 0;
  std::uint16_t number_of_sections = 0;
  std::uint32_t timestamp = 0;
  std::uint16_t size_of_optional_header = 0;
  std::uint16_t characteristics = 0;
  // optional header
  std::uint16_t magic = 0;
  bool pe32_plus = false;
  std::uint32_t entry_point = 0;  // RVA
  std::uint64_t image_base = 0;
  std::uint32_t size_of_image = 0;
  std::uint32_t size_of_headers = 0;
  std::uint16_t subsystem = 0;
  std::uint16_t dll_characteristics = 0;
  std::vector<PeDataDirectory> directories;

  std::vector<PeSection> sections;
  std::vector<PeImport> imports;
  std::string export_dll_name;
  std::vector<PeExport> exports;
  PeLoadConfig load_config;
  bool has_certificate = false;  // Authenticode blob present in the security directory
  std::vector<std::string> warnings;

  PeDataDirectory directory(std::size_t index) const noexcept;
  // Maps an RVA to a file offset through the section table (or the headers).
  std::optional<std::uint64_t> rva_to_offset(std::uint64_t rva) const noexcept;
};

// True if data starts with "MZ".
bool is_pe(std::span<const std::uint8_t> data) noexcept;

Result<PeFile> parse_pe(std::span<const std::uint8_t> data);

std::string pe_machine_name(std::uint16_t machine);
std::string pe_subsystem_name(std::uint16_t subsystem);
std::string pe_section_flags(std::uint32_t characteristics);

}  // namespace binsec
