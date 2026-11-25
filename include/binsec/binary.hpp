// Format auto-detection: "\x7fELF" -> ELF, "MZ" -> PE, anything else -> UnknownFormat.
#pragma once
#include <cstdint>
#include <span>
#include <variant>

#include "binsec/elf.hpp"
#include "binsec/pe.hpp"
#include "binsec/result.hpp"

namespace binsec {

enum class Format { Elf, Pe };
using Binary = std::variant<ElfFile, PeFile>;

Result<Format> detect_format(std::span<const std::uint8_t> data);
Result<Binary> parse_binary(std::span<const std::uint8_t> data);

}  // namespace binsec
