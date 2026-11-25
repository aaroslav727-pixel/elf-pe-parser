#include "binsec/binary.hpp"

#include <string>

namespace binsec {

Result<Format> detect_format(std::span<const std::uint8_t> data) {
  if (is_elf(data)) return Format::Elf;
  if (is_pe(data)) return Format::Pe;
  return make_error(ErrorCode::UnknownFormat,
                    data.empty() ? std::string("empty file")
                                 : std::string("unknown format: neither ELF (7f 45 4c 46) nor PE ('MZ')"));
}

Result<Binary> parse_binary(std::span<const std::uint8_t> data) {
  BINSEC_TRY(const Format fmt, detect_format(data));
  if (fmt == Format::Elf) {
    BINSEC_TRY(ElfFile f, parse_elf(data));
    return Binary(std::move(f));
  }
  BINSEC_TRY(PeFile f, parse_pe(data));
  return Binary(std::move(f));
}

}  // namespace binsec
