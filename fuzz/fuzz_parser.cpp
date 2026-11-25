// libFuzzer entry point: feeds arbitrary bytes to format detection, the ELF/PE
// parsers, checksec and the report renderers. No file I/O, no exit(); returns 0.
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <variant>

#include "binsec/binary.hpp"
#include "binsec/checksec.hpp"
#include "binsec/report.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::uint8_t> input(data, size);
  auto bin = binsec::parse_binary(input);
  if (!bin) return 0;
  std::visit(
      [](const auto& f) {
        if constexpr (std::is_same_v<std::decay_t<decltype(f)>, binsec::ElfFile>) (void)binsec::checksec_elf(f);
        else (void)binsec::checksec_pe(f);
      },
      *bin);
  binsec::ReportOptions opt;
  opt.all = true;
  (void)binsec::render_json(*bin, "fuzz", opt);
  (void)binsec::render_text(*bin, "fuzz", opt);
  return 0;
}
