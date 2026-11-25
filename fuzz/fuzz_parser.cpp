// libFuzzer entry point: feeds arbitrary bytes to the parser, checksec and the
// report renderers. No file I/O, no exit(); always returns 0.
#include <cstddef>
#include <cstdint>
#include <span>

#include "binsec/checksec.hpp"
#include "binsec/elf.hpp"
#include "binsec/report.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::uint8_t> input(data, size);
  auto elf = binsec::parse_elf(input);
  if (elf) {
    const auto sec = binsec::checksec_elf(*elf);
    (void)sec;
    binsec::ReportOptions opt;
    opt.all = true;
    (void)binsec::render_json(*elf, "fuzz", opt);
    (void)binsec::render_text(*elf, "fuzz", opt);
  }
  return 0;
}
