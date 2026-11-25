// Internal helpers (not part of the public API).
#pragma once
#include <cstdint>
#include <string>

namespace binsec {

inline std::string hex(std::uint64_t v) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string s;
  do {
    s.insert(s.begin(), digits[v & 0xF]);
    v >>= 4;
  } while (v != 0);
  return "0x" + s;
}

}  // namespace binsec
