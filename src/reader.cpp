#include "binsec/reader.hpp"

#include <algorithm>
#include <string>

#include "util.hpp"

namespace binsec {

namespace {
Error oob(std::uint64_t offset, std::uint64_t length, std::size_t size) {
  return make_error(ErrorCode::OutOfBounds, "read of " + std::to_string(length) + " byte(s) at " + hex(offset) +
                                                " exceeds buffer of " + std::to_string(size) + " byte(s)");
}
}  // namespace

std::string_view error_code_name(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::OutOfBounds: return "out-of-bounds";
    case ErrorCode::BadMagic: return "bad-magic";
    case ErrorCode::Unsupported: return "unsupported";
    case ErrorCode::Malformed: return "malformed";
    case ErrorCode::UnknownFormat: return "unknown-format";
    case ErrorCode::Io: return "io";
  }
  return "unknown";
}

Result<std::uint64_t> Reader::read_uint(std::uint64_t offset, unsigned width) const {
  if (!in_bounds(offset, width)) return oob(offset, width, data_.size());
  std::uint64_t v = 0;
  const auto base = static_cast<std::size_t>(offset);
  for (unsigned i = 0; i < width; ++i) {
    const unsigned idx = endian_ == Endian::Little ? width - 1 - i : i;
    v = (v << 8) | data_[base + idx];
  }
  return v;
}

Result<std::uint8_t> Reader::u8(std::uint64_t offset) const {
  if (!in_bounds(offset, 1)) return oob(offset, 1, data_.size());
  return data_[static_cast<std::size_t>(offset)];
}

Result<std::uint16_t> Reader::u16(std::uint64_t offset) const {
  BINSEC_TRY(const auto v, read_uint(offset, 2));
  return static_cast<std::uint16_t>(v);
}

Result<std::uint32_t> Reader::u32(std::uint64_t offset) const {
  BINSEC_TRY(const auto v, read_uint(offset, 4));
  return static_cast<std::uint32_t>(v);
}

Result<std::uint64_t> Reader::u64(std::uint64_t offset) const { return read_uint(offset, 8); }

Result<Reader> Reader::sub(std::uint64_t offset, std::uint64_t length) const {
  if (!in_bounds(offset, length)) return oob(offset, length, data_.size());
  return Reader(data_.subspan(static_cast<std::size_t>(offset), static_cast<std::size_t>(length)), endian_);
}

Result<std::string> Reader::cstring(std::uint64_t offset, std::size_t max_len) const {
  if (offset >= data_.size()) return oob(offset, 1, data_.size());
  const auto start = static_cast<std::size_t>(offset);
  const std::size_t limit = std::min(data_.size() - start, max_len);
  for (std::size_t i = 0; i < limit; ++i) {
    if (data_[start + i] == 0) return std::string(reinterpret_cast<const char*>(data_.data() + start), i);
  }
  return make_error(ErrorCode::Malformed, "unterminated string at " + hex(offset));
}

Result<std::string> Reader::fixed_string(std::uint64_t offset, std::size_t width) const {
  if (!in_bounds(offset, width)) return oob(offset, width, data_.size());
  const auto start = static_cast<std::size_t>(offset);
  std::size_t len = 0;
  while (len < width && data_[start + len] != 0) ++len;
  return std::string(reinterpret_cast<const char*>(data_.data() + start), len);
}

}  // namespace binsec
