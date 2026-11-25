// Bounds-checked byte reader. Every access is validated against the buffer;
// out-of-range reads produce an Error (Reader) or a sticky failure flag (Cursor),
// never undefined behaviour.
#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "binsec/result.hpp"

namespace binsec {

enum class Endian { Little, Big };

class Reader {
 public:
  Reader() = default;
  explicit Reader(std::span<const std::uint8_t> data, Endian endian = Endian::Little) noexcept
      : data_(data), endian_(endian) {}

  std::size_t size() const noexcept { return data_.size(); }
  Endian endian() const noexcept { return endian_; }
  void set_endian(Endian e) noexcept { endian_ = e; }
  std::span<const std::uint8_t> data() const noexcept { return data_; }

  // True if [offset, offset + length) lies inside the buffer (overflow-safe).
  bool in_bounds(std::uint64_t offset, std::uint64_t length) const noexcept {
    return offset <= data_.size() && length <= data_.size() - offset;
  }

  Result<std::uint8_t> u8(std::uint64_t offset) const;
  Result<std::uint16_t> u16(std::uint64_t offset) const;
  Result<std::uint32_t> u32(std::uint64_t offset) const;
  Result<std::uint64_t> u64(std::uint64_t offset) const;

  // Sub-view [offset, offset + length) with the same endianness.
  Result<Reader> sub(std::uint64_t offset, std::uint64_t length) const;

  // NUL-terminated string at offset; the terminator must be found within
  // max_len bytes and inside the buffer.
  Result<std::string> cstring(std::uint64_t offset, std::size_t max_len = 4096) const;

  // Fixed-width NUL-padded string field (e.g. PE section names).
  Result<std::string> fixed_string(std::uint64_t offset, std::size_t width) const;

 private:
  Result<std::uint64_t> read_uint(std::uint64_t offset, unsigned width) const;

  std::span<const std::uint8_t> data_{};
  Endian endian_ = Endian::Little;
};

// Sequential reader with a sticky failure flag: after the first out-of-range
// read every further read returns 0 and failed() stays true. Lets parsers read
// a whole structure and check once.
class Cursor {
 public:
  Cursor(const Reader& reader, std::uint64_t offset) noexcept : r_(&reader), pos_(offset) {}

  std::uint8_t u8() { return take<std::uint8_t>(r_->u8(pos_), 1); }
  std::uint16_t u16() { return take<std::uint16_t>(r_->u16(pos_), 2); }
  std::uint32_t u32() { return take<std::uint32_t>(r_->u32(pos_), 4); }
  std::uint64_t u64() { return take<std::uint64_t>(r_->u64(pos_), 8); }
  // Native word: 8 bytes for 64-bit formats, 4 bytes otherwise.
  std::uint64_t word(bool is64) { return is64 ? u64() : u32(); }
  void skip(std::uint64_t n) {
    if (failed_ || !r_->in_bounds(pos_, n)) {
      failed_ = true;
      return;
    }
    pos_ += n;
  }

  bool failed() const noexcept { return failed_; }
  std::uint64_t pos() const noexcept { return pos_; }

 private:
  template <class T, class R>
  T take(const R& res, unsigned width) {
    if (failed_ || !res.ok()) {
      failed_ = true;
      return 0;
    }
    pos_ += width;
    return static_cast<T>(res.value());
  }

  const Reader* r_;
  std::uint64_t pos_;
  bool failed_ = false;
};

}  // namespace binsec
