// Result<T>: value-or-error type (C++20 stand-in for std::expected).
// The library never throws across its API and never calls exit().
#pragma once
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace binsec {

enum class ErrorCode {
  OutOfBounds,    // read outside the input buffer
  BadMagic,       // signature does not match
  Unsupported,    // valid but not supported (class, version, ...)
  Malformed,      // structurally invalid field value
  UnknownFormat,  // neither ELF nor PE
  Io,             // file could not be read (CLI helper only)
};

struct Error {
  ErrorCode code;
  std::string message;
};

std::string_view error_code_name(ErrorCode code) noexcept;

template <class T>
class [[nodiscard]] Result {
 public:
  Result(T value) : v_(std::in_place_index<0>, std::move(value)) {}      // NOLINT: implicit by design
  Result(Error error) : v_(std::in_place_index<1>, std::move(error)) {}  // NOLINT: implicit by design

  bool ok() const noexcept { return v_.index() == 0; }
  explicit operator bool() const noexcept { return ok(); }

  T& value() & { return std::get<0>(v_); }
  const T& value() const& { return std::get<0>(v_); }
  T&& value() && { return std::get<0>(std::move(v_)); }
  const Error& error() const { return std::get<1>(v_); }

  T& operator*() & { return value(); }
  const T& operator*() const& { return value(); }
  T* operator->() { return &value(); }
  const T* operator->() const { return &value(); }

  T value_or(T fallback) const { return ok() ? value() : std::move(fallback); }

 private:
  std::variant<T, Error> v_;
};

inline Error make_error(ErrorCode code, std::string message) { return Error{code, std::move(message)}; }

}  // namespace binsec

// Propagate the error of an expression returning Result<U>, otherwise bind its value.
#define BINSEC_CONCAT2(a, b) a##b
#define BINSEC_CONCAT(a, b) BINSEC_CONCAT2(a, b)
#define BINSEC_TRY_IMPL(tmp, decl, expr) \
  auto tmp = (expr);                     \
  if (!tmp.ok()) return tmp.error();     \
  decl = std::move(tmp).value()
#define BINSEC_TRY(decl, expr) BINSEC_TRY_IMPL(BINSEC_CONCAT(binsec_try_, __LINE__), decl, expr)
