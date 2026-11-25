// Tiny pretty-printing JSON writer (internal).
#pragma once
#include <concepts>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "binsec/report.hpp"

namespace binsec {

class JsonWriter {
 public:
  JsonWriter& begin_object() { return open('{'); }
  JsonWriter& end_object() { return close('}'); }
  JsonWriter& begin_array() { return open('['); }
  JsonWriter& end_array() { return close(']'); }

  JsonWriter& key(std::string_view k) {
    element();
    out_ += '"';
    out_ += json_escape(k);
    out_ += "\": ";
    after_key_ = true;
    return *this;
  }

  JsonWriter& value(std::string_view s) {
    pre_value();
    out_ += '"';
    out_ += json_escape(s);
    out_ += '"';
    return *this;
  }
  JsonWriter& value(const char* s) { return value(std::string_view(s)); }
  JsonWriter& value(bool b) {
    pre_value();
    out_ += b ? "true" : "false";
    return *this;
  }
  template <std::integral T>
    requires(!std::same_as<T, bool>)
  JsonWriter& value(T v) {
    pre_value();
    out_ += std::to_string(v);
    return *this;
  }
  JsonWriter& null() {
    pre_value();
    out_ += "null";
    return *this;
  }

  template <class T>
  JsonWriter& kv(std::string_view k, const T& v) {
    key(k);
    return value(v);
  }
  // Empty string -> null.
  JsonWriter& kv_opt(std::string_view k, std::string_view v) {
    key(k);
    return v.empty() ? null() : value(v);
  }

  std::string str() const { return out_ + "\n"; }

 private:
  JsonWriter& open(char c) {
    pre_value();
    out_ += c;
    first_.push_back(true);
    return *this;
  }
  JsonWriter& close(char c) {
    const bool empty = first_.back();
    first_.pop_back();
    if (!empty) newline();
    out_ += c;
    return *this;
  }
  void pre_value() {
    if (after_key_) {
      after_key_ = false;
      return;
    }
    element();
  }
  void element() {
    if (first_.empty()) return;
    if (!first_.back()) out_ += ',';
    first_.back() = false;
    newline();
  }
  void newline() {
    out_ += '\n';
    out_.append(first_.size() * 2, ' ');
  }

  std::string out_;
  std::vector<bool> first_;
  bool after_key_ = false;
};

}  // namespace binsec
