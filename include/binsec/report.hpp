// Text and JSON rendering of parse results (shared by the CLI and tests).
#pragma once
#include <string>
#include <string_view>

#include "binsec/binary.hpp"
#include "binsec/result.hpp"

namespace binsec {

struct ReportOptions {
  bool checksec = false;
  bool sections = false;  // ELF: program + section headers; PE: sections
  bool symbols = false;   // ELF: .dynsym/.symtab; PE: imports/exports
  bool all = false;       // everything above + dynamic section
};

std::string render_text(const ElfFile& f, std::string_view path, const ReportOptions& opt);
std::string render_json(const ElfFile& f, std::string_view path, const ReportOptions& opt);
std::string render_text(const PeFile& f, std::string_view path, const ReportOptions& opt);
std::string render_json(const PeFile& f, std::string_view path, const ReportOptions& opt);
std::string render_text(const Binary& b, std::string_view path, const ReportOptions& opt);
std::string render_json(const Binary& b, std::string_view path, const ReportOptions& opt);
std::string render_error_json(const Error& e, std::string_view path);

// JSON string escaping; bytes >= 0x80 are emitted as \u00XX so output is always valid JSON.
std::string json_escape(std::string_view s);

}  // namespace binsec
