#include "binsec/report.hpp"

#include <cstdio>
#include <string>

#include "binsec/checksec.hpp"
#include "json.hpp"
#include "util.hpp"

namespace binsec {

namespace {

std::string pad(std::string_view s, std::size_t width) {
  std::string r(s);
  if (r.size() < width) r.append(width - r.size(), ' ');
  return r;
}

std::string hexw(std::uint64_t v, int digits) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "0x%0*llx", digits, static_cast<unsigned long long>(v));
  return buf;
}

// Names come from untrusted input: never write raw control bytes to a terminal.
std::string printable(std::string_view s) {
  std::string r;
  r.reserve(s.size());
  for (unsigned char ch : s) r += (ch >= 0x20 && ch < 0x7f) ? static_cast<char>(ch) : '?';
  return r;
}

void line(std::string& out, std::string_view label, std::string_view value) {
  out += "  ";
  out += pad(label, 12);
  out += value;
  out += '\n';
}

bool want_checksec(const ReportOptions& o) { return o.checksec || o.all; }
bool want_sections(const ReportOptions& o) { return o.sections || o.all; }
bool want_symbols(const ReportOptions& o) { return o.symbols || o.all; }

void elf_symbols_text(std::string& out, std::string_view title, const std::vector<ElfSymbol>& syms) {
  out += "\nSymbol table '" + std::string(title) + "' (" + std::to_string(syms.size()) + " entries)\n";
  if (syms.empty()) return;
  out += "     Num  Value              Size      Type     Bind     Ndx    Name\n";
  for (std::size_t i = 0; i < syms.size(); ++i) {
    const auto& s = syms[i];
    char num[16];
    std::snprintf(num, sizeof num, "%6zu", i);
    std::string ndx = s.shndx == 0 ? "UND" : s.shndx == 0xfff1 ? "ABS" : std::to_string(s.shndx);
    out += "  " + std::string(num) + "  " + hexw(s.value, 16) + " " + pad(std::to_string(s.size), 9) + " " +
           pad(elf_symbol_type_name(s.type()), 8) + " " + pad(elf_symbol_bind_name(s.bind()), 8) + " " +
           pad(ndx, 6) + " " + printable(s.name) + "\n";
  }
}

void elf_symbols_json(JsonWriter& j, const std::vector<ElfSymbol>& syms) {
  j.begin_array();
  for (const auto& s : syms) {
    j.begin_object()
        .kv("name", s.name)
        .kv("value", hex(s.value))
        .kv("size", s.size)
        .kv("type", elf_symbol_type_name(s.type()))
        .kv("bind", elf_symbol_bind_name(s.bind()))
        .kv("shndx", s.shndx)
        .end_object();
  }
  j.end_array();
}

std::string dynamic_value_text(const ElfDynamic& d) {
  return d.str.empty() ? hex(d.value) : printable(d.str);
}

}  // namespace

std::string json_escape(std::string_view s) {
  std::string r;
  r.reserve(s.size() + 2);
  for (unsigned char ch : s) {
    switch (ch) {
      case '"': r += "\\\""; break;
      case '\\': r += "\\\\"; break;
      case '\n': r += "\\n"; break;
      case '\r': r += "\\r"; break;
      case '\t': r += "\\t"; break;
      default:
        if (ch < 0x20 || ch >= 0x7f) {
          char buf[8];
          std::snprintf(buf, sizeof buf, "\\u%04x", ch);
          r += buf;
        } else {
          r += static_cast<char>(ch);
        }
    }
  }
  return r;
}

std::string render_error_json(const Error& e, std::string_view path) {
  JsonWriter j;
  j.begin_object().kv("file", path).key("error").begin_object();
  j.kv("code", error_code_name(e.code)).kv("message", e.message).end_object().end_object();
  return j.str();
}

// ---- ELF -------------------------------------------------------------------

std::string render_text(const ElfFile& f, std::string_view path, const ReportOptions& opt) {
  const auto& h = f.header;
  std::string out;
  out += "File:        " + printable(path) + "\n";
  out += "Format:      ELF" + std::to_string(h.bits) +
         (h.endian == Endian::Little ? ", little-endian" : ", big-endian") + "\n";
  out += "Type:        " + elf_type_name(h.type) + "\n";
  out += "Machine:     " + elf_machine_name(h.machine) + "\n";
  out += "Entry point: " + hex(h.entry) + "\n";
  if (!f.interpreter.empty()) out += "Interpreter: " + printable(f.interpreter) + "\n";
  out += "Headers:     " + std::to_string(f.segments.size()) + " program, " + std::to_string(f.sections.size()) +
         " section\n";

  if (want_checksec(opt)) {
    const auto c = checksec_elf(f);
    out += "\nChecksec\n";
    line(out, "RELRO", to_string(c.relro));
    line(out, "Canary", c.canary ? "Canary found" : "No canary found");
    line(out, "NX", to_string(c.nx));
    line(out, "PIE", to_string(c.pie));
    line(out, "Fortify",
         c.fortify ? "Yes (" + std::to_string(c.fortified.size()) + " fortified functions)" : std::string("No"));
    line(out, "RPATH", c.rpath.empty() ? "No RPATH" : printable(c.rpath));
    line(out, "RUNPATH", c.runpath.empty() ? "No RUNPATH" : printable(c.runpath));
    line(out, "Stripped", c.stripped ? "Yes (no .symtab)" : "No");
  }

  if (want_sections(opt)) {
    out += "\nProgram headers (" + std::to_string(f.segments.size()) + ")\n";
    if (!f.segments.empty())
      out += "  Type           Offset             VirtAddr           FileSiz            MemSiz             Flg\n";
    for (const auto& p : f.segments) {
      out += "  " + pad(elf_segment_type_name(p.type), 14) + " " + hexw(p.offset, 16) + " " + hexw(p.vaddr, 16) +
             " " + hexw(p.filesz, 16) + " " + hexw(p.memsz, 16) + " " + elf_segment_flags(p.flags) + "\n";
    }
    out += "\nSection headers (" + std::to_string(f.sections.size()) + ")\n";
    if (!f.sections.empty())
      out += "  [Nr] Name                 Type         Address            Offset     Size       Flags\n";
    for (std::size_t i = 0; i < f.sections.size(); ++i) {
      const auto& s = f.sections[i];
      char nr[16];
      std::snprintf(nr, sizeof nr, "[%2zu]", i);
      out += "  " + std::string(nr) + " " + pad(printable(s.name), 20) + " " + pad(elf_section_type_name(s.type), 12) +
             " " + hexw(s.addr, 16) + " " + hexw(s.offset, 8) + " " + hexw(s.size, 8) + " " +
             elf_section_flags(s.flags) + "\n";
    }
  }

  if (want_symbols(opt)) {
    elf_symbols_text(out, ".dynsym", f.dynamic_symbols);
    elf_symbols_text(out, ".symtab", f.symbols);
  }

  if (opt.all) {
    out += "\nDynamic section (" + std::to_string(f.dynamic.size()) + " entries)\n";
    for (const auto& d : f.dynamic) out += "  " + pad(elf_dynamic_tag_name(d.tag), 16) + " " + dynamic_value_text(d) + "\n";
  }

  if (!f.warnings.empty()) {
    out += "\nWarnings (" + std::to_string(f.warnings.size()) + ")\n";
    for (const auto& w : f.warnings) out += "  - " + printable(w) + "\n";
  }
  return out;
}

std::string render_json(const ElfFile& f, std::string_view path, const ReportOptions& opt) {
  const auto& h = f.header;
  JsonWriter j;
  j.begin_object().kv("file", path).kv("format", "ELF");
  j.key("header").begin_object();
  j.kv("class", "ELF" + std::to_string(h.bits))
      .kv("endian", h.endian == Endian::Little ? "little" : "big")
      .kv("type", elf_type_name(h.type))
      .kv("machine", elf_machine_name(h.machine))
      .kv("entry", hex(h.entry))
      .kv_opt("interpreter", f.interpreter)
      .kv("program_headers", f.segments.size())
      .kv("section_headers", f.sections.size())
      .end_object();

  if (want_checksec(opt)) {
    const auto c = checksec_elf(f);
    j.key("checksec").begin_object();
    j.kv("relro", c.relro == Relro::Full ? "full" : c.relro == Relro::Partial ? "partial" : "none");
    j.kv("canary", c.canary);
    j.key("nx");
    if (c.nx == Nx::NotApplicable) j.null();
    else j.value(c.nx == Nx::Enabled);
    j.kv("pie", c.pie == Pie::Yes ? "pie" : c.pie == Pie::No ? "no" : c.pie == Pie::Dso ? "dso" : "rel");
    j.kv("fortify", c.fortify);
    j.key("fortified_functions").begin_array();
    for (const auto& n : c.fortified) j.value(n);
    j.end_array();
    j.kv_opt("rpath", c.rpath).kv_opt("runpath", c.runpath).kv("stripped", c.stripped).end_object();
  }

  if (want_sections(opt)) {
    j.key("segments").begin_array();
    for (const auto& p : f.segments) {
      j.begin_object()
          .kv("type", elf_segment_type_name(p.type))
          .kv("flags", elf_segment_flags(p.flags))
          .kv("offset", hex(p.offset))
          .kv("vaddr", hex(p.vaddr))
          .kv("filesz", p.filesz)
          .kv("memsz", p.memsz)
          .end_object();
    }
    j.end_array();
    j.key("sections").begin_array();
    for (const auto& s : f.sections) {
      j.begin_object()
          .kv("name", s.name)
          .kv("type", elf_section_type_name(s.type))
          .kv("flags", elf_section_flags(s.flags))
          .kv("addr", hex(s.addr))
          .kv("offset", hex(s.offset))
          .kv("size", s.size)
          .end_object();
    }
    j.end_array();
  }

  if (want_symbols(opt)) {
    j.key("dynsym");
    elf_symbols_json(j, f.dynamic_symbols);
    j.key("symtab");
    elf_symbols_json(j, f.symbols);
  }

  if (opt.all) {
    j.key("dynamic").begin_array();
    for (const auto& d : f.dynamic) {
      j.begin_object().kv("tag", elf_dynamic_tag_name(d.tag)).kv("value", hex(d.value));
      if (!d.str.empty()) j.kv("string", d.str);
      j.end_object();
    }
    j.end_array();
  }

  j.key("warnings").begin_array();
  for (const auto& w : f.warnings) j.value(w);
  j.end_array();
  j.end_object();
  return j.str();
}

}  // namespace binsec
