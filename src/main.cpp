// binsec CLI: binsec <file> [--checksec] [--sections] [--symbols] [--all] [--json]
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

#include "binsec/elf.hpp"
#include "binsec/report.hpp"
#include "binsec/version.hpp"

namespace {

constexpr const char* kUsage =
    "usage: binsec <file> [--checksec] [--sections] [--symbols] [--all] [--json]\n"
    "\n"
    "  --checksec  security hardening audit (default when no other view is selected)\n"
    "  --sections  program/section headers\n"
    "  --symbols   symbol tables (ELF) / imports and exports (PE)\n"
    "  --all       everything, including the dynamic section\n"
    "  --json      machine-readable JSON instead of tables\n";

binsec::Result<std::vector<std::uint8_t>> read_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return binsec::make_error(binsec::ErrorCode::Io, "cannot open file");
  std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  if (in.bad()) return binsec::make_error(binsec::ErrorCode::Io, "read error");
  return data;
}

int fail(const binsec::Error& e, const std::string& path, bool json) {
  if (json) std::fputs(binsec::render_error_json(e, path).c_str(), stdout);
  else std::fprintf(stderr, "binsec: %s: %s: %s\n", path.c_str(), std::string(error_code_name(e.code)).c_str(),
                    e.message.c_str());
  return 1;
}

}  // namespace

int main(int argc, char** argv) {
  binsec::ReportOptions opt;
  bool json = false;
  std::string path;
  for (int i = 1; i < argc; ++i) {
    const std::string_view a = argv[i];
    if (a == "--help" || a == "-h") {
      std::printf("binsec %.*s\n%s", static_cast<int>(binsec::version().size()), binsec::version().data(), kUsage);
      return 0;
    }
    if (a == "--checksec") opt.checksec = true;
    else if (a == "--sections") opt.sections = true;
    else if (a == "--symbols") opt.symbols = true;
    else if (a == "--all") opt.all = true;
    else if (a == "--json") json = true;
    else if (a.starts_with("--") || !path.empty()) {
      std::fprintf(stderr, "binsec: unexpected argument '%s'\n%s", argv[i], kUsage);
      return 2;
    } else path = a;
  }
  if (path.empty()) {
    std::fputs(kUsage, stderr);
    return 2;
  }
  if (!opt.sections && !opt.symbols && !opt.all) opt.checksec = true;

  auto data = read_file(path);
  if (!data) return fail(data.error(), path, json);

  auto parsed = binsec::parse_elf(*data);
  if (!parsed) return fail(parsed.error(), path, json);
  const std::string out = json ? binsec::render_json(*parsed, path, opt) : binsec::render_text(*parsed, path, opt);
  std::fwrite(out.data(), 1, out.size(), stdout);
  return 0;
}
