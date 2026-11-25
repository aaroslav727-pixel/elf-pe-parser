#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "binsec/binary.hpp"
#include "binsec/checksec.hpp"
#include "binsec/pe.hpp"
#include "binsec/report.hpp"
#include "elf_builder.hpp"
#include "pe_builder.hpp"
#include "test.hpp"

using namespace binsec;

namespace {
void put32(std::vector<std::uint8_t>& v, std::size_t off, std::uint32_t x) {
  for (int i = 0; i < 4; ++i) v[off + i] = static_cast<std::uint8_t>(x >> (8 * i));
}
PeChecksec run(const testpe::Spec& sp) {
  auto r = parse_pe(testpe::build(sp));
  return r ? checksec_pe(*r) : PeChecksec{};
}
}  // namespace

TEST(pe32plus_valid) {
  testpe::Spec sp;
  sp.dll = true;
  sp.exports = {"alpha", "beta"};
  auto r = parse_pe(testpe::build(sp));
  REQUIRE(r.ok());
  const PeFile& f = *r;
  CHECK(f.pe32_plus);
  CHECK_EQ(f.magic, pe::MAGIC_PE32_PLUS);
  CHECK_EQ(f.machine, 0x8664);
  CHECK_EQ(f.image_base, 0x140000000ull);
  CHECK_EQ(f.entry_point, 0x1000u);
  REQUIRE(f.sections.size() == 2u);
  CHECK_EQ(f.sections[0].name, ".text");
  CHECK_EQ(f.sections[1].name, ".rdata");
  REQUIRE(f.imports.size() == 2u);
  CHECK_EQ(f.imports[0].dll, "KERNEL32.dll");
  CHECK((f.imports[0].functions == std::vector<std::string>{"ExitProcess", "GetStdHandle", "#17"}));
  CHECK_EQ(f.imports[1].functions.at(0), "printf");
  CHECK_EQ(f.export_dll_name, "test.dll");
  REQUIRE(f.exports.size() == 2u);
  CHECK_EQ(f.exports[1].name, "beta");
  CHECK_EQ(f.exports[1].ordinal, 2u);
  CHECK_EQ(f.exports[1].rva, 0x1010u);
  CHECK(f.load_config.present);
  CHECK(f.warnings.empty());
}

TEST(pe32_valid) {
  testpe::Spec sp;
  sp.pe32_plus = false;
  auto r = parse_pe(testpe::build(sp));
  REQUIRE(r.ok());
  CHECK(!r->pe32_plus);
  CHECK_EQ(r->magic, pe::MAGIC_PE32);
  CHECK_EQ(r->machine, 0x14c);
  CHECK_EQ(r->image_base, 0x400000u);
  REQUIRE(r->imports.size() == 2u);
  CHECK_EQ(r->imports[0].functions.at(2), "#17");
  CHECK(r->warnings.empty());
}

TEST(pe_checksec) {
  const auto c = run({});
  CHECK(c.aslr);
  CHECK(c.high_entropy_va);
  CHECK(c.dep);
  CHECK(c.cfg);
  CHECK(c.safeseh == SafeSeh::NotApplicable);
  CHECK(c.gs);
  CHECK(!c.authenticode);

  testpe::Spec none;
  none.dll_characteristics = 0;
  none.load_config = false;
  const auto n = run(none);
  CHECK(!n.aslr && !n.high_entropy_va && !n.dep && !n.cfg && !n.gs);

  testpe::Spec signed_pe;
  signed_pe.certificate = true;
  CHECK(run(signed_pe).authenticode);

  testpe::Spec x86;
  x86.pe32_plus = false;
  CHECK(run(x86).safeseh == SafeSeh::No);
  CHECK(!run(x86).high_entropy_va);  // HEVA is meaningless for 32-bit images
  x86.seh_table = true;
  CHECK(run(x86).safeseh == SafeSeh::Yes);
  x86.dll_characteristics |= pe::DLL_NO_SEH;
  CHECK(run(x86).safeseh == SafeSeh::NoSeh);
}

TEST(pe_truncated_every_length) {
  for (bool plus : {true, false}) {
    testpe::Spec sp;
    sp.pe32_plus = plus;
    sp.exports = {"alpha"};
    sp.certificate = true;
    const auto img = testpe::build(sp);
    for (std::size_t len = img.size(); len-- > 0;) {
      auto r = parse_pe(std::span(img.data(), len));  // must never crash
      if (len < (plus ? 0x1d8u : 0x1c8u)) CHECK(!r.ok());  // section table incomplete
    }
  }
}

TEST(pe_bad_headers) {
  const auto img = testpe::build({});
  auto far = img;
  put32(far, 0x3c, 0xfffffff0);
  CHECK(parse_pe(far).error().code == ErrorCode::OutOfBounds);

  auto sig = img;
  sig[0x81] = 'X';
  CHECK(parse_pe(sig).error().code == ErrorCode::BadMagic);

  auto magic = img;
  magic[0x98] = 0x07, magic[0x99] = 0x01;
  CHECK(parse_pe(magic).error().code == ErrorCode::Unsupported);

  auto nsec = img;
  nsec[0x86] = 0xff, nsec[0x87] = 0xff;
  CHECK(parse_pe(nsec).error().code == ErrorCode::OutOfBounds);

  auto small_opt = img;
  small_opt[0x94] = 0x10, small_opt[0x95] = 0;
  CHECK(parse_pe(small_opt).error().code == ErrorCode::Malformed);

  auto bad_import = img;  // import directory RVA pointing nowhere -> warning, not error
  put32(bad_import, 0x98 + 112 + 8, 0x7fff0000);
  auto r = parse_pe(bad_import);
  REQUIRE(r.ok());
  CHECK(r->imports.empty());
  CHECK(!r->warnings.empty());
}

TEST(pe_garbage_input) {
  std::uint32_t seed = 7;
  for (std::size_t n = 2; n < 600; n += 3) {
    std::vector<std::uint8_t> g(n);
    for (auto& b : g) b = static_cast<std::uint8_t>((seed = seed * 1664525u + 1013904223u) >> 24);
    g[0] = 'M', g[1] = 'Z';
    if (n > 0x40) put32(g, 0x3c, static_cast<std::uint32_t>(n / 2));
    (void)parse_pe(g);  // ok or error, never a crash
  }
  CHECK(!parse_pe(std::span<const std::uint8_t>{}).ok());
}

TEST(format_detection) {
  CHECK(*detect_format(testelf::build({})) == Format::Elf);
  CHECK(*detect_format(testpe::build({})) == Format::Pe);
  const std::uint8_t text[] = {'h', 'e', 'l', 'l', 'o'};
  CHECK(detect_format(text).error().code == ErrorCode::UnknownFormat);
  CHECK(parse_binary(std::span<const std::uint8_t>{}).error().code == ErrorCode::UnknownFormat);
  auto pe_bin = parse_binary(testpe::build({}));
  REQUIRE(pe_bin.ok());
  CHECK(std::holds_alternative<PeFile>(*pe_bin));
  auto elf_bin = parse_binary(testelf::build({}));
  REQUIRE(elf_bin.ok());
  CHECK(std::holds_alternative<ElfFile>(*elf_bin));
}

TEST(pe_report) {
  testpe::Spec sp;
  sp.exports = {"alpha"};
  auto r = parse_binary(testpe::build(sp));
  REQUIRE(r.ok());
  ReportOptions opt;
  opt.all = true;
  const auto json = render_json(*r, "t.exe", opt);
  CHECK(json.find("\"format\": \"PE\"") != std::string::npos);
  CHECK(json.find("\"aslr\": true") != std::string::npos);
  CHECK(json.find("\"dll\": \"KERNEL32.dll\"") != std::string::npos);
  const auto text = render_text(*r, "t.exe", opt);
  CHECK(text.find("PE32+ (64-bit)") != std::string::npos);
  CHECK(text.find("ExitProcess") != std::string::npos);
  CHECK(text.find("LOAD_CONFIG") != std::string::npos);
}
