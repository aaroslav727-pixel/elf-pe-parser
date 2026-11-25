#include <algorithm>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

#include "binsec/elf.hpp"
#include "binsec/reader.hpp"
#include "elf_builder.hpp"
#include "test.hpp"

using namespace binsec;

namespace {
std::vector<std::uint8_t> garbage(std::size_t n, std::uint32_t seed) {
  std::vector<std::uint8_t> v(n);
  for (auto& b : v) {
    seed = seed * 1664525u + 1013904223u;
    b = static_cast<std::uint8_t>(seed >> 24);
  }
  return v;
}

bool has_symbol(const std::vector<ElfSymbol>& syms, const std::string& name) {
  return std::any_of(syms.begin(), syms.end(), [&](const ElfSymbol& s) { return s.name == name; });
}
}  // namespace

TEST(reader_bounds_and_overflow) {
  const std::uint8_t raw[] = {0x01, 0x02, 0x03, 0x04, 'h', 'i', 0, 'x'};
  Reader le(raw);
  CHECK_EQ(*le.u32(0), 0x04030201u);
  Reader be(raw, Endian::Big);
  CHECK_EQ(*be.u16(0), 0x0102u);
  CHECK(!le.u32(5).ok());
  CHECK(!le.u64(1).ok());
  CHECK(!le.u8(std::numeric_limits<std::uint64_t>::max()).ok());
  CHECK(!le.sub(4, std::numeric_limits<std::uint64_t>::max()).ok());
  CHECK(!le.in_bounds(std::numeric_limits<std::uint64_t>::max(), 2));
  CHECK_EQ(*le.cstring(4), "hi");
  CHECK(!le.cstring(7).ok());  // unterminated
  CHECK(!le.cstring(8).ok());  // past end
  Cursor c(le, 6);
  c.u32();
  CHECK(c.failed());
  CHECK_EQ(c.u8(), 0);  // sticky
}

TEST(elf64_valid) {
  testelf::Spec sp;
  sp.rpath = "/opt/lib";
  const auto img = testelf::build(sp);
  auto r = parse_elf(img);
  REQUIRE(r.ok());
  const ElfFile& f = *r;
  CHECK_EQ(f.header.bits, 64u);
  CHECK(f.header.endian == Endian::Little);
  CHECK_EQ(f.header.type, elf::ET_DYN);
  CHECK_EQ(f.header.machine, 62);
  CHECK_EQ(f.segments.size(), 5u);
  CHECK(f.find_segment(elf::PT_GNU_RELRO) != nullptr);
  CHECK_EQ(f.interpreter, "/lib64/ld-linux-x86-64.so.2");
  REQUIRE(f.sections.size() == 8u);
  CHECK_EQ(f.sections[1].name, ".interp");
  CHECK_EQ(f.sections.back().name, ".shstrtab");
  CHECK(has_symbol(f.dynamic_symbols, "__stack_chk_fail"));
  CHECK(has_symbol(f.symbols, "main"));
  REQUIRE(!f.dynamic.empty());
  CHECK_EQ(f.dynamic[0].tag, elf::DT_NEEDED);
  CHECK_EQ(f.dynamic[0].str, "libc.so.6");
  CHECK_EQ(f.dynamic[1].str, "/opt/lib");
  CHECK(f.dynamic_value(elf::DT_FLAGS).has_value());
  CHECK(f.warnings.empty());
}

TEST(elf32_valid) {
  testelf::Spec sp;
  sp.is64 = false;
  sp.machine = 3;
  sp.type = elf::ET_EXEC;
  auto r = parse_elf(testelf::build(sp));
  REQUIRE(r.ok());
  CHECK_EQ(r->header.bits, 32u);
  CHECK_EQ(r->header.type, elf::ET_EXEC);
  CHECK_EQ(r->header.entry, 0x401000u);
  CHECK(has_symbol(r->dynamic_symbols, "puts"));
  CHECK(has_symbol(r->symbols, "helper"));
  CHECK_EQ(r->dynamic[0].str, "libc.so.6");
  CHECK(r->warnings.empty());
}

TEST(elf_big_endian_64_and_32) {
  for (bool is64 : {true, false}) {
    testelf::Spec sp;
    sp.is64 = is64;
    sp.big_endian = true;
    sp.machine = is64 ? 21 : 20;  // PowerPC64 / PowerPC
    auto r = parse_elf(testelf::build(sp));
    REQUIRE(r.ok());
    CHECK(r->header.endian == Endian::Big);
    CHECK_EQ(r->header.machine, sp.machine);
    CHECK_EQ(r->sections[1].name, ".interp");
    CHECK(has_symbol(r->dynamic_symbols, "__printf_chk"));
    CHECK_EQ(r->dynamic[0].str, "libc.so.6");
  }
}

TEST(elf_without_section_headers_uses_pt_dynamic) {
  testelf::Spec sp;
  sp.section_headers = false;
  auto r = parse_elf(testelf::build(sp));
  REQUIRE(r.ok());
  CHECK(r->sections.empty());
  CHECK_EQ(r->dynamic[0].str, "libc.so.6");  // resolved via DT_STRTAB -> PT_LOAD
}

TEST(elf_truncated_every_length) {
  for (bool is64 : {true, false}) {
    testelf::Spec sp;
    sp.is64 = is64;
    const auto img = testelf::build(sp);
    for (std::size_t len = img.size(); len-- > 0;) {
      auto r = parse_elf(std::span(img.data(), len));  // must never crash
      if (len < (is64 ? 64u : 52u)) CHECK(!r.ok());
    }
    // section header table sits at the very end: dropping one byte must be an error
    CHECK(!parse_elf(std::span(img.data(), img.size() - 1)).ok());
  }
}

TEST(elf_bad_magic) {
  auto img = testelf::build({});
  img[3] = 'G';
  auto r = parse_elf(img);
  REQUIRE(!r.ok());
  CHECK(r.error().code == ErrorCode::BadMagic);
  CHECK(!parse_elf(std::span<const std::uint8_t>{}).ok());
}

TEST(elf_garbage_input) {
  for (std::uint32_t seed = 1; seed < 200; ++seed) {
    auto g = garbage(seed * 7, seed);
    auto r = parse_elf(g);
    CHECK(!r.ok());
    if (g.size() >= 4) {
      g[0] = 0x7f, g[1] = 'E', g[2] = 'L', g[3] = 'F';  // valid magic, garbage body
      (void)parse_elf(g);                               // ok or error, but no crash
    }
  }
}

TEST(elf_unsupported_class_and_encoding) {
  auto img = testelf::build({});
  auto bad_class = img;
  bad_class[4] = 3;
  auto r1 = parse_elf(bad_class);
  REQUIRE(!r1.ok());
  CHECK(r1.error().code == ErrorCode::Unsupported);
  auto bad_data = img;
  bad_data[5] = 0;
  CHECK(parse_elf(bad_data).error().code == ErrorCode::Unsupported);
}

TEST(elf_corrupted_fields_are_tolerated) {
  const auto img = testelf::build({});
  auto r = parse_elf(img);
  REQUIRE(r.ok());
  const std::size_t shoff = r->header.shoff;

  auto bad_strndx = img;  // e_shstrndx -> out of range
  bad_strndx[62] = 0xee, bad_strndx[63] = 0x00;
  auto r1 = parse_elf(bad_strndx);
  REQUIRE(r1.ok());
  CHECK(!r1->warnings.empty());

  auto bad_offsets = img;  // .dynsym (section 3) sh_offset -> huge
  for (int i = 0; i < 8; ++i) bad_offsets[shoff + 3 * 64 + 24 + i] = 0xff;
  auto r2 = parse_elf(bad_offsets);
  REQUIRE(r2.ok());
  CHECK(r2->dynamic_symbols.empty());
  CHECK(!r2->warnings.empty());

  auto bad_phent = img;  // e_phentsize too small -> structured error
  bad_phent[54] = 8, bad_phent[55] = 0;
  CHECK(parse_elf(bad_phent).error().code == ErrorCode::Malformed);

  auto huge_phnum = img;  // e_phnum = 0xfffe -> table exceeds file
  huge_phnum[56] = 0xfe, huge_phnum[57] = 0xff;
  CHECK(parse_elf(huge_phnum).error().code == ErrorCode::OutOfBounds);
}
