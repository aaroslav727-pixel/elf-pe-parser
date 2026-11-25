#include <string>

#include "binsec/checksec.hpp"
#include "binsec/report.hpp"
#include "elf_builder.hpp"
#include "test.hpp"

using namespace binsec;

namespace {
ElfChecksec run(const testelf::Spec& sp) {
  auto r = parse_elf(testelf::build(sp));
  if (!r) return {};
  return checksec_elf(*r);
}
bool contains(const std::string& s, const std::string& needle) { return s.find(needle) != std::string::npos; }
}  // namespace

TEST(checksec_fully_hardened) {
  const auto c = run({});
  CHECK(c.relro == Relro::Full);
  CHECK(c.pie == Pie::Yes);
  CHECK(c.nx == Nx::Enabled);
  CHECK(c.canary);
  CHECK(c.fortify);
  REQUIRE(c.fortified.size() == 1u);
  CHECK_EQ(c.fortified[0], "__printf_chk");
  CHECK(!c.stripped);
  CHECK(c.rpath.empty());
  CHECK(c.runpath.empty());
}

TEST(checksec_relro_levels) {
  testelf::Spec partial;
  partial.bind_now = false;
  CHECK(run(partial).relro == Relro::Partial);
  testelf::Spec none;
  none.gnu_relro = false;
  CHECK(run(none).relro == Relro::None);
}

TEST(checksec_pie_variants) {
  testelf::Spec exec;
  exec.type = elf::ET_EXEC;
  CHECK(run(exec).pie == Pie::No);
  testelf::Spec dso;
  dso.interp = false;
  CHECK(run(dso).pie == Pie::Dso);
  testelf::Spec static_pie;
  static_pie.interp = false;
  static_pie.flags_1 = elf::DF_1_PIE;
  CHECK(run(static_pie).pie == Pie::Yes);
}

TEST(checksec_nx) {
  testelf::Spec rwx;
  rwx.exec_stack = true;
  CHECK(run(rwx).nx == Nx::Disabled);
  testelf::Spec no_stack;
  no_stack.gnu_stack = false;
  CHECK(run(no_stack).nx == Nx::Disabled);
}

TEST(checksec_canary_fortify_paths_stripped) {
  testelf::Spec sp;
  sp.dynsyms = {"puts", "memcpy"};
  sp.rpath = "/opt/a";
  sp.runpath = "$ORIGIN/lib";
  sp.symtab = false;
  const auto c = run(sp);
  CHECK(!c.canary);
  CHECK(!c.fortify);
  CHECK_EQ(c.rpath, "/opt/a");
  CHECK_EQ(c.runpath, "$ORIGIN/lib");
  CHECK(c.stripped);
}

TEST(report_json_and_text) {
  auto r = parse_elf(testelf::build({}));
  REQUIRE(r.ok());
  ReportOptions opt;
  opt.all = true;
  const auto json = render_json(*r, "a.out", opt);
  CHECK(contains(json, "\"relro\": \"full\""));
  CHECK(contains(json, "\"pie\": \"pie\""));
  CHECK(contains(json, "\"nx\": true"));
  CHECK(contains(json, "\"name\": \".dynsym\""));
  CHECK(contains(json, "\"string\": \"libc.so.6\""));
  const auto text = render_text(*r, "a.out", opt);
  CHECK(contains(text, "Full RELRO"));
  CHECK(contains(text, "Canary found"));
  CHECK(contains(text, ".shstrtab"));
}

TEST(json_escape_untrusted_bytes) {
  CHECK_EQ(json_escape("a\"b\\c\n"), "a\\\"b\\\\c\\n");
  CHECK_EQ(json_escape(std::string("\x01\xff", 2)), "\\u0001\\u00ff");
  const auto err = render_error_json(make_error(ErrorCode::BadMagic, "bad"), "x");
  CHECK(contains(err, "\"code\": \"bad-magic\""));
}
