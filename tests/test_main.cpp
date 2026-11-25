#include <cstdio>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include "binsec/version.hpp"
#include "elf_builder.hpp"
#include "pe_builder.hpp"
#include "test.hpp"

TEST(version_is_set) { CHECK(!binsec::version().empty()); }

namespace {
// `binsec_tests --write-seeds DIR`: dump the synthetic ELF/PE images used by the
// tests, as compiler-independent seeds for fuzz/gen_corpus.py.
int write_seeds(const std::string& dir) {
  auto save = [&](const std::string& name, const std::vector<std::uint8_t>& v) {
    std::ofstream(dir + "/" + name, std::ios::binary)
        .write(reinterpret_cast<const char*>(v.data()), static_cast<std::streamsize>(v.size()));
  };
  for (bool is64 : {true, false})
    for (bool be : {false, true}) {
      testelf::Spec sp;
      sp.is64 = is64;
      sp.big_endian = be;
      sp.rpath = "/opt/lib";
      save(std::string("seed_elf") + (is64 ? "64" : "32") + (be ? "be" : "le"), testelf::build(sp));
    }
  for (bool plus : {true, false}) {
    testpe::Spec sp;
    sp.pe32_plus = plus;
    sp.exports = {"alpha", "beta"};
    sp.certificate = true;
    sp.seh_table = !plus;
    save(std::string("seed_pe") + (plus ? "32plus" : "32"), testpe::build(sp));
  }
  std::printf("seeds written to %s\n", dir.c_str());
  return 0;
}
}  // namespace

int main(int argc, char** argv) {
  if (argc == 3 && std::string_view(argv[1]) == "--write-seeds") return write_seeds(argv[2]);
  const std::string_view filter = argc > 1 ? argv[1] : "";
  int run = 0;
  for (const auto& c : test::registry()) {
    if (!filter.empty() && std::string_view(c.name).find(filter) == std::string_view::npos) continue;
    const int before = test::failures();
    c.fn();
    ++run;
    std::printf("[%s] %s\n", test::failures() == before ? " OK " : "FAIL", c.name);
  }
  std::printf("%d test(s), %d failure(s)\n", run, test::failures());
  return test::failures() == 0 ? 0 : 1;
}
