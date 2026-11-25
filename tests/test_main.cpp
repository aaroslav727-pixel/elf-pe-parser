#include <cstdio>
#include <string_view>

#include "binsec/version.hpp"
#include "test.hpp"

TEST(version_is_set) { CHECK(!binsec::version().empty()); }

int main(int argc, char** argv) {
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
