// Minimal self-contained test harness (no external dependencies).
#pragma once
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace test {

struct Case {
  const char* name;
  std::function<void()> fn;
};

inline std::vector<Case>& registry() {
  static std::vector<Case> cases;
  return cases;
}
inline int& failures() {
  static int n = 0;
  return n;
}

struct Registrar {
  Registrar(const char* name, std::function<void()> fn) { registry().push_back({name, std::move(fn)}); }
};

inline void fail(const char* file, int line, const std::string& what) {
  ++failures();
  std::fprintf(stderr, "  FAIL %s:%d: %s\n", file, line, what.c_str());
}

}  // namespace test

#define TEST_CAT2(a, b) a##b
#define TEST_CAT(a, b) TEST_CAT2(a, b)
#define TEST(name)                                                        \
  static void name();                                                     \
  static const test::Registrar TEST_CAT(reg_, name){#name, &name};        \
  static void name()

#define CHECK(cond)                                                       \
  do {                                                                    \
    if (!(cond)) test::fail(__FILE__, __LINE__, "CHECK(" #cond ")");      \
  } while (0)

#define REQUIRE(cond)                                                     \
  do {                                                                    \
    if (!(cond)) {                                                        \
      test::fail(__FILE__, __LINE__, "REQUIRE(" #cond ")");               \
      return;                                                             \
    }                                                                     \
  } while (0)

#define CHECK_EQ(a, b)                                                    \
  do {                                                                    \
    if (!((a) == (b))) test::fail(__FILE__, __LINE__, "CHECK_EQ(" #a ", " #b ")"); \
  } while (0)
