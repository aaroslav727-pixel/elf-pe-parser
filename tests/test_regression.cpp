// Replays every saved fuzzer crash and every corpus seed through the fuzz target.
// Passing means: no crash, no sanitizer report (when built with sanitizers).
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <vector>

#include "test.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

namespace {
std::size_t replay_dir(const char* dir) {
  namespace fs = std::filesystem;
  std::size_t n = 0;
  std::error_code ec;
  for (const auto& e : fs::directory_iterator(dir, ec)) {
    if (!e.is_regular_file() || e.path().filename().string().starts_with(".")) continue;
    std::ifstream in(e.path(), std::ios::binary);
    std::vector<std::uint8_t> data{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK_EQ(LLVMFuzzerTestOneInput(data.data(), data.size()), 0);
    ++n;
  }
  return n;
}
}  // namespace

TEST(regression_fuzz_crashes) {
  const auto n = replay_dir(BINSEC_CRASH_DIR);
  std::printf("       replayed %zu crash file(s)\n", n);
}

TEST(regression_fuzz_corpus) {
  const auto n = replay_dir(BINSEC_CORPUS_DIR);
  std::printf("       replayed %zu corpus file(s)\n", n);
  CHECK(n > 0);
}
