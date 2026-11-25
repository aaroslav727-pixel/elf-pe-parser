// Fallback driver for toolchains without libFuzzer (e.g. MSYS2/MinGW clang with
// ASan+UBSan). Replays files and, with -max_total_time=N, runs a simple random
// mutation loop over them. On a sanitizer crash the current input is written to
// <crash_dir>/crash-<n>. The primary fuzzer is libFuzzer on Linux (binsec_fuzz).
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>
#include <string>
#include <vector>

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#include <sanitizer/common_interface_defs.h>
#define BINSEC_HAVE_DEATH_CALLBACK 1
#endif
#endif

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

namespace fs = std::filesystem;

namespace {
std::vector<std::uint8_t> g_current;
std::string g_crash_dir = "fuzz/crashes";

void dump_current() {
  std::error_code ec;
  fs::create_directories(g_crash_dir, ec);
  const auto path = fs::path(g_crash_dir) / ("crash-" + std::to_string(std::hash<std::string>{}(
                                                 std::string(g_current.begin(), g_current.end()))));
  std::ofstream(path, std::ios::binary).write(reinterpret_cast<const char*>(g_current.data()),
                                              static_cast<std::streamsize>(g_current.size()));
  std::fprintf(stderr, "\n==binsec== crashing input written to %s\n", path.string().c_str());
}

std::vector<std::uint8_t> read_all(const fs::path& p) {
  std::ifstream in(p, std::ios::binary);
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void mutate(std::vector<std::uint8_t>& v, std::mt19937_64& rng) {
  static constexpr std::uint8_t interesting[] = {0x00, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff, 0x40, 0x20};
  const int n = 1 + static_cast<int>(rng() % 8);
  for (int i = 0; i < n; ++i) {
    if (v.empty()) v.push_back(0);
    const std::size_t pos = rng() % v.size();
    // header bytes are the most interesting: bias half of the edits to the first 512 bytes
    const std::size_t hpos = (rng() & 1) ? pos % std::min<std::size_t>(v.size(), 512) : pos;
    switch (rng() % 7) {
      case 0: v[hpos] ^= static_cast<std::uint8_t>(1u << (rng() % 8)); break;
      case 1: v[hpos] = interesting[rng() % sizeof interesting]; break;
      case 2: v[hpos] = static_cast<std::uint8_t>(rng()); break;
      case 3: v.resize(pos); break;  // truncate
      case 4: v.insert(v.begin() + static_cast<std::ptrdiff_t>(pos), static_cast<std::uint8_t>(rng())); break;
      case 5: v.erase(v.begin() + static_cast<std::ptrdiff_t>(pos)); break;
      case 6: {  // 32-bit little/big endian field overwrite with an extreme value
        const std::uint32_t vals[] = {0, 1, 0x7fffffff, 0x80000000, 0xffffffff, 0xffff, static_cast<std::uint32_t>(v.size())};
        const std::uint32_t x = vals[rng() % 7];
        for (int b = 0; b < 4 && hpos + b < v.size(); ++b) v[hpos + b] = static_cast<std::uint8_t>(x >> (8 * b));
        break;
      }
    }
  }
}
}  // namespace

int main(int argc, char** argv) {
  double max_time = 0;
  std::uint64_t seed = 1;
  std::vector<std::vector<std::uint8_t>> inputs;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if (a.rfind("-max_total_time=", 0) == 0) max_time = std::stod(a.substr(16));
    else if (a.rfind("-seed=", 0) == 0) seed = std::stoull(a.substr(6));
    else if (a.rfind("-crash_dir=", 0) == 0) g_crash_dir = a.substr(11);
    else if (fs::is_directory(a)) {
      for (const auto& e : fs::directory_iterator(a))
        if (e.is_regular_file() && e.path().filename().string()[0] != '.') inputs.push_back(read_all(e.path()));
    } else if (fs::is_regular_file(a)) inputs.push_back(read_all(a));
  }
#ifdef BINSEC_HAVE_DEATH_CALLBACK
  __sanitizer_set_death_callback(dump_current);
#endif
  for (const auto& in : inputs) {
    g_current = in;
    LLVMFuzzerTestOneInput(g_current.data(), g_current.size());
  }
  std::printf("replayed %zu input(s)\n", inputs.size());
  if (max_time <= 0 || inputs.empty()) return 0;

  std::mt19937_64 rng(seed);
  const auto start = std::chrono::steady_clock::now();
  std::uint64_t execs = 0;
  for (;;) {
    const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    if (elapsed >= max_time) break;
    g_current = inputs[rng() % inputs.size()];
    mutate(g_current, rng);
    LLVMFuzzerTestOneInput(g_current.data(), g_current.size());
    if ((++execs & 0xffff) == 0) std::printf("#%llu execs, %.0fs\n", static_cast<unsigned long long>(execs), elapsed);
  }
  std::printf("done: %llu execs in %.0fs, no crashes\n", static_cast<unsigned long long>(execs), max_time);
  return 0;
}
