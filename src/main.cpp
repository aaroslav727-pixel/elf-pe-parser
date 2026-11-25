#include <cstdio>
#include <string_view>

#include "binsec/version.hpp"

int main(int argc, char** argv) {
  if (argc < 2 || std::string_view(argv[1]) == "--help") {
    std::printf("binsec %.*s\nusage: binsec <file>\n", static_cast<int>(binsec::version().size()),
                binsec::version().data());
    return argc < 2 ? 2 : 0;
  }
  return 0;
}
