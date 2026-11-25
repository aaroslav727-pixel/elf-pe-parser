cmake_minimum_required(VERSION 3.25)
project(binsec VERSION 0.1.0 LANGUAGES CXX)

option(BINSEC_BUILD_TESTS  "Build unit tests"                        ON)
option(BINSEC_BUILD_FUZZER "Build the libFuzzer target (Clang only)" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

set(BINSEC_WARNINGS -Wall -Wextra -Werror)

# Fuzzing: sanitizers must instrument the parser library itself, not only the harness.
if(BINSEC_BUILD_FUZZER)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "BINSEC_BUILD_FUZZER requires Clang (libFuzzer)")
  endif()
  if(WIN32)
    message(FATAL_ERROR "libFuzzer + ASan are not supported on this toolchain; build the fuzzer on Linux/WSL")
  endif()
  set(BINSEC_SAN_FLAGS -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g)
  add_compile_options(${BINSEC_SAN_FLAGS})
  add_link_options(-fsanitize=address,undefined)
endif()

# ---- library ---------------------------------------------------------------
add_library(binsec_lib STATIC
  src/version.cpp
)
target_include_directories(binsec_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(binsec_lib PRIVATE ${BINSEC_WARNINGS})
if(BINSEC_BUILD_FUZZER)
  # coverage feedback for libFuzzer inside the parser
  target_compile_options(binsec_lib PRIVATE -fsanitize=fuzzer-no-link)
endif()

# ---- CLI -------------------------------------------------------------------
add_executable(binsec src/main.cpp)
target_link_libraries(binsec PRIVATE binsec_lib)
target_compile_options(binsec PRIVATE ${BINSEC_WARNINGS})

# ---- tests -----------------------------------------------------------------
if(BINSEC_BUILD_TESTS)
  enable_testing()
  add_executable(binsec_tests
    tests/test_main.cpp
    fuzz/fuzz_parser.cpp
  )
  target_link_libraries(binsec_tests PRIVATE binsec_lib)
  target_compile_options(binsec_tests PRIVATE ${BINSEC_WARNINGS})
  target_compile_definitions(binsec_tests PRIVATE
    BINSEC_CRASH_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fuzz/crashes")
  add_test(NAME unit_tests COMMAND binsec_tests)
  add_test(NAME cli_usage COMMAND binsec --help)
endif()

# ---- fuzzer ----------------------------------------------------------------
if(BINSEC_BUILD_FUZZER)
  add_executable(binsec_fuzz fuzz/fuzz_parser.cpp)
  target_link_libraries(binsec_fuzz PRIVATE binsec_lib)
  target_compile_options(binsec_fuzz PRIVATE ${BINSEC_WARNINGS} -fsanitize=fuzzer)
  target_link_options(binsec_fuzz PRIVATE -fsanitize=fuzzer)
endif()
