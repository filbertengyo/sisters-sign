cmake_minimum_required(VERSION 3.31)
project(sister-sign VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(SISTER_SIGN_WERROR "Treat warnings as errors" ON)
option(SISTER_SIGN_SANITIZE "Enable ASAN + UBSAN" OFF)

add_library(project_options INTERFACE)
target_compile_options(project_options INTERFACE -Wall -Wextra -Wpedantic)
if(SISTER_SIGN_WERROR)
  target_compile_options(project_options INTERFACE -Werror)
endif()
if(SISTER_SIGN_SANITIZE)
  target_compile_options(project_options INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(project_options INTERFACE -fsanitize=address,undefined)
endif()

# Python3
find_package(Python3 COMPONENTS Interpreter REQUIRED)

# OpenSSL >= 3.5: sama dengan image (Debian trixie) dan CI.
# <3.5 streaming Ed25519 crash dan default salt RSA-PSS berbeda.
find_package(OpenSSL 3.5 REQUIRED)

include(FetchContent)
FetchContent_Declare(glaze
  GIT_REPOSITORY https://github.com/stephenberry/glaze.git
  GIT_TAG v8.4.0
  GIT_SHALLOW TRUE
  SYSTEM)
FetchContent_Declare(doctest
  GIT_REPOSITORY https://github.com/doctest/doctest.git
  GIT_TAG v2.5.1
  GIT_SHALLOW TRUE
  SYSTEM)
FetchContent_MakeAvailable(glaze doctest)

# Library inti: tiap src/<komponen>/CMakeLists.txt menambah source lewat target_sources(core PRIVATE ...)
add_library(core STATIC)
target_include_directories(core PUBLIC ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(core PUBLIC OpenSSL::Crypto glaze::glaze PRIVATE project_options)

foreach(comp util crypto manifest bundle trust verify cli)
  add_subdirectory(src/${comp})
endforeach()

add_executable(sister-sign src/main.cpp)
target_link_libraries(sister-sign PRIVATE core project_options)

enable_testing()
add_executable(unit_tests
  tests/unit/main.cpp
  tests/unit/smoke_test.cpp
  tests/unit/result_test.cpp
  tests/unit/crypto_raii_test.cpp
  tests/unit/crypto_ed25519_test.cpp
  tests/unit/crypto_ecdsa_test.cpp
  tests/unit/crypto_rsa_test.cpp
  tests/unit/crypto_keyid_test.cpp
  tests/unit/crypto_keyio_test.cpp
  tests/unit/hex_test.cpp
  tests/unit/hash_test.cpp
  tests/unit/base64_test.cpp
  tests/unit/json_scan_test.cpp
  tests/unit/manifest_test.cpp
  tests/unit/bundle_test.cpp
  tests/unit/trust_test.cpp
  tests/unit/cli_test.cpp
  tests/unit/cli_keygen_test.cpp
  tests/unit/cli_trust_test.cpp
  tests/unit/cli_sign_test.cpp
  tests/unit/verify_test.cpp
  tests/unit/cli_verify_test.cpp
  tests/unit/bench_stats_test.cpp
  tests/unit/cli_sbom_test.cpp)
target_link_libraries(unit_tests PRIVATE core doctest::doctest project_options)
# bench/stats.hpp (T29) diuji di unit_tests.
target_include_directories(unit_tests PRIVATE ${CMAKE_SOURCE_DIR}/bench)
target_compile_definitions(unit_tests PRIVATE SISTER_SIGN_FIXTURE_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures")
add_test(NAME unit_tests COMMAND unit_tests)

# CLI tidak boleh menunggu input: stdin ditutup (/dev/null), harus keluar 2 tanpa hang.
add_test(NAME cli_no_stdin
  COMMAND sh -c "$<TARGET_FILE:sister-sign> keygen < /dev/null > /dev/null 2>&1; test $? -eq 2")
set_tests_properties(cli_no_stdin PROPERTIES TIMEOUT 10)

# Alat bantu test e2e: membuat/memanipulasi bundle (bukan bagian dari produk).
add_executable(forge tests/tools/forge.cpp)
target_link_libraries(forge PRIVATE core project_options)

# Harness e2e (tests/e2e): kasus contoh harus lulus, dan harness harus mendeteksi kasus gagal.
add_test(NAME e2e_cases
  COMMAND bash ${CMAKE_SOURCE_DIR}/tests/e2e/run.sh $<TARGET_FILE:sister-sign>
          ${CMAKE_SOURCE_DIR}/tests/e2e/cases ${CMAKE_BINARY_DIR}/e2e-results)
add_test(NAME e2e_harness_selftest
  COMMAND bash ${CMAKE_SOURCE_DIR}/tests/e2e/selftest.sh $<TARGET_FILE:sister-sign>
          ${CMAKE_BINARY_DIR}/e2e-selftest)
# Bonus T37: kasus e2e subperintah sbom (terpisah dari U01-U14).
add_test(NAME e2e_sbom
  COMMAND bash ${CMAKE_SOURCE_DIR}/tests/e2e/run.sh $<TARGET_FILE:sister-sign>
          ${CMAKE_SOURCE_DIR}/tests/e2e/sbom-cases ${CMAKE_BINARY_DIR}/e2e-sbom-results)
set_tests_properties(e2e_cases e2e_harness_selftest e2e_sbom PROPERTIES TIMEOUT 300)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/e2e-selftest)

# Satu perintah untuk laporan: jalankan semua kasus dan tulis bukti + tabel ke tests/results/.
add_custom_target(e2e_report
  COMMAND bash ${CMAKE_SOURCE_DIR}/tests/e2e/run.sh $<TARGET_FILE:sister-sign>
          ${CMAKE_SOURCE_DIR}/tests/e2e/cases ${CMAKE_SOURCE_DIR}/tests/results
  DEPENDS sister-sign forge
  USES_TERMINAL)

# Spike A
add_executable(spike_a tests/spikes/glaze_spike.cpp)
target_link_libraries(spike_a PRIVATE doctest::doctest glaze::glaze project_options)
add_test(NAME spike_a COMMAND spike_a)

# Spike C (T04): Ed25519 one-shot + parameter RSA-PSS; lihat docs/spike-c.md
add_executable(spike_c tests/spikes/ed_rsa_spike.cpp)
target_link_libraries(spike_c PRIVATE OpenSSL::Crypto doctest::doctest project_options)
add_test(NAME spike_c COMMAND spike_c)

# Nonce Reuse Attack Demo
add_test(NAME nonce_reuse COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/attacks/nonce_reuse.py)

# Canonicalization Confusion Attack Demo
add_executable(canonicalization_demo tests/attacks/canonicalization_demo.cpp)
target_link_libraries(canonicalization_demo PRIVATE core doctest::doctest glaze::glaze project_options)
add_test(NAME canonicalization_demo COMMAND canonicalization_demo)

# Rollback Attack Demo
add_executable(rollback_demo tests/attacks/rollback_demo.cpp)
target_link_libraries(rollback_demo PRIVATE project_options)
add_test(NAME rollback_demo COMMAND rollback_demo)

# Benchmark (T29): build Release untuk angka yang bermakna; lihat bench/README.md.
add_executable(bench bench/bench_main.cpp)
target_link_libraries(bench PRIVATE core project_options)
