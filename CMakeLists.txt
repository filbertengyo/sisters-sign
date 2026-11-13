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

foreach(comp util crypto manifest bundle trust cli)
  add_subdirectory(src/${comp})
endforeach()

add_executable(sister-sign src/main.cpp)
target_link_libraries(sister-sign PRIVATE core project_options)

enable_testing()
add_executable(unit_tests tests/unit/main.cpp tests/unit/smoke_test.cpp tests/unit/result_test.cpp)
target_link_libraries(unit_tests PRIVATE core doctest::doctest project_options)
add_test(NAME unit_tests COMMAND unit_tests)

# Spike C (T04): Ed25519 one-shot + parameter RSA-PSS; lihat docs/spike-c.md
add_executable(spike_c tests/spikes/ed_rsa_spike.cpp)
target_link_libraries(spike_c PRIVATE OpenSSL::Crypto doctest::doctest project_options)
add_test(NAME spike_c COMMAND spike_c)

add_executable(bench bench/bench_main.cpp)
target_link_libraries(bench PRIVATE core project_options)
