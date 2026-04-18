# cmake/Fuzzing.cmake
#
# libFuzzer harness wiring.  Included from the top-level CMakeLists
# only when AAS_SIGN_FUZZ=ON.  Requires Clang (libFuzzer ships with
# it).  Tested on Linux + macOS; Windows is out of scope.  Applies
# ASan + UBSan and the stdlib's debug-mode hardening (detected below).

if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  message(FATAL_ERROR "AAS_SIGN_FUZZ requires Clang (libFuzzer)")
endif()
if(WIN32)
  message(FATAL_ERROR "AAS_SIGN_FUZZ is not supported on Windows")
endif()

# --- stdlib detection --------------------------------------------------
#
# The two C++ standard libraries we might end up with on a Linux+Clang
# host each expose their own debug/hardening mode via a different
# preprocessor knob.  Probe for which is actually in use (Clang on
# Linux defaults to libstdc++; a user may override with -stdlib=libc++)
# and apply the matching flag.
#
#   libstdc++ -> _GLIBCXX_DEBUG (+ _GLIBCXX_DEBUG_PEDANTIC)
#   libc++    -> _LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG

include(CheckCXXSourceCompiles)

check_cxx_source_compiles("
#include <version>
#ifndef __GLIBCXX__
#error not libstdc++
#endif
int main() {}
" AAS_SIGN_STDLIB_LIBSTDCXX)

check_cxx_source_compiles("
#include <version>
#ifndef _LIBCPP_VERSION
#error not libc++
#endif
int main() {}
" AAS_SIGN_STDLIB_LIBCXX)

set(_aas_fuzz_defs "")
if(AAS_SIGN_STDLIB_LIBSTDCXX)
  message(STATUS "aas-sign fuzz: libstdc++ detected; enabling _GLIBCXX_DEBUG")
  list(APPEND _aas_fuzz_defs _GLIBCXX_DEBUG _GLIBCXX_DEBUG_PEDANTIC)
elseif(AAS_SIGN_STDLIB_LIBCXX)
  message(STATUS "aas-sign fuzz: libc++ detected; enabling _LIBCPP_HARDENING_MODE_DEBUG")
  list(APPEND _aas_fuzz_defs
       _LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG)
else()
  message(WARNING
    "aas-sign fuzz: could not detect libstdc++ or libc++; "
    "no stdlib hardening will be applied")
endif()

set(_aas_fuzz_flags
  -fsanitize=fuzzer,address,undefined
  -fno-omit-frame-pointer
  -g)

# --- harness helper ----------------------------------------------------
#
# aas_sign_add_fuzz_target(<name> <sources...>)
#   Adds a libFuzzer harness executable with the common ASan/UBSan/
#   stdlib-debug flags, include paths, and library links.  Each harness
#   pulls in only the .cpp files it actually needs (see call sites
#   below) to keep link times low.

function(aas_sign_add_fuzz_target name)
  add_executable(${name} ${ARGN})
  target_include_directories(${name} PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${mbedtls_SOURCE_DIR}/include)
  target_compile_options(${name} PRIVATE ${_aas_fuzz_flags})
  target_compile_definitions(${name} PRIVATE ${_aas_fuzz_defs}
                                             AAS_SIGN_NO_MAIN)
  target_link_options(${name} PRIVATE ${_aas_fuzz_flags})
  target_link_libraries(${name} PRIVATE
    nlohmann_json::nlohmann_json
    mbedtls mbedx509 mbedcrypto Threads::Threads)
endfunction()

# --- targets -----------------------------------------------------------

aas_sign_add_fuzz_target(fuzz_der_tlv
  fuzz/fuzz_der_tlv.cpp
  src/x509.cpp)

aas_sign_add_fuzz_target(fuzz_x509_cert_id
  fuzz/fuzz_x509_cert_id.cpp
  src/x509.cpp)

aas_sign_add_fuzz_target(fuzz_x509_split_certs
  fuzz/fuzz_x509_split_certs.cpp
  src/x509.cpp)

aas_sign_add_fuzz_target(fuzz_tsa_parse
  fuzz/fuzz_tsa_parse.cpp
  src/tsa.cpp src/x509.cpp src/der.cpp src/base64.cpp src/posix.cpp)

aas_sign_add_fuzz_target(fuzz_pe
  fuzz/fuzz_pe.cpp
  src/pe.cpp src/posix.cpp)
