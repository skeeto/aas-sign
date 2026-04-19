cmake_minimum_required(VERSION 3.20)
project(aas-sign VERSION 0.3.0 LANGUAGES CXX C)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable Windows resource compiler (windres on MinGW / rc on MSVC).
if(WIN32)
  enable_language(RC)
endif()

find_package(Threads REQUIRED)

include(FetchContent)

FetchContent_Declare(json
  URL                     https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
  URL_HASH                SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
  DOWNLOAD_EXTRACT_TIMESTAMP FALSE)
FetchContent_MakeAvailable(json)

if(NOT WIN32)
  set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
  set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
  set(MBEDTLS_AS_SUBPROJECT ON CACHE BOOL "" FORCE)
  # mbedTLS 3.6.2 enables -Werror by default and newer clang (>=19)
  # adds diagnostics that trip it.  We don't need mbedTLS to be that
  # strict for our consumer-level use.
  set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(mbedtls
    URL                     https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.2/mbedtls-3.6.2.tar.bz2
    URL_HASH                SHA256=8b54fb9bcf4d5a7078028e0520acddefb7900b3e66fec7f7175bb5b7d85ccdca
    DOWNLOAD_EXTRACT_TIMESTAMP FALSE)
  FetchContent_MakeAvailable(mbedtls)
endif()

# Windows EXE metadata (CompanyName, FileVersion, etc.) via .rc file.
# The template substitutes CMake project version into both the numeric
# FILEVERSION/PRODUCTVERSION fields and the displayed string fields.
if(WIN32)
  configure_file(src/aas-sign.rc.in
                 ${CMAKE_CURRENT_BINARY_DIR}/aas-sign.rc @ONLY)
endif()

add_executable(aas-sign
  src/main.cpp
  src/base64.cpp
  src/der.cpp
  src/x509.cpp
  src/pe.cpp
  src/azure.cpp
  src/cms.cpp
  src/tsa.cpp
  src/oidc.cpp
  src/urlenc.cpp
  src/signer.cpp
  src/auth_laptop.cpp
  $<$<PLATFORM_ID:Windows>:src/win32.cpp>
  $<$<PLATFORM_ID:Windows>:${CMAKE_CURRENT_BINARY_DIR}/aas-sign.rc>
  $<$<NOT:$<PLATFORM_ID:Windows>>:src/posix.cpp>
)

target_compile_definitions(aas-sign PRIVATE
  AAS_SIGN_VERSION="${PROJECT_VERSION}")

target_link_libraries(aas-sign PRIVATE nlohmann_json::nlohmann_json Threads::Threads)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(aas-sign PRIVATE -Wall -Wconversion)
endif()

if(WIN32)
  target_link_libraries(aas-sign PRIVATE
    winhttp bcrypt shell32 ws2_32)
else()
  target_include_directories(aas-sign PRIVATE
    ${mbedtls_SOURCE_DIR}/include)
  target_link_libraries(aas-sign PRIVATE
    mbedtls
    mbedx509
    mbedcrypto)
endif()

# libFuzzer harnesses.  Built only when explicitly requested; requires
# Clang (for libFuzzer).  Detection of libstdc++ vs libc++ and the
# per-harness add_executable wiring live in cmake/Fuzzing.cmake.
option(AAS_SIGN_FUZZ "Build libFuzzer harnesses (Clang-only, POSIX)" OFF)

if(AAS_SIGN_FUZZ)
  list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
  include(Fuzzing)
endif()
