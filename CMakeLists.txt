cmake_minimum_required(VERSION 3.20)
project(aas-sign LANGUAGES CXX C)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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
  FetchContent_Declare(mbedtls
    URL                     https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.2/mbedtls-3.6.2.tar.bz2
    URL_HASH                SHA256=8b54fb9bcf4d5a7078028e0520acddefb7900b3e66fec7f7175bb5b7d85ccdca
    DOWNLOAD_EXTRACT_TIMESTAMP FALSE)
  FetchContent_MakeAvailable(mbedtls)
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
  $<$<PLATFORM_ID:Windows>:src/win32.cpp>
  $<$<NOT:$<PLATFORM_ID:Windows>>:src/posix.cpp>
)

target_link_libraries(aas-sign PRIVATE nlohmann_json::nlohmann_json Threads::Threads)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(aas-sign PRIVATE -Wall -Wconversion)
endif()

if(WIN32)
  target_link_libraries(aas-sign PRIVATE winhttp bcrypt shell32)
else()
  target_include_directories(aas-sign PRIVATE
    ${mbedtls_SOURCE_DIR}/include)
  target_link_libraries(aas-sign PRIVATE
    mbedtls
    mbedx509
    mbedcrypto)
endif()
