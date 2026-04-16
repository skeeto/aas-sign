cmake_minimum_required(VERSION 3.20)
project(aas-sign LANGUAGES CXX C)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        v3.11.3
  GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(json)

if(NOT WIN32)
  set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
  set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
  set(MBEDTLS_AS_SUBPROJECT ON CACHE BOOL "" FORCE)
  FetchContent_Declare(mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v3.6.2
    GIT_SHALLOW    TRUE)
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

target_link_libraries(aas-sign PRIVATE nlohmann_json::nlohmann_json)

if(WIN32)
  target_link_libraries(aas-sign PRIVATE winhttp bcrypt)
else()
  target_include_directories(aas-sign PRIVATE
    ${mbedtls_SOURCE_DIR}/include)
  target_link_libraries(aas-sign PRIVATE
    mbedtls
    mbedx509
    mbedcrypto)
endif()
