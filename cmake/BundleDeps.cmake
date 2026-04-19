# Bundle dependencies into deps/ for offline source releases.
# Usage: cmake -P cmake/BundleDeps.cmake
#
# Downloads the same upstream archives the main CMakeLists.txt
# pins and extracts them under deps/.  After running this, the
# tree can be `cmake -B build`'d with no network access: the
# FETCH mode sees deps/<name>/ and uses it directly.

if(NOT DEPS_DIR)
  set(DEPS_DIR "${CMAKE_CURRENT_LIST_DIR}/../deps")
endif()

# Keep these URL/hash pairs in lock-step with the FetchContent_Declare
# entries in ../CMakeLists.txt.
set(JSON_URL  "https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz")
set(JSON_HASH "d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d")

set(MBEDTLS_URL  "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.2/mbedtls-3.6.2.tar.bz2")
set(MBEDTLS_HASH "8b54fb9bcf4d5a7078028e0520acddefb7900b3e66fec7f7175bb5b7d85ccdca")

function(bundle_dep name url hash)
  set(dest "${DEPS_DIR}/${name}")
  if(IS_DIRECTORY "${dest}")
    message(STATUS "${name}: already bundled")
    return()
  endif()

  string(REGEX REPLACE ".*/" "" archive "${url}")
  set(archive_path "${DEPS_DIR}/${archive}")
  message(STATUS "${name}: downloading ${url}")
  file(DOWNLOAD "${url}" "${archive_path}"
       EXPECTED_HASH SHA256=${hash}
       SHOW_PROGRESS)

  # Extract into a scratch dir, then move the sole top-level directory
  # the archive produces to deps/<name>/.
  set(tmp "${DEPS_DIR}/_tmp_${name}")
  file(REMOVE_RECURSE "${tmp}")
  file(MAKE_DIRECTORY "${tmp}")
  file(ARCHIVE_EXTRACT INPUT "${archive_path}" DESTINATION "${tmp}")
  file(REMOVE "${archive_path}")

  file(GLOB children "${tmp}/*")
  list(LENGTH children n)
  if(n EQUAL 1 AND IS_DIRECTORY "${children}")
    file(RENAME "${children}" "${dest}")
  else()
    file(RENAME "${tmp}" "${dest}")
  endif()
  file(REMOVE_RECURSE "${tmp}")

  message(STATUS "${name}: bundled into ${dest}")
endfunction()

file(MAKE_DIRECTORY "${DEPS_DIR}")
bundle_dep(json    "${JSON_URL}"    "${JSON_HASH}")
bundle_dep(mbedtls "${MBEDTLS_URL}" "${MBEDTLS_HASH}")
