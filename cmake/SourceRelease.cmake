# Produce an offline source-release tarball.
# Usage: cmake -P cmake/SourceRelease.cmake
# Produces: aas-sign-VERSION.tar.gz in the project root.
#
# The tarball is `git archive` output plus the bundled dependency
# trees under deps/.  A consumer can untar, `cmake -B build`, and
# build with no network access.

cmake_minimum_required(VERSION 3.25)

set(SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/..")

find_program(GIT git REQUIRED)

# Version selection, in order of precedence:
#   1. $AAS_SIGN_RELEASE_VERSION env var, when set.  Used by the
#      release workflow to pass GITHUB_REF_NAME directly so we
#      don't need git's tag metadata in the runner's checkout
#      (actions/checkout@v5 + fetch-tags + tag triggers + shallow
#      clone collide on refspecs).
#   2. `git describe --tags --abbrev=8 --always` against the
#      working tree.  Picks up vX.Y.Z tags as plain "X.Y.Z" and
#      post-tag commits as "X.Y.Z-N-gSHA".
#   3. UTC date stamp, as a last-resort fallback for trees with no
#      tags at all.
if(DEFINED ENV{AAS_SIGN_RELEASE_VERSION} AND NOT "$ENV{AAS_SIGN_RELEASE_VERSION}" STREQUAL "")
  set(VERSION "$ENV{AAS_SIGN_RELEASE_VERSION}")
else()
  execute_process(
    COMMAND "${GIT}" describe --tags --abbrev=8 --always
    WORKING_DIRECTORY "${SOURCE_DIR}"
    OUTPUT_VARIABLE VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE rc
  )
  if(rc OR NOT VERSION)
    string(TIMESTAMP VERSION "%Y%m%d" UTC)
  endif()
endif()
string(REGEX REPLACE "^v" "" VERSION "${VERSION}")

set(NAME   "aas-sign-${VERSION}")
set(WORK   "${SOURCE_DIR}/_source_release")
set(STAGE  "${WORK}/${NAME}")
set(OUTPUT "${SOURCE_DIR}/${NAME}.tar.gz")

message(STATUS "Preparing source release: ${NAME}")

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}")

# Stage a pristine copy of HEAD via `git archive`.
message(STATUS "Exporting git tree...")
execute_process(
  COMMAND "${GIT}" archive --format=tar --prefix=${NAME}/ HEAD
  WORKING_DIRECTORY "${SOURCE_DIR}"
  OUTPUT_FILE "${WORK}/src.tar"
  RESULT_VARIABLE rc
)
if(rc)
  message(FATAL_ERROR "git archive failed")
endif()

execute_process(
  COMMAND ${CMAKE_COMMAND} -E tar xf src.tar
  WORKING_DIRECTORY "${WORK}"
  RESULT_VARIABLE rc
)
file(REMOVE "${WORK}/src.tar")
if(rc)
  message(FATAL_ERROR "Failed to extract git archive")
endif()

# Materialise deps/ into the staging tree.
message(STATUS "Bundling dependencies...")
set(DEPS_DIR "${STAGE}/deps")
include("${CMAKE_CURRENT_LIST_DIR}/BundleDeps.cmake")

message(STATUS "Creating ${NAME}.tar.gz...")
execute_process(
  COMMAND ${CMAKE_COMMAND} -E tar czf "${OUTPUT}" "${NAME}"
  WORKING_DIRECTORY "${WORK}"
  RESULT_VARIABLE rc
)
if(rc)
  message(FATAL_ERROR "Failed to create tarball")
endif()

file(REMOVE_RECURSE "${WORK}")

file(SIZE "${OUTPUT}" size)
math(EXPR size_kb "${size} / 1024")
message(STATUS "Source release: ${OUTPUT} (${size_kb} KiB)")
