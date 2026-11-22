# sdk/cmake/openbsd-darwin.cmake -- CMake cross-compilation toolchain for
# OpenBSD arm64 guest ports on Darwin (`translate/darwin` & `emulate/darwin`);
# releases come from config/versions/index.tsv.

set(CMAKE_SYSTEM_NAME OpenBSD)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

get_filename_component(_OBSD_SDK_DIR "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
get_filename_component(_OBSD_REPO_DIR "${_OBSD_SDK_DIR}/.." ABSOLUTE)

if(DEFINED ENV{OPENBSD_VERSION} AND NOT "$ENV{OPENBSD_VERSION}" STREQUAL "")
  set(CMAKE_SYSTEM_VERSION "$ENV{OPENBSD_VERSION}")
else()
  file(STRINGS "${_OBSD_REPO_DIR}/config/versions/index.tsv" _OBSD_REL_ROWS REGEX "^[0-9]+\\.[0-9]+\tverified\t")
  set(_OBSD_RELS "")
  foreach(_row IN LISTS _OBSD_REL_ROWS)
    string(REGEX MATCH "^[0-9]+\\.[0-9]+" _rel "${_row}")
    list(APPEND _OBSD_RELS "${_rel}")
  endforeach()
  if(NOT _OBSD_RELS)
    message(FATAL_ERROR "openbsd-darwin.cmake: no verified releases in ${_OBSD_REPO_DIR}/config/versions/index.tsv")
  endif()
  list(SORT _OBSD_RELS COMPARE NATURAL)
  list(GET _OBSD_RELS -1 CMAKE_SYSTEM_VERSION)
endif()

if(DEFINED ENV{COMPAT_BACKEND} AND NOT "$ENV{COMPAT_BACKEND}" STREQUAL "")
  set(_OBSD_BACKEND "$ENV{COMPAT_BACKEND}")
else()
  set(_OBSD_BACKEND "translate")
endif()

if(DEFINED ENV{COMPAT_SDK} AND NOT "$ENV{COMPAT_SDK}" STREQUAL "")
  set(_OBSD_SDK "$ENV{COMPAT_SDK}")
elseif(_OBSD_BACKEND STREQUAL "translate")
  set(_OBSD_SDK "macosx")
else()
  set(_OBSD_SDK "iphonesimulator")
endif()

if(DEFINED ENV{OBSD_STAGE_DIR} AND NOT "$ENV{OBSD_STAGE_DIR}" STREQUAL "")
  set(_OBSD_STAGE_DIR "$ENV{OBSD_STAGE_DIR}")
else()
  set(_OBSD_STAGE_DIR "${_OBSD_REPO_DIR}/build/openbsd/${CMAKE_SYSTEM_VERSION}/${_OBSD_BACKEND}/darwin-${_OBSD_SDK}/stage")
endif()

set(CMAKE_C_COMPILER "${_OBSD_SDK_DIR}/bin/obsd-cc")
set(CMAKE_CXX_COMPILER "${_OBSD_SDK_DIR}/bin/obsd-c++")
set(CMAKE_AR "${_OBSD_SDK_DIR}/bin/obsd-ar" CACHE FILEPATH "OpenBSD Darwin ar")
set(CMAKE_RANLIB "${_OBSD_SDK_DIR}/bin/obsd-ranlib" CACHE FILEPATH "OpenBSD Darwin ranlib")
set(CMAKE_LINKER "${_OBSD_SDK_DIR}/bin/obsd-ld" CACHE FILEPATH "OpenBSD Darwin ld")
set(CMAKE_NM "${_OBSD_SDK_DIR}/bin/obsd-nm" CACHE FILEPATH "OpenBSD Darwin nm")
set(CMAKE_STRIP "${_OBSD_SDK_DIR}/bin/obsd-strip" CACHE FILEPATH "OpenBSD Darwin strip")
set(PKG_CONFIG_EXECUTABLE "${_OBSD_SDK_DIR}/bin/obsd-pkg-config" CACHE FILEPATH "OpenBSD Darwin pkg-config")

set(CMAKE_FIND_ROOT_PATH "${_OBSD_STAGE_DIR}/usr/local" "${_OBSD_STAGE_DIR}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static libraries for OpenBSD Darwin guest" FORCE)
set(CMAKE_POSITION_INDEPENDENT_CODE ON CACHE BOOL "Enable PIC for Mach-O arm64 objects" FORCE)
set(CMAKE_SKIP_RPATH ON CACHE BOOL "Disable host RPATH relinking for OpenBSD guest objects" FORCE)
