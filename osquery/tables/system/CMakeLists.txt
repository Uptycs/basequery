# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryTablesSystemMain)
  generateOsqueryTablesSystemSystemtable()
endfunction()

function(generateOsqueryTablesSystemSystemtable)
  if(DEFINED PLATFORM_LINUX)
    set(source_files
      linux/processes.cpp
    )

  elseif(DEFINED PLATFORM_MACOS)
    set(source_files
      darwin/processes.cpp
    )

  elseif(DEFINED PLATFORM_FREEBSD)
    set(source_files
      freebsd/processes.cpp
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    set(source_files
      windows/processes.cpp
    )
  endif()

  add_osquery_library(osquery_tables_system_systemtable EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_tables_system_systemtable PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_filesystem
    osquery_hashing
    osquery_logger
    osquery_process
    osquery_utils
    osquery_utils_conversions
    osquery_utils_expected
    osquery_utils_system_env
    osquery_utils_system_filepath
    osquery_utils_system_time
    osquery_utils_system_uptime
    osquery_worker_ipc_platformtablecontaineripc
    thirdparty_boost
    osquery_rows_processes_header
  )
endfunction()

osqueryTablesSystemMain()
