# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(specsMain)
  add_osquery_library(specs_tables INTERFACE)

  generateNativeTables()
  list(APPEND table_target_list "${generateNativeTables_output}")

  foreach(table_target ${table_target_list})
    target_link_libraries("${table_target}" PUBLIC osquery_tables_tableimplementations)
    enableLinkWholeArchive("${table_target}")
  endforeach()

  target_link_libraries(specs_tables INTERFACE ${table_target_list})

  generateCopyFileTarget("specs_table_files" "" "REGEX" "*.table" "${TEST_CONFIGS_DIR}/specs")
endfunction()

function(generateNativeTables)
  set(platform_independent_spec_files
    processes.table
    utility/osquery_events.table
    utility/osquery_extensions.table
    utility/osquery_flags.table
    utility/osquery_info.table
    utility/osquery_packs.table
    utility/osquery_registry.table
    utility/osquery_schedule.table
    utility/time.table
  )

  list(APPEND spec_file_list ${platform_independent_spec_files})

  generateTableCategoryAmalgamation("native" ${spec_file_list})
  set(generateNativeTables_output "${generateTableCategoryAmalgamation_output}" PARENT_SCOPE)
endfunction()

specsMain()
