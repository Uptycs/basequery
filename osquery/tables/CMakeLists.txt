# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryTablesMain)
  add_subdirectory("system")
  add_subdirectory("utility")

  generateOsqueryTablesTableimplementations()
endfunction()

function(generateOsqueryTablesTableimplementations)
  add_osquery_library(osquery_tables_tableimplementations INTERFACE)

  target_link_libraries(osquery_tables_tableimplementations INTERFACE
    osquery_tables_system_systemtable
    osquery_tables_utility_utilitytable
  )
endfunction()

osqueryTablesMain()
