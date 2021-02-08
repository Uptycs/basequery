# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(testsIntegrationTablesMain)
  generateTestsIntegrationTablesIntegrationtestshelper()
  generateTestsIntegrationTablesTestsTest()

endfunction()

function(generateTestsIntegrationTablesIntegrationtestshelper)
  add_osquery_library(tests_integration_tables_integrationtestshelper EXCLUDE_FROM_ALL helper.cpp)

  set(public_headers
    helper.h
  )

  generateIncludeNamespace(tests_integration_tables_integrationtestshelper "osquery/tests/integration/tables" "FILE_ONLY" ${public_headers})

  target_link_libraries(tests_integration_tables_integrationtestshelper PUBLIC
    osquery_cxx_settings
    osquery_database
    osquery_sql
    osquery_utils
    thirdparty_boost
    thirdparty_googletest_headers
  )
endfunction()

function(generateTestsIntegrationTablesTestsTest)
  set(source_files
    osquery_events.cpp
    osquery_extensions.cpp
    osquery_flags.cpp
    osquery_info.cpp
    osquery_packs.cpp
    osquery_registry.cpp
    osquery_schedule.cpp
    processes.cpp
    time.cpp
  )

  add_osquery_executable(tests_integration_tables-test ${source_files})

  target_link_libraries(tests_integration_tables-test PRIVATE
    osquery_cxx_settings
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_remote_enroll_tlsenroll
    osquery_utils_conversions
    osquery_utils_info
    plugins_config_tlsconfig
    specs_tables
    tests_integration_tables_integrationtestshelper
    thirdparty_googletest
  )

  add_test(NAME tests_integration_tables-test COMMAND tests_integration_tables-test)

endfunction()

testsIntegrationTablesMain()
