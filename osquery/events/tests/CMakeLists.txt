# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryEventsTestsMain)
  generateOsqueryEventsTestsTest()
  generateOsqueryEventsTestsEventsdatabasetestsTest()
endfunction()

function(generateOsqueryEventsTestsTest)
  add_osquery_executable(osquery_events_tests-test events_tests.cpp)

  target_link_libraries(osquery_events_tests-test PRIVATE
    osquery_cxx_settings
    osquery_config_tests_testutils
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_utils
    osquery_utils_conversions
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generateOsqueryEventsTestsEventsdatabasetestsTest)
  add_osquery_executable(osquery_events_tests_eventsdatabasetests-test
    mockedosquerydatabase.cpp
    eventsubscriberplugin.cpp
  )

  target_link_libraries(osquery_events_tests_eventsdatabasetests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_filesystem
    osquery_utils
    osquery_utils_conversions
    specs_tables
    thirdparty_googletest
  )
endfunction()

osqueryEventsTestsMain()
