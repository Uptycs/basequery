# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(pluginsConfigParsersMain)
  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generatePluginsConfigParsers()
endfunction()

function(generatePluginsConfigParsers)
  add_osquery_library(plugins_config_parsers EXCLUDE_FROM_ALL
    decorators.cpp
    events_parser.cpp
    feature_vectors.cpp
    file_paths.cpp
    kafka_topics.cpp
    logger.cpp
    options.cpp
    prometheus_targets.cpp
    views.cpp
  )

  enableLinkWholeArchive(plugins_config_parsers)

  target_link_libraries(plugins_config_parsers PUBLIC
    osquery_cxx_settings
    osquery_config
    osquery_core
    osquery_database
    osquery_filesystem
    osquery_logger_datalogger
    osquery_registry
    osquery_sql
    osquery_utils
    osquery_utils_json
  )

  set(public_header_files
    decorators.h
    feature_vectors.h
    kafka_topics.h
    logger.h
    prometheus_targets.h
  )

  generateIncludeNamespace(plugins_config_parsers "plugins/config/parsers" "FILE_ONLY" ${public_header_files})

  add_test(NAME plugins_config_parsers_tests_decoratorstests-test COMMAND plugins_config_parsers_tests_decoratorstests-test)
  add_test(NAME plugins_config_parsers_tests_eventsparsertests-test COMMAND plugins_config_parsers_tests_eventsparsertests-test)
  add_test(NAME plugins_config_parsers_tests_filepathstests-test COMMAND plugins_config_parsers_tests_filepathstests-test)
  add_test(NAME plugins_config_parsers_tests_optionstests-test COMMAND plugins_config_parsers_tests_optionstests-test)
  add_test(NAME plugins_config_parsers_tests_viewstests-test COMMAND plugins_config_parsers_tests_viewstests-test)

  set_tests_properties(
    plugins_config_parsers_tests_decoratorstests-test
    plugins_config_parsers_tests_eventsparsertests-test
    plugins_config_parsers_tests_filepathstests-test
    plugins_config_parsers_tests_optionstests-test
    plugins_config_parsers_tests_viewstests-test
    PROPERTIES ENVIRONMENT "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
  )
endfunction()

pluginsConfigParsersMain()
