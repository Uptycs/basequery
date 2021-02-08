# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryEventsMain)
  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryEventsEventsregistry()
endfunction()

function(generateOsqueryEventsEventsregistry)
  add_osquery_library(osquery_events_eventsregistry EXCLUDE_FROM_ALL
    subscription.cpp
    eventer.cpp
    eventpublisherplugin.cpp
    events.cpp
    eventfactory.cpp
    eventsubscriberplugin.cpp
    extension_events.cpp
  )

  target_link_libraries(osquery_events_eventsregistry PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_config
    osquery_dispatcher
    osquery_sql
  )

  set(public_header_files
    eventer.h
    eventfactory.h
    eventpublisher.h
    eventpublisherplugin.h
    events.h
    eventsubscriber.h
    eventsubscriberplugin.h
    extension_events.h
    pathset.h
    subscription.h
    types.h
  )

  generateIncludeNamespace(osquery_events_eventsregistry "osquery/events" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_events_tests-test COMMAND osquery_events_tests-test)
endfunction()

osqueryEventsMain()
