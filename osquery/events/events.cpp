/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/events/eventfactory.h>
#include <osquery/events/events.h>
#include <osquery/events/extension_events.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry.h>
#include <osquery/utils/conversions/split.h>

#include <boost/algorithm/string.hpp>

namespace osquery {

FLAG(string,
     extension_event_tables,
     "",
     "Comma-separated list of event tables implemented in extensions");

void attachEvents() {
  // Start pub/sub for external event tables
  auto pubs_registry = RegistryFactory::get().registry("event_publisher");
  auto subs_registry = RegistryFactory::get().registry("event_subscriber");
  for (const auto& table : split(FLAGS_extension_event_tables, ",")) {
    auto pub = std::make_shared<ExtensionEventPublisher>();
    pub->setType(table);
    pubs_registry->add(table, pub, false);

    auto sub = std::make_shared<ExtensionEventSubscriber>();
    sub->setType(table);
    subs_registry->add(table, sub, false);
  }

  const auto& publishers = RegistryFactory::get().plugins("event_publisher");
  for (const auto& publisher : publishers) {
    EventFactory::registerEventPublisher(publisher.second);
  }

  const auto& subscribers = RegistryFactory::get().plugins("event_subscriber");
  for (const auto& subscriber : subscribers) {
    if (!boost::ends_with(subscriber.first, "_events")) {
      LOG(ERROR) << "Error registering subscriber: " << subscriber.first
                 << ": Must use a '_events' suffix";
      continue;
    }

    auto status = EventFactory::registerEventSubscriber(subscriber.second);
    if (!status.ok()) {
      VLOG(1) << "Skipping subscriber: " << subscriber.first << ": "
              << status.getMessage();
    }
  }

  // Configure the event publishers and subscribers.
  EventFactory::configUpdate();
}

} // namespace osquery
