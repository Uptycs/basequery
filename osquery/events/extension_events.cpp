/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/events/extension_events.h>

namespace osquery {

DECLARE_bool(disable_events);

Status ExtensionEventSubscriber::init() {
  if (FLAGS_disable_events) {
    return Status(1, "Extension events disabled via configuration");
  }

  auto sc = createSubscriptionContext();
  subscribe(&ExtensionEventSubscriber::Callback, sc);

  return Status::success();
}

Status ExtensionEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  if (ec->events.size() > 0) {
    addBatch(ec->events);
  }

  return Status::success();
}

Status ExtensionEventPublisher::setUp() {
  if (FLAGS_disable_events) {
    return Status(1, "Extension events disabled via configuration");
  }

  return Status::success();
}

Status ExtensionEventPublisher::run() {
  if (!FLAGS_disable_events) {
    WriteLock lock(mutex_);
    if (events_.size() > 0) {
      auto ec = createEventContext();
      ec->events.insert(ec->events.end(), events_.begin(), events_.end());
      fire(ec);

      events_.clear();
    }
  }

  return Status::success();
}

Status ExtensionEventPublisher::add(
    const std::vector<std::map<std::string, std::string>>& batch) {
  if (!FLAGS_disable_events) {
    WriteLock lock(mutex_);
    events_.insert(events_.end(), batch.begin(), batch.end());
  }

  return Status::success();
}
} // namespace osquery
