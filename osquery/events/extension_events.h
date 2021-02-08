/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/events.h>
#include <osquery/utils/mutex.h>

namespace osquery {

/**
 * @brief Extension event publisher define this context for extension event
 * subscriber to use.
 */
struct ExtensionEventSubscriptionContext : public SubscriptionContext {
 private:
  friend class ExtensionEventPublisher;
};

/**
 * @brief Extension event subscriber Callback method will receive this context.
 */
struct ExtensionEventContext : public EventContext {
  std::vector<std::map<std::string, std::string>> events;
};

/**
 * @brief Extension events are streamed to this publisher. It holds the events
 * until subscriber retrieves it.
 */
class ExtensionEventPublisher
    : public EventPublisher<ExtensionEventSubscriptionContext,
                            ExtensionEventContext> {
 public:
  ExtensionEventPublisher() : EventPublisher() {}

  const std::string type() const override final {
    return type_;
  }

  void setType(const std::string& type) {
    type_ = type;
  }

  Status setUp() override;

  Status run() override;

  /// Used by the extension to add the streamed events
  Status add(const std::vector<std::map<std::string, std::string>>& batch);

 private:
  std::string type_;

  Mutex mutex_;
  std::vector<std::map<std::string, std::string>> events_;
};

/**
 * @brief Extension events subscriber that gathers events from publisher
 * and provides them for table generation.
 */
class ExtensionEventSubscriber final
    : public EventSubscriber<ExtensionEventPublisher> {
 public:
  Status init() override;

  Status Callback(const ECRef& ec, const SCRef& sc);

  void setType(const std::string& type) {
    type_ = type;
  }

  const std::string& getType() const override {
    return type_;
  };

 private:
  std::string type_;
};

} // namespace osquery
