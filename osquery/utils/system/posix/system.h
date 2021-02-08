/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <sys/types.h>
#include <unistd.h>

namespace osquery {

/// The osquery platform agnostic process identifier type.
using PlatformPidType = pid_t;

} // namespace osquery
