/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "McrouterLogFailure.h"

#include "mcrouter/options.h"

namespace facebook {
namespace memcache {
namespace mcrouter {

std::string routerName(const McrouterOptions& opts) {
  return "libmcrouter." + opts.service_name + "." + opts.router_name;
}
}
}
} // facebook::memcache::mcrouter
