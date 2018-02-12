/*
 *  Copyright (c) 2017, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

/*
 *  THIS FILE IS AUTOGENERATED. DO NOT MODIFY IT; ALL CHANGES WILL BE LOST IN
 *  VAIN.
 *
 */
#pragma once

#include <functional>
#include <unordered_map>

#include <folly/Range.h>

#include <mcrouter/lib/carbon/Stats.h>

#include "mcrouter/lib/carbon/test/gen/CarbonTestRouteHandleIf.h"
#include "mcrouter/lib/carbon/test/gen/CarbonTestRouterStats.h"

// Forward declarations
namespace folly {
struct dynamic;
} // folly

namespace facebook {
namespace memcache {
template <class RouteHandleIf>
class RouteHandleFactory;
namespace mcrouter {
template <class RouterInfo>
class ExtraRouteHandleProviderIf;
} // mcrouter
} // memcache
} // facebook

namespace carbon {
namespace test {

namespace detail {

using CarbonTestRoutableRequests = carbon::List<
    AnotherRequest,
    TestRequest,
    TestRequestStringKey,
    test2::util::YetAnotherRequest>;

} // detail

struct CarbonTestRouterInfo {
  using RouteHandleIf = CarbonTestRouteHandleIf;
  using RouteHandlePtr = std::shared_ptr<RouteHandleIf>;

  static constexpr const char* name = "CarbonTest";

  template <class Route>
  using RouteHandle = CarbonTestRouteHandle<Route>;
  using RoutableRequests = detail::CarbonTestRoutableRequests;

  using RouterStats = carbon::Stats<CarbonTestRouterStatsConfig>;

  using RouteHandleFactoryMap = std::unordered_map<
      folly::StringPiece,
      std::function<RouteHandlePtr(
          facebook::memcache::RouteHandleFactory<RouteHandleIf>&,
          const folly::dynamic&)>,
      folly::Hash>;

  static RouteHandleFactoryMap buildRouteMap();

  static std::unique_ptr<facebook::memcache::mcrouter::
                             ExtraRouteHandleProviderIf<CarbonTestRouterInfo>>
  buildExtraProvider();
};

} // test
} // carbon