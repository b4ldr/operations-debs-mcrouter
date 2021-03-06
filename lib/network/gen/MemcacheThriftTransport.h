/*
 *  Copyright (c) 2017-present, Facebook, Inc.
 *
 *  This source code is licensed under the MIT license found in the LICENSE
 *  file in the root directory of this source tree.
 *
 */

/*
 *  THIS FILE IS AUTOGENERATED. DO NOT MODIFY IT; ALL CHANGES WILL BE LOST IN
 *  VAIN.
 *
 *  @generated
 */
#pragma once

#include <exception>
#include <memory>

#include <mcrouter/lib/network/RpcStatsContext.h>
#include <mcrouter/lib/network/ThriftTransport.h>
#include <thrift/lib/cpp/TApplicationException.h>
#include <thrift/lib/cpp/transport/TTransportException.h>
#include <thrift/lib/cpp2/async/RequestChannel.h>

#include "mcrouter/lib/network/gen/gen-cpp2/MemcacheAsyncClient.h"

namespace facebook {
namespace memcache {

template <>
class ThriftTransport<MemcacheRouterInfo> : public ThriftTransportBase {
 public:
  ThriftTransport(folly::EventBase& eventBase, ConnectionOptions options)
      : ThriftTransportBase(eventBase, std::move(options)) {}
  ThriftTransport(folly::VirtualEventBase& eventBase, ConnectionOptions options)
      : ThriftTransportBase(eventBase.getEventBase(), std::move(options)) {}
  ~ThriftTransport() override final {
    resetClient();
  }

  void setFlushList(FlushList* flushList) override final {
    flushList_ = flushList;
    if (thriftClient_) {
      auto* channel = static_cast<apache::thrift::RocketClientChannel*>(
          thriftClient_->getChannel());
      channel->setFlushList(flushList_);
    }
  }

  McAddReply sendSync(
      const McAddRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McAddReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcAdd(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McAppendReply sendSync(
      const McAppendRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McAppendReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcAppend(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McCasReply sendSync(
      const McCasRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McCasReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcCas(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McDecrReply sendSync(
      const McDecrRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McDecrReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcDecr(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McDeleteReply sendSync(
      const McDeleteRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McDeleteReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcDelete(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McFlushAllReply sendSync(
      const McFlushAllRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McFlushAllReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcFlushAll(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McFlushReReply sendSync(
      const McFlushReRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McFlushReReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcFlushRe(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McGatReply sendSync(
      const McGatRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McGatReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcGat(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McGatsReply sendSync(
      const McGatsRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McGatsReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcGats(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McGetReply sendSync(
      const McGetRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McGetReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcGet(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McGetsReply sendSync(
      const McGetsRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McGetsReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcGets(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McIncrReply sendSync(
      const McIncrRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McIncrReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcIncr(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McLeaseGetReply sendSync(
      const McLeaseGetRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McLeaseGetReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcLeaseGet(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McLeaseSetReply sendSync(
      const McLeaseSetRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McLeaseSetReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcLeaseSet(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McMetagetReply sendSync(
      const McMetagetRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McMetagetReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcMetaget(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McPrependReply sendSync(
      const McPrependRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McPrependReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcPrepend(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McReplaceReply sendSync(
      const McReplaceRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McReplaceReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcReplace(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McSetReply sendSync(
      const McSetRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McSetReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcSet(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McTouchReply sendSync(
      const McTouchRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McTouchReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcTouch(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

  McVersionReply sendSync(
      const McVersionRequest& request,
      std::chrono::milliseconds timeout,
      RpcStatsContext* /* rpcContext */ = nullptr) {
    return sendSyncImpl([this, &request, timeout] {
      folly::Try<apache::thrift::RpcResponseComplete<McVersionReply>> reply;
      if (auto* thriftClient = getThriftClient()) {
        auto rpcOptions = getRpcOptions(timeout);
        reply = thriftClient->sync_complete_mcVersion(
            rpcOptions, request);
      } else {
        reply.emplaceException(
            folly::make_exception_wrapper<apache::thrift::transport::TTransportException>(
              apache::thrift::transport::TTransportException::NOT_OPEN,
              "Error creating thrift client."));
      }
      return reply;
    });
  }

 private:
  std::unique_ptr<thrift::MemcacheAsyncClient> thriftClient_;
  FlushList* flushList_{nullptr};

  thrift::MemcacheAsyncClient* getThriftClient() {
    if (!thriftClient_) {
      thriftClient_ = createThriftClient<thrift::MemcacheAsyncClient>();
      if (flushList_) {
        auto* channel = static_cast<apache::thrift::RocketClientChannel*>(
            thriftClient_->getChannel());
        channel->setFlushList(flushList_);
      }
    }
    return thriftClient_.get();
  }

  void resetClient() override final {
    if (thriftClient_) {
      if (auto channel = thriftClient_->getChannel()) {
        // Reset the callback to avoid the following cycle:
        //  ~ThriftAsyncClient() -> ~RocketClientChannel() ->
        //  channelClosed() -> ~ThriftAsyncClient()
        channel->setCloseCallback(nullptr);
      }
      thriftClient_.reset();
    }
  }
};

} // namespace memcache
} // namespace facebook