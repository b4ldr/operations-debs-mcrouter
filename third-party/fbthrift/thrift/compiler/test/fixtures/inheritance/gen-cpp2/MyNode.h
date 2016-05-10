/**
 * Autogenerated by Thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#pragma once

#include <thrift/lib/cpp2/ServiceIncludes.h>
#include <thrift/lib/cpp2/async/HeaderChannel.h>
#include <thrift/lib/cpp/TApplicationException.h>
#include <thrift/lib/cpp2/async/FutureRequest.h>
#include <folly/futures/Future.h>
#include "thrift/compiler/test/fixtures/inheritance/gen-cpp2/module_types.h"


#include "thrift/compiler/test/fixtures/inheritance/gen-cpp2/MyRoot.h"

namespace folly {
  class IOBuf;
  class IOBufQueue;
}
namespace apache { namespace thrift {
  class Cpp2RequestContext;
  class BinaryProtocolReader;
  class CompactProtocolReader;
  namespace transport { class THeader; }
}}

namespace cpp2 {

class MyNodeSvAsyncIf {
 public:
  virtual ~MyNodeSvAsyncIf() {}
  virtual void async_tm_do_mid(std::unique_ptr<apache::thrift::HandlerCallback<void>> callback) = 0;
  virtual void async_do_mid(std::unique_ptr<apache::thrift::HandlerCallback<void>> callback) = delete;
  virtual folly::Future<folly::Unit> future_do_mid() = 0;
};

class MyNodeAsyncProcessor;

class MyNodeSvIf : public MyNodeSvAsyncIf, virtual public  ::cpp2::MyRootSvIf {
 public:
  typedef MyNodeAsyncProcessor ProcessorType;

  virtual ~MyNodeSvIf() {}
  virtual std::unique_ptr<apache::thrift::AsyncProcessor> getProcessor();
  virtual void do_mid();
  folly::Future<folly::Unit> future_do_mid();
  virtual void async_tm_do_mid(std::unique_ptr<apache::thrift::HandlerCallback<void>> callback);
};

class MyNodeSvNull : public MyNodeSvIf, virtual public  ::cpp2::MyRootSvIf {
 public:
  virtual ~MyNodeSvNull() {}
  virtual void do_mid();
};

class MyNodeAsyncProcessor : public  ::cpp2::MyRootAsyncProcessor {
 public:
  virtual const char* getServiceName();
  using BaseAsyncProcessor =  ::cpp2::MyRootAsyncProcessor;
 protected:
  MyNodeSvIf* iface_;
  virtual folly::Optional<std::string> getCacheKey(folly::IOBuf* buf, apache::thrift::protocol::PROTOCOL_TYPES protType);
 public:
  virtual void process(std::unique_ptr<apache::thrift::ResponseChannel::Request> req, std::unique_ptr<folly::IOBuf> buf, apache::thrift::protocol::PROTOCOL_TYPES protType, apache::thrift::Cpp2RequestContext* context, folly::EventBase* eb, apache::thrift::concurrency::ThreadManager* tm);
 protected:
  virtual bool isOnewayMethod(const folly::IOBuf* buf, const apache::thrift::transport::THeader* header);
 private:
  static std::unordered_set<std::string> onewayMethods_;
  static std::unordered_map<std::string, int16_t> cacheKeyMap_;
 public:
  using BinaryProtocolProcessFunc = ProcessFunc<MyNodeAsyncProcessor, apache::thrift::BinaryProtocolReader>;
  using BinaryProtocolProcessMap = ProcessMap<BinaryProtocolProcessFunc>;
  static const MyNodeAsyncProcessor::BinaryProtocolProcessMap& getBinaryProtocolProcessMap();
 private:
  static MyNodeAsyncProcessor::BinaryProtocolProcessMap binaryProcessMap_;
 public:
  using CompactProtocolProcessFunc = ProcessFunc<MyNodeAsyncProcessor, apache::thrift::CompactProtocolReader>;
  using CompactProtocolProcessMap = ProcessMap<CompactProtocolProcessFunc>;
  static const MyNodeAsyncProcessor::CompactProtocolProcessMap& getCompactProtocolProcessMap();
 private:
  static MyNodeAsyncProcessor::CompactProtocolProcessMap compactProcessMap_;
 private:
  template <typename ProtocolIn_, typename ProtocolOut_>
  void _processInThread_do_mid(std::unique_ptr<apache::thrift::ResponseChannel::Request> req, std::unique_ptr<folly::IOBuf> buf, std::unique_ptr<ProtocolIn_> iprot, apache::thrift::Cpp2RequestContext* ctx, folly::EventBase* eb, apache::thrift::concurrency::ThreadManager* tm);
  template <typename ProtocolIn_, typename ProtocolOut_>
  void process_do_mid(std::unique_ptr<apache::thrift::ResponseChannel::Request> req, std::unique_ptr<folly::IOBuf> buf, std::unique_ptr<ProtocolIn_> iprot,apache::thrift::Cpp2RequestContext* ctx,folly::EventBase* eb, apache::thrift::concurrency::ThreadManager* tm);
  template <class ProtocolIn_, class ProtocolOut_>
  static folly::IOBufQueue return_do_mid(int32_t protoSeqId, apache::thrift::ContextStack* ctx);
  template <class ProtocolIn_, class ProtocolOut_>
  static void throw_do_mid(std::unique_ptr<apache::thrift::ResponseChannel::Request> req,int32_t protoSeqId,apache::thrift::ContextStack* ctx,std::exception_ptr ep,apache::thrift::Cpp2RequestContext* reqCtx);
  template <class ProtocolIn_, class ProtocolOut_>
  static void throw_wrapped_do_mid(std::unique_ptr<apache::thrift::ResponseChannel::Request> req,int32_t protoSeqId,apache::thrift::ContextStack* ctx,folly::exception_wrapper ew,apache::thrift::Cpp2RequestContext* reqCtx);
 public:
  MyNodeAsyncProcessor(MyNodeSvIf* iface) :
       ::cpp2::MyRootAsyncProcessor(iface),
      iface_(iface) {}

  virtual ~MyNodeAsyncProcessor() {}
};

class MyNodeAsyncClient : public  ::cpp2::MyRootAsyncClient {
 public:
  virtual const char* getServiceName();
  typedef std::unique_ptr<apache::thrift::RequestChannel, folly::DelayedDestruction::Destructor> channel_ptr;

  virtual ~MyNodeAsyncClient() {}

  MyNodeAsyncClient(std::shared_ptr<apache::thrift::RequestChannel> channel) :
       ::cpp2::MyRootAsyncClient(channel) {}
  virtual void do_mid(std::unique_ptr<apache::thrift::RequestCallback> callback);
  virtual void do_mid(apache::thrift::RpcOptions& rpcOptions, std::unique_ptr<apache::thrift::RequestCallback> callback);
  virtual void sync_do_mid();
  virtual void sync_do_mid(apache::thrift::RpcOptions& rpcOptions);
  virtual folly::Future<folly::Unit> future_do_mid();
  virtual folly::Future<folly::Unit> future_do_mid(apache::thrift::RpcOptions& rpcOptions);
  virtual folly::Future<std::pair<folly::Unit, std::unique_ptr<apache::thrift::transport::THeader>>> header_future_do_mid(apache::thrift::RpcOptions& rpcOptions);
  virtual void do_mid(std::function<void (::apache::thrift::ClientReceiveState&&)> callback);
  static folly::exception_wrapper recv_wrapped_do_mid(::apache::thrift::ClientReceiveState& state);
  static void recv_do_mid(::apache::thrift::ClientReceiveState& state);
  // Mock friendly virtual instance method
  virtual void recv_instance_do_mid(::apache::thrift::ClientReceiveState& state);
  virtual folly::exception_wrapper recv_instance_wrapped_do_mid(::apache::thrift::ClientReceiveState& state);
  template <typename Protocol_>
  void do_midT(Protocol_* prot, apache::thrift::RpcOptions& rpcOptions, std::unique_ptr<apache::thrift::RequestCallback> callback);
  template <typename Protocol_>
  static folly::exception_wrapper recv_wrapped_do_midT(Protocol_* prot, ::apache::thrift::ClientReceiveState& state);
  template <typename Protocol_>
  static void recv_do_midT(Protocol_* prot, ::apache::thrift::ClientReceiveState& state);
};

} // cpp2
namespace apache { namespace thrift {

}} // apache::thrift