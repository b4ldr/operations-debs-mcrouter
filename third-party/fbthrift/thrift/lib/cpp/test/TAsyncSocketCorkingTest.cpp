/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vector>

#include <folly/portability/GTest.h>
#include <pcap.h>

#include <folly/Conv.h>
#include <folly/io/IOBuf.h>
#include <folly/io/async/AsyncServerSocket.h>
#include <folly/io/async/AsyncSocket.h>
#include <folly/io/async/AsyncSocketException.h>
#include <folly/io/async/EventBase.h>
#include <folly/lang/Bits.h>
#include <folly/net/NetworkSocket.h>
#include <thrift/lib/cpp/async/TAsyncSSLSocket.h>
#include <thrift/lib/cpp/async/TAsyncSocket.h>

using apache::thrift::async::TAsyncSocket;
using apache::thrift::async::TAsyncSSLSocket;
using apache::thrift::async::WriteFlags;
using apache::thrift::transport::TTransportException;
using folly::AsyncServerSocket;
using folly::EventBase;
using folly::IOBuf;
using folly::SocketAddress;
using folly::SSLContext;
using std::shared_ptr;
using std::string;
using std::unique_ptr;
using std::vector;

class AcceptCallback : public AsyncServerSocket::AcceptCallback {
 public:
  explicit AcceptCallback(const std::function<void(int)>& fn) : fn_(fn) {}

  void connectionAccepted(
      folly::NetworkSocket fdNetworkSocket,
      const folly::SocketAddress&) noexcept override {
    int fd = fdNetworkSocket.toFd();

    fn_(fd);
  }
  void acceptError(const std::exception& ex) noexcept override {
    LOG(FATAL) << "acceptError(): " << ex.what();
  }

 private:
  std::function<void(int)> fn_;
};

class ConnectCallback : public folly::AsyncSocket::ConnectCallback {
 public:
  explicit ConnectCallback(const std::function<void()>& fn) : fn_(fn) {}

  void connectSuccess() noexcept override {
    fn_();
  }
  void connectErr(const folly::AsyncSocketException& ex) noexcept override {
    LOG(FATAL) << "connectErr(): " << ex.what();
  }

 private:
  std::function<void()> fn_;
};

class HandshakeCallback : public TAsyncSSLSocket::HandshakeCallback {
 public:
  explicit HandshakeCallback(const std::function<void()>& fn) : fn_(fn) {}

  void handshakeSuccess(TAsyncSSLSocket*) noexcept override {
    fn_();
  }
  void handshakeError(
      TAsyncSSLSocket*,
      const TTransportException& ex) noexcept override {
    LOG(FATAL) << "handshakeError(): " << ex.what();
  }

 private:
  std::function<void()> fn_;
};

void createTCPSocketPair(
    EventBase* eventBase,
    shared_ptr<TAsyncSocket>* client,
    shared_ptr<TAsyncSocket>* server) {
  AsyncServerSocket::UniquePtr acceptSocket(new AsyncServerSocket(eventBase));

  AcceptCallback acceptCallback([&](int fd) {
    VLOG(4) << "socket accepted";

    // Destroy the accept socket to stop waiting on new connections,
    // so that the event loop will terminate
    acceptSocket.reset();

    *server =
        TAsyncSocket::newSocket(eventBase, folly::NetworkSocket::fromFd(fd));
  });

  acceptSocket->addAcceptCallback(&acceptCallback, nullptr);
  folly::SocketAddress serverAddr("127.0.0.1", 0);
  acceptSocket->bind(serverAddr);
  acceptSocket->listen(10);
  acceptSocket->getAddress(&serverAddr);
  acceptSocket->startAccepting();

  *client = TAsyncSocket::newSocket(eventBase);
  ConnectCallback clientConnectCallback(
      [&] { VLOG(4) << "client connect done"; });
  (*client)->connect(&clientConnectCallback, serverAddr);

  eventBase->loop();
}

void createSSLSocketPair(
    EventBase* eventBase,
    shared_ptr<TAsyncSSLSocket>* client,
    shared_ptr<TAsyncSSLSocket>* server) {
  AsyncServerSocket::UniquePtr acceptSocket(new AsyncServerSocket(eventBase));

  shared_ptr<SSLContext> ctx(new SSLContext);
  ctx->loadCertificate("thrift/lib/cpp/test/ssl/tests-cert.pem");
  ctx->loadPrivateKey("thrift/lib/cpp/test/ssl/tests-key.pem");
  ctx->ciphers("ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

  HandshakeCallback serverHandshakeCallback(
      [&] { VLOG(4) << "server handshake done"; });

  AcceptCallback acceptCallback([&](int fd) {
    VLOG(4) << "socket accepted";

    // Destroy the accept socket to stop waiting on new connections,
    // so that the event loop will terminate
    acceptSocket.reset();

    *server = TAsyncSSLSocket::newSocket(
        ctx, eventBase, folly::NetworkSocket::fromFd(fd));
    (*server)->sslAccept(
        &serverHandshakeCallback, std::chrono::milliseconds(5));
  });

  acceptSocket->addAcceptCallback(&acceptCallback, nullptr);
  folly::SocketAddress serverAddr("127.0.0.1", 0);
  acceptSocket->bind(serverAddr);
  acceptSocket->listen(10);
  acceptSocket->getAddress(&serverAddr);
  acceptSocket->startAccepting();

  *client = TAsyncSSLSocket::newSocket(ctx, eventBase);
  ConnectCallback clientConnectCallback(
      [&] { VLOG(4) << "client connect done"; });
  (*client)->connect(&clientConnectCallback, serverAddr);

  eventBase->loop();
}

struct __attribute__((__packed__)) EthernetHeader {
  uint8_t dst[6];
  uint8_t src[6];
  uint16_t type;
};

struct __attribute__((__packed__)) IPv4Header {
  uint8_t versionAndHeader;
  uint8_t dscp;
  uint16_t totalLen;
  uint16_t identification;
  uint16_t flagsAndFramentOffset;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t cksum;
  uint32_t src;
  uint32_t dst;
};

struct __attribute__((__packed__)) TCPHeader {
  uint16_t srcPort;
  uint16_t dstPort;
  uint32_t seq;
  uint32_t ack;
  uint8_t offset;
  uint8_t flags;
  uint16_t windowSize;
  uint16_t cksum;
  uint16_t urg;
};

class Packet {
 public:
  Packet(const struct pcap_pkthdr* hdr, const unsigned char* bytes) {
    CHECK_EQ(hdr->caplen, hdr->len);
    dataLength_ = hdr->caplen;
    data_.reset(new uint8_t[hdr->caplen]);
    memcpy(data_.get(), bytes, hdr->caplen);
    parse();
  }

  const EthernetHeader* ether() const {
    return ether_;
  }
  const IPv4Header* ip() const {
    return ip_;
  }
  const TCPHeader* tcp() const {
    return tcp_;
  }
  const folly::SocketAddress& src() const {
    return srcAddr_;
  }
  const folly::SocketAddress& dst() const {
    return dstAddr_;
  }
  const uint8_t* payload() const {
    return payload_;
  }
  uint32_t payloadLength() const {
    return payloadLength_;
  }

 private:
  void parse() {
    ether_ = reinterpret_cast<EthernetHeader*>(data_.get());
    uint16_t ethertype = folly::Endian::big(ether_->type);
    VLOG(4) << "  ethertype: " << ethertype;
    static const uint16_t kTypeIP = 2048;
    if (ethertype != kTypeIP) {
      return;
    }

    ip_ = reinterpret_cast<IPv4Header*>(data_.get() + sizeof(EthernetHeader));
    int ipVersion = (ip_->versionAndHeader & 0xf0) >> 4;
    VLOG(4) << "  IP version: " << ipVersion;
    if (ipVersion != 4) {
      ip_ = nullptr;
      return;
    }
    size_t ipHeaderLen = 4 * (ip_->versionAndHeader & 0x0f);
    VLOG(4) << "  IP header length: " << ipHeaderLen;
    VLOG(4) << "  Protocol: " << (int)ip_->protocol;
    if (ip_->protocol != IPPROTO_TCP) {
      return;
    }

    uint8_t* tcpStart = data_.get() + sizeof(EthernetHeader) + ipHeaderLen;
    tcp_ = reinterpret_cast<TCPHeader*>(tcpStart);

    struct sockaddr_in rawAddr;
    rawAddr.sin_family = AF_INET;

    rawAddr.sin_addr.s_addr = ip_->src;
    rawAddr.sin_port = tcp_->srcPort;
    srcAddr_.setFromSockaddr(&rawAddr);

    rawAddr.sin_addr.s_addr = ip_->dst;
    rawAddr.sin_port = tcp_->dstPort;
    dstAddr_.setFromSockaddr(&rawAddr);

    VLOG(4) << "  Src: " << srcAddr_;
    VLOG(4) << "  Dst: " << dstAddr_;

    size_t tcpHeaderLen = 4 * (tcp_->offset >> 4);
    payload_ = tcpStart + tcpHeaderLen;
    const uint8_t* bufEnd = data_.get() + dataLength_;
    payloadLength_ = bufEnd - payload_;
  }

  std::unique_ptr<uint8_t[]> data_;
  uint32_t dataLength_ = 0;
  EthernetHeader* ether_ = nullptr;
  IPv4Header* ip_ = nullptr;
  TCPHeader* tcp_ = nullptr;
  folly::SocketAddress srcAddr_;
  folly::SocketAddress dstAddr_;
  uint8_t* payload_ = nullptr;
  uint32_t payloadLength_ = 0;
};

class Capturer {
 public:
  explicit Capturer(const std::string& filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_ = pcap_open_live("lo", 65535, 0, -1, errbuf);
    // Note that this unit test needs to be run as root.
    // Otherwise you won't be able to initialize packet capturing, and the
    // following check will fail.
    CHECK(pcap_ != nullptr)
        << "unable to initialize packet capturing: " << errbuf;

    struct bpf_program program;
    int rc = pcap_compile(pcap_, &program, filter.c_str(), 1, 0xffffffff);
    CHECK_EQ(rc, 0) << "failed to compile pcap filter: " << errbuf;
    rc = pcap_setfilter(pcap_, &program);
    CHECK_EQ(rc, 0) << "failed to set pcap filter: " << errbuf;
    rc = pcap_setnonblock(pcap_, 1, errbuf);
    CHECK_EQ(rc, 0) << "failed to set pcap nonblocking mode: " << errbuf;
  }

  ~Capturer() {
    pcap_close(pcap_);
  }

  vector<Packet> capture(int max = 1024) {
    vector<Packet> packets;
    int rc = pcap_dispatch(
        pcap_, max, pcapCallback, reinterpret_cast<unsigned char*>(&packets));
    CHECK_GE(rc, 0);
    return packets;
  }

 private:
  static void pcapCallback(
      unsigned char* arg,
      const struct pcap_pkthdr* hdr,
      const unsigned char* bytes) {
    vector<Packet>* packets = reinterpret_cast<vector<Packet>*>(arg);
    packets->emplace_back(hdr, bytes);
  }

  pcap_t* pcap_;
};

void ensureNPackets(
    const shared_ptr<TAsyncSocket>& sender,
    const shared_ptr<TAsyncSocket>& /* receiver */,
    size_t expectedNumPackets,
    const std::function<void()>& fn) {
  folly::SocketAddress senderAddr;
  folly::SocketAddress receiverAddr;
  sender->getLocalAddress(&senderAddr);
  sender->getPeerAddress(&receiverAddr);

  string captureFilter = folly::to<string>(
      "src port ",
      senderAddr.getPort(),
      " and dst port ",
      receiverAddr.getPort());
  Capturer cap(captureFilter);

  // Call the function
  fn();

  auto packets = cap.capture();
  EXPECT_EQ(expectedNumPackets, packets.size());
}

void testWriteFlushing(
    EventBase* eventBase,
    const shared_ptr<TAsyncSocket>& client,
    const shared_ptr<TAsyncSocket>& server) {
  char buf[] = "foobar";
  const int bufsize = 6;

  const int iovCount = 3;
  iovec iov[iovCount];
  iov[0].iov_base = const_cast<char*>("test1234");
  iov[0].iov_len = 8;
  iov[1].iov_base = const_cast<char*>("some more data");
  iov[1].iov_len = 14;
  iov[2].iov_base = const_cast<char*>("last bit");
  iov[2].iov_len = 8;

  // Two small writes should trigger two packets, since we use TCP_NODELAY
  ensureNPackets(client, server, 2, [&] {
    client->write(nullptr, buf, bufsize);
    client->write(nullptr, buf, bufsize);
    eventBase->loop();
  });

  // A writev() of several small buffers should go out in one packet
  ensureNPackets(client, server, 1, [&] {
    client->writev(nullptr, iov, iovCount);
    eventBase->loop();
  });

  // Calling write() with cork=true shouldn't trigger its own packet
  ensureNPackets(client, server, 2, [&] {
    client->write(nullptr, buf, bufsize, WriteFlags::CORK);
    client->write(nullptr, buf, bufsize);
    client->write(nullptr, buf, bufsize, WriteFlags::CORK);
    client->writev(nullptr, iov, iovCount, WriteFlags::CORK);
    client->write(nullptr, buf, bufsize, WriteFlags::CORK);
    client->write(nullptr, buf, bufsize);
    eventBase->loop();
  });

  // Test the behavior of IOBuf chains
  // We perform several corked writes, with 3 uncorked writes
  ensureNPackets(client, server, 3, [&] {
    auto buf1 = IOBuf::copyBuffer(buf, bufsize);
    auto buf2 = IOBuf::copyBuffer(iov[0].iov_base, iov[1].iov_len);
    buf2->appendChain(buf1->clone());

    buf2 = buf1->clone();
    auto buf3 = buf1->clone();
    buf3->appendChain(buf2->clone());

    client->writeChain(nullptr, buf3->clone(), WriteFlags::CORK);
    client->writeChain(nullptr, buf1->clone());
    client->writeChain(nullptr, buf2->clone(), WriteFlags::CORK);
    client->writeChain(nullptr, buf3->clone(), WriteFlags::CORK);
    client->writeChain(nullptr, buf3->clone());
    client->writeChain(nullptr, buf1->clone());
    eventBase->loop();
  });
}

TEST(WriteFlushTest, TAsyncSocket) {
  EventBase eventBase;

  shared_ptr<TAsyncSocket> client;
  shared_ptr<TAsyncSocket> server;
  createTCPSocketPair(&eventBase, &client, &server);

  testWriteFlushing(&eventBase, client, server);
}

TEST(WriteFlushTest, TAsyncSSLSocket) {
  EventBase eventBase;

  shared_ptr<TAsyncSSLSocket> client;
  shared_ptr<TAsyncSSLSocket> server;
  createSSLSocketPair(&eventBase, &client, &server);

  testWriteFlushing(&eventBase, client, server);
}
