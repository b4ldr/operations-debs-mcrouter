/**
 * Autogenerated by Thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#pragma once

#include <thrift/lib/cpp2/Thrift.h>
#include <thrift/lib/cpp2/protocol/Protocol.h>
#include <thrift/lib/cpp/TApplicationException.h>
#include <folly/io/IOBuf.h>
#include <folly/io/Cursor.h>
#include <boost/operators.hpp>




namespace cpp2 {

class Banal;
class Fiery;

class Banal : private boost::totally_ordered<Banal>, public apache::thrift::TException {
 public:

  Banal() {}
  // FragileConstructor for use in initialization lists only

  Banal(apache::thrift::FragileConstructor) {}

  Banal(Banal&&) = default;

  Banal(const Banal&) = default;

  Banal& operator=(Banal&&) = default;

  Banal& operator=(const Banal&) = default;

  virtual ~Banal() throw() {}

  bool operator==(const Banal& /* rhs */) const;

  bool operator < (const Banal& rhs) const {
    return false;
  }

  template <class Protocol_>
  uint32_t read(Protocol_* iprot);
  template <class Protocol_>
  uint32_t serializedSize(Protocol_* prot_) const;
  template <class Protocol_>
  uint32_t serializedSizeZC(Protocol_* prot_) const;
  template <class Protocol_>
  uint32_t write(Protocol_* prot_) const;

  virtual const char* what() const throw() {
    return " ::cpp2::Banal";
  }
};

void swap(Banal& a, Banal& b);

} // cpp2
namespace apache { namespace thrift {

template <> inline constexpr apache::thrift::protocol::TType Cpp2Ops< ::cpp2::Banal>::thriftType() {
  return apache::thrift::protocol::T_STRUCT;
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::cpp2::Banal>::write(Protocol* proto, const  ::cpp2::Banal* obj) {
  return obj->write(proto);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::cpp2::Banal>::read(Protocol* proto,   ::cpp2::Banal* obj) {
  return obj->read(proto);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::cpp2::Banal>::serializedSize(Protocol* proto, const  ::cpp2::Banal* obj) {
  return obj->serializedSize(proto);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::cpp2::Banal>::serializedSizeZC(Protocol* proto, const  ::cpp2::Banal* obj) {
  return obj->serializedSizeZC(proto);
}

}} // apache::thrift
namespace cpp2 {

class Fiery : private boost::totally_ordered<Fiery>, public apache::thrift::TException {
 public:

  Fiery() {}
  // FragileConstructor for use in initialization lists only

  Fiery(apache::thrift::FragileConstructor, std::string message__arg) :
      message(std::move(message__arg)) {}
  template <typename T__ThriftWrappedArgument__Ctor, typename... Args__ThriftWrappedArgument__Ctor>
  Fiery(::apache::thrift::detail::argument_wrapper<1, T__ThriftWrappedArgument__Ctor> arg, Args__ThriftWrappedArgument__Ctor&&... args):
    Fiery(std::forward<Args__ThriftWrappedArgument__Ctor>(args)...)
  {
    message = arg.move();
  }

  Fiery(Fiery&&) = default;

  Fiery(const Fiery&) = default;

  Fiery& operator=(Fiery&&) = default;

  Fiery& operator=(const Fiery&) = default;
  void __clear();

  virtual ~Fiery() throw() {}

  std::string message;
  bool operator==(const Fiery& rhs) const;

  bool operator < (const Fiery& rhs) const {
    if (!(message == rhs.message)) {
      return message < rhs.message;
    }
    return false;
  }

  const std::string& get_message() const& {
    return message;
  }

  std::string get_message() && {
    return std::move(message);
  }

  template <typename T_Fiery_message_struct_setter>
  std::string& set_message(T_Fiery_message_struct_setter&& message_) {
    message = std::forward<T_Fiery_message_struct_setter>(message_);
    return message;
  }

  template <class Protocol_>
  uint32_t read(Protocol_* iprot);
  template <class Protocol_>
  uint32_t serializedSize(Protocol_* prot_) const;
  template <class Protocol_>
  uint32_t serializedSizeZC(Protocol_* prot_) const;
  template <class Protocol_>
  uint32_t write(Protocol_* prot_) const;

  virtual const char* what() const throw() {
    return " ::cpp2::Fiery";
  }
};

void swap(Fiery& a, Fiery& b);

} // cpp2
namespace apache { namespace thrift {

template <> inline void Cpp2Ops< ::cpp2::Fiery>::clear( ::cpp2::Fiery* obj) {
  return obj->__clear();
}

template <> inline constexpr apache::thrift::protocol::TType Cpp2Ops< ::cpp2::Fiery>::thriftType() {
  return apache::thrift::protocol::T_STRUCT;
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::cpp2::Fiery>::write(Protocol* proto, const  ::cpp2::Fiery* obj) {
  return obj->write(proto);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::cpp2::Fiery>::read(Protocol* proto,   ::cpp2::Fiery* obj) {
  return obj->read(proto);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::cpp2::Fiery>::serializedSize(Protocol* proto, const  ::cpp2::Fiery* obj) {
  return obj->serializedSize(proto);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::cpp2::Fiery>::serializedSizeZC(Protocol* proto, const  ::cpp2::Fiery* obj) {
  return obj->serializedSizeZC(proto);
}

}} // apache::thrift
namespace cpp2 {

} // cpp2