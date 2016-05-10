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

#include "thrift/compiler/test/fixtures/fatal-compat/gen-cpp/module_types.h"



namespace test_cpp2 { namespace cpp_reflection {

typedef  ::test_cpp1::cpp_reflection::enum1 enum1;
typedef  ::test_cpp1::cpp_reflection::enum2 enum2;
typedef  ::test_cpp1::cpp_reflection::enum3 enum3;
typedef ::test_cpp1::cpp_reflection::union1 union1;
template <class Protocol_>
uint32_t union1_read(Protocol_* iprot, union1* obj);
template <class Protocol_>
uint32_t union1_serializedSize(Protocol_* prot_, const union1* obj);
template <class Protocol_>
uint32_t union1_serializedSizeZC(Protocol_* prot_, const union1* obj);
template <class Protocol_>
uint32_t union1_write(Protocol_* prot_, const union1* obj);

}} // test_cpp2::cpp_reflection
namespace apache { namespace thrift {

template <> inline void Cpp2Ops< ::test_cpp2::cpp_reflection::union1>::clear( ::test_cpp2::cpp_reflection::union1* obj) {
  return obj->__clear();
}

template <> inline constexpr apache::thrift::protocol::TType Cpp2Ops< ::test_cpp2::cpp_reflection::union1>::thriftType() {
  return apache::thrift::protocol::T_STRUCT;
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::union1>::write(Protocol* proto, const  ::test_cpp2::cpp_reflection::union1* obj) {
  return  ::test_cpp2::cpp_reflection::union1_write(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::union1>::read(Protocol* proto,   ::test_cpp2::cpp_reflection::union1* obj) {
  return  ::test_cpp2::cpp_reflection::union1_read(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::union1>::serializedSize(Protocol* proto, const  ::test_cpp2::cpp_reflection::union1* obj) {
  return  ::test_cpp2::cpp_reflection::union1_serializedSize(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::union1>::serializedSizeZC(Protocol* proto, const  ::test_cpp2::cpp_reflection::union1* obj) {
  return  ::test_cpp2::cpp_reflection::union1_serializedSizeZC(proto, obj);
}

}} // apache::thrift
namespace test_cpp2 { namespace cpp_reflection {

typedef ::test_cpp1::cpp_reflection::union2 union2;
template <class Protocol_>
uint32_t union2_read(Protocol_* iprot, union2* obj);
template <class Protocol_>
uint32_t union2_serializedSize(Protocol_* prot_, const union2* obj);
template <class Protocol_>
uint32_t union2_serializedSizeZC(Protocol_* prot_, const union2* obj);
template <class Protocol_>
uint32_t union2_write(Protocol_* prot_, const union2* obj);

}} // test_cpp2::cpp_reflection
namespace apache { namespace thrift {

template <> inline void Cpp2Ops< ::test_cpp2::cpp_reflection::union2>::clear( ::test_cpp2::cpp_reflection::union2* obj) {
  return obj->__clear();
}

template <> inline constexpr apache::thrift::protocol::TType Cpp2Ops< ::test_cpp2::cpp_reflection::union2>::thriftType() {
  return apache::thrift::protocol::T_STRUCT;
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::union2>::write(Protocol* proto, const  ::test_cpp2::cpp_reflection::union2* obj) {
  return  ::test_cpp2::cpp_reflection::union2_write(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::union2>::read(Protocol* proto,   ::test_cpp2::cpp_reflection::union2* obj) {
  return  ::test_cpp2::cpp_reflection::union2_read(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::union2>::serializedSize(Protocol* proto, const  ::test_cpp2::cpp_reflection::union2* obj) {
  return  ::test_cpp2::cpp_reflection::union2_serializedSize(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::union2>::serializedSizeZC(Protocol* proto, const  ::test_cpp2::cpp_reflection::union2* obj) {
  return  ::test_cpp2::cpp_reflection::union2_serializedSizeZC(proto, obj);
}

}} // apache::thrift
namespace test_cpp2 { namespace cpp_reflection {

typedef ::test_cpp1::cpp_reflection::union3 union3;
template <class Protocol_>
uint32_t union3_read(Protocol_* iprot, union3* obj);
template <class Protocol_>
uint32_t union3_serializedSize(Protocol_* prot_, const union3* obj);
template <class Protocol_>
uint32_t union3_serializedSizeZC(Protocol_* prot_, const union3* obj);
template <class Protocol_>
uint32_t union3_write(Protocol_* prot_, const union3* obj);

}} // test_cpp2::cpp_reflection
namespace apache { namespace thrift {

template <> inline void Cpp2Ops< ::test_cpp2::cpp_reflection::union3>::clear( ::test_cpp2::cpp_reflection::union3* obj) {
  return obj->__clear();
}

template <> inline constexpr apache::thrift::protocol::TType Cpp2Ops< ::test_cpp2::cpp_reflection::union3>::thriftType() {
  return apache::thrift::protocol::T_STRUCT;
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::union3>::write(Protocol* proto, const  ::test_cpp2::cpp_reflection::union3* obj) {
  return  ::test_cpp2::cpp_reflection::union3_write(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::union3>::read(Protocol* proto,   ::test_cpp2::cpp_reflection::union3* obj) {
  return  ::test_cpp2::cpp_reflection::union3_read(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::union3>::serializedSize(Protocol* proto, const  ::test_cpp2::cpp_reflection::union3* obj) {
  return  ::test_cpp2::cpp_reflection::union3_serializedSize(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::union3>::serializedSizeZC(Protocol* proto, const  ::test_cpp2::cpp_reflection::union3* obj) {
  return  ::test_cpp2::cpp_reflection::union3_serializedSizeZC(proto, obj);
}

}} // apache::thrift
namespace test_cpp2 { namespace cpp_reflection {

typedef ::test_cpp1::cpp_reflection::structA structA;
template <class Protocol_>
uint32_t structA_read(Protocol_* iprot, structA* obj);
template <class Protocol_>
uint32_t structA_serializedSize(Protocol_* prot_, const structA* obj);
template <class Protocol_>
uint32_t structA_serializedSizeZC(Protocol_* prot_, const structA* obj);
template <class Protocol_>
uint32_t structA_write(Protocol_* prot_, const structA* obj);

}} // test_cpp2::cpp_reflection
namespace apache { namespace thrift {

template <> inline void Cpp2Ops< ::test_cpp2::cpp_reflection::structA>::clear( ::test_cpp2::cpp_reflection::structA* obj) {
  return obj->__clear();
}

template <> inline constexpr apache::thrift::protocol::TType Cpp2Ops< ::test_cpp2::cpp_reflection::structA>::thriftType() {
  return apache::thrift::protocol::T_STRUCT;
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::structA>::write(Protocol* proto, const  ::test_cpp2::cpp_reflection::structA* obj) {
  return  ::test_cpp2::cpp_reflection::structA_write(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::structA>::read(Protocol* proto,   ::test_cpp2::cpp_reflection::structA* obj) {
  return  ::test_cpp2::cpp_reflection::structA_read(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::structA>::serializedSize(Protocol* proto, const  ::test_cpp2::cpp_reflection::structA* obj) {
  return  ::test_cpp2::cpp_reflection::structA_serializedSize(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::structA>::serializedSizeZC(Protocol* proto, const  ::test_cpp2::cpp_reflection::structA* obj) {
  return  ::test_cpp2::cpp_reflection::structA_serializedSizeZC(proto, obj);
}

}} // apache::thrift
namespace test_cpp2 { namespace cpp_reflection {

typedef ::test_cpp1::cpp_reflection::unionA unionA;
template <class Protocol_>
uint32_t unionA_read(Protocol_* iprot, unionA* obj);
template <class Protocol_>
uint32_t unionA_serializedSize(Protocol_* prot_, const unionA* obj);
template <class Protocol_>
uint32_t unionA_serializedSizeZC(Protocol_* prot_, const unionA* obj);
template <class Protocol_>
uint32_t unionA_write(Protocol_* prot_, const unionA* obj);

}} // test_cpp2::cpp_reflection
namespace apache { namespace thrift {

template <> inline void Cpp2Ops< ::test_cpp2::cpp_reflection::unionA>::clear( ::test_cpp2::cpp_reflection::unionA* obj) {
  return obj->__clear();
}

template <> inline constexpr apache::thrift::protocol::TType Cpp2Ops< ::test_cpp2::cpp_reflection::unionA>::thriftType() {
  return apache::thrift::protocol::T_STRUCT;
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::unionA>::write(Protocol* proto, const  ::test_cpp2::cpp_reflection::unionA* obj) {
  return  ::test_cpp2::cpp_reflection::unionA_write(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::unionA>::read(Protocol* proto,   ::test_cpp2::cpp_reflection::unionA* obj) {
  return  ::test_cpp2::cpp_reflection::unionA_read(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::unionA>::serializedSize(Protocol* proto, const  ::test_cpp2::cpp_reflection::unionA* obj) {
  return  ::test_cpp2::cpp_reflection::unionA_serializedSize(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::unionA>::serializedSizeZC(Protocol* proto, const  ::test_cpp2::cpp_reflection::unionA* obj) {
  return  ::test_cpp2::cpp_reflection::unionA_serializedSizeZC(proto, obj);
}

}} // apache::thrift
namespace test_cpp2 { namespace cpp_reflection {

typedef ::test_cpp1::cpp_reflection::structB structB;
template <class Protocol_>
uint32_t structB_read(Protocol_* iprot, structB* obj);
template <class Protocol_>
uint32_t structB_serializedSize(Protocol_* prot_, const structB* obj);
template <class Protocol_>
uint32_t structB_serializedSizeZC(Protocol_* prot_, const structB* obj);
template <class Protocol_>
uint32_t structB_write(Protocol_* prot_, const structB* obj);

}} // test_cpp2::cpp_reflection
namespace apache { namespace thrift {

template <> inline void Cpp2Ops< ::test_cpp2::cpp_reflection::structB>::clear( ::test_cpp2::cpp_reflection::structB* obj) {
  return obj->__clear();
}

template <> inline constexpr apache::thrift::protocol::TType Cpp2Ops< ::test_cpp2::cpp_reflection::structB>::thriftType() {
  return apache::thrift::protocol::T_STRUCT;
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::structB>::write(Protocol* proto, const  ::test_cpp2::cpp_reflection::structB* obj) {
  return  ::test_cpp2::cpp_reflection::structB_write(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::structB>::read(Protocol* proto,   ::test_cpp2::cpp_reflection::structB* obj) {
  return  ::test_cpp2::cpp_reflection::structB_read(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::structB>::serializedSize(Protocol* proto, const  ::test_cpp2::cpp_reflection::structB* obj) {
  return  ::test_cpp2::cpp_reflection::structB_serializedSize(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::structB>::serializedSizeZC(Protocol* proto, const  ::test_cpp2::cpp_reflection::structB* obj) {
  return  ::test_cpp2::cpp_reflection::structB_serializedSizeZC(proto, obj);
}

}} // apache::thrift
namespace test_cpp2 { namespace cpp_reflection {

typedef ::test_cpp1::cpp_reflection::structC structC;
template <class Protocol_>
uint32_t structC_read(Protocol_* iprot, structC* obj);
template <class Protocol_>
uint32_t structC_serializedSize(Protocol_* prot_, const structC* obj);
template <class Protocol_>
uint32_t structC_serializedSizeZC(Protocol_* prot_, const structC* obj);
template <class Protocol_>
uint32_t structC_write(Protocol_* prot_, const structC* obj);

}} // test_cpp2::cpp_reflection
namespace apache { namespace thrift {

template <> inline void Cpp2Ops< ::test_cpp2::cpp_reflection::structC>::clear( ::test_cpp2::cpp_reflection::structC* obj) {
  return obj->__clear();
}

template <> inline constexpr apache::thrift::protocol::TType Cpp2Ops< ::test_cpp2::cpp_reflection::structC>::thriftType() {
  return apache::thrift::protocol::T_STRUCT;
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::structC>::write(Protocol* proto, const  ::test_cpp2::cpp_reflection::structC* obj) {
  return  ::test_cpp2::cpp_reflection::structC_write(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::structC>::read(Protocol* proto,   ::test_cpp2::cpp_reflection::structC* obj) {
  return  ::test_cpp2::cpp_reflection::structC_read(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::structC>::serializedSize(Protocol* proto, const  ::test_cpp2::cpp_reflection::structC* obj) {
  return  ::test_cpp2::cpp_reflection::structC_serializedSize(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::structC>::serializedSizeZC(Protocol* proto, const  ::test_cpp2::cpp_reflection::structC* obj) {
  return  ::test_cpp2::cpp_reflection::structC_serializedSizeZC(proto, obj);
}

}} // apache::thrift
namespace test_cpp2 { namespace cpp_reflection {

typedef ::test_cpp1::cpp_reflection::struct1 struct1;
template <class Protocol_>
uint32_t struct1_read(Protocol_* iprot, struct1* obj);
template <class Protocol_>
uint32_t struct1_serializedSize(Protocol_* prot_, const struct1* obj);
template <class Protocol_>
uint32_t struct1_serializedSizeZC(Protocol_* prot_, const struct1* obj);
template <class Protocol_>
uint32_t struct1_write(Protocol_* prot_, const struct1* obj);

}} // test_cpp2::cpp_reflection
namespace apache { namespace thrift {

template <> inline void Cpp2Ops< ::test_cpp2::cpp_reflection::struct1>::clear( ::test_cpp2::cpp_reflection::struct1* obj) {
  return obj->__clear();
}

template <> inline constexpr apache::thrift::protocol::TType Cpp2Ops< ::test_cpp2::cpp_reflection::struct1>::thriftType() {
  return apache::thrift::protocol::T_STRUCT;
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::struct1>::write(Protocol* proto, const  ::test_cpp2::cpp_reflection::struct1* obj) {
  return  ::test_cpp2::cpp_reflection::struct1_write(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::struct1>::read(Protocol* proto,   ::test_cpp2::cpp_reflection::struct1* obj) {
  return  ::test_cpp2::cpp_reflection::struct1_read(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::struct1>::serializedSize(Protocol* proto, const  ::test_cpp2::cpp_reflection::struct1* obj) {
  return  ::test_cpp2::cpp_reflection::struct1_serializedSize(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::struct1>::serializedSizeZC(Protocol* proto, const  ::test_cpp2::cpp_reflection::struct1* obj) {
  return  ::test_cpp2::cpp_reflection::struct1_serializedSizeZC(proto, obj);
}

}} // apache::thrift
namespace test_cpp2 { namespace cpp_reflection {

typedef ::test_cpp1::cpp_reflection::struct2 struct2;
template <class Protocol_>
uint32_t struct2_read(Protocol_* iprot, struct2* obj);
template <class Protocol_>
uint32_t struct2_serializedSize(Protocol_* prot_, const struct2* obj);
template <class Protocol_>
uint32_t struct2_serializedSizeZC(Protocol_* prot_, const struct2* obj);
template <class Protocol_>
uint32_t struct2_write(Protocol_* prot_, const struct2* obj);

}} // test_cpp2::cpp_reflection
namespace apache { namespace thrift {

template <> inline void Cpp2Ops< ::test_cpp2::cpp_reflection::struct2>::clear( ::test_cpp2::cpp_reflection::struct2* obj) {
  return obj->__clear();
}

template <> inline constexpr apache::thrift::protocol::TType Cpp2Ops< ::test_cpp2::cpp_reflection::struct2>::thriftType() {
  return apache::thrift::protocol::T_STRUCT;
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::struct2>::write(Protocol* proto, const  ::test_cpp2::cpp_reflection::struct2* obj) {
  return  ::test_cpp2::cpp_reflection::struct2_write(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::struct2>::read(Protocol* proto,   ::test_cpp2::cpp_reflection::struct2* obj) {
  return  ::test_cpp2::cpp_reflection::struct2_read(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::struct2>::serializedSize(Protocol* proto, const  ::test_cpp2::cpp_reflection::struct2* obj) {
  return  ::test_cpp2::cpp_reflection::struct2_serializedSize(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::struct2>::serializedSizeZC(Protocol* proto, const  ::test_cpp2::cpp_reflection::struct2* obj) {
  return  ::test_cpp2::cpp_reflection::struct2_serializedSizeZC(proto, obj);
}

}} // apache::thrift
namespace test_cpp2 { namespace cpp_reflection {

typedef ::test_cpp1::cpp_reflection::struct3 struct3;
template <class Protocol_>
uint32_t struct3_read(Protocol_* iprot, struct3* obj);
template <class Protocol_>
uint32_t struct3_serializedSize(Protocol_* prot_, const struct3* obj);
template <class Protocol_>
uint32_t struct3_serializedSizeZC(Protocol_* prot_, const struct3* obj);
template <class Protocol_>
uint32_t struct3_write(Protocol_* prot_, const struct3* obj);

}} // test_cpp2::cpp_reflection
namespace apache { namespace thrift {

template <> inline void Cpp2Ops< ::test_cpp2::cpp_reflection::struct3>::clear( ::test_cpp2::cpp_reflection::struct3* obj) {
  return obj->__clear();
}

template <> inline constexpr apache::thrift::protocol::TType Cpp2Ops< ::test_cpp2::cpp_reflection::struct3>::thriftType() {
  return apache::thrift::protocol::T_STRUCT;
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::struct3>::write(Protocol* proto, const  ::test_cpp2::cpp_reflection::struct3* obj) {
  return  ::test_cpp2::cpp_reflection::struct3_write(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::struct3>::read(Protocol* proto,   ::test_cpp2::cpp_reflection::struct3* obj) {
  return  ::test_cpp2::cpp_reflection::struct3_read(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::struct3>::serializedSize(Protocol* proto, const  ::test_cpp2::cpp_reflection::struct3* obj) {
  return  ::test_cpp2::cpp_reflection::struct3_serializedSize(proto, obj);
}

template <> template <class Protocol> inline uint32_t Cpp2Ops< ::test_cpp2::cpp_reflection::struct3>::serializedSizeZC(Protocol* proto, const  ::test_cpp2::cpp_reflection::struct3* obj) {
  return  ::test_cpp2::cpp_reflection::struct3_serializedSizeZC(proto, obj);
}

}} // apache::thrift
namespace test_cpp2 { namespace cpp_reflection {

}} // test_cpp2::cpp_reflection