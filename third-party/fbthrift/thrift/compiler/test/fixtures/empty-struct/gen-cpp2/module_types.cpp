/**
 * Autogenerated by Thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#include "thrift/compiler/test/fixtures/empty-struct/gen-cpp2/module_types.h"

#include "thrift/compiler/test/fixtures/empty-struct/gen-cpp2/module_types.tcc"

#include <algorithm>

namespace cpp2 {

template uint32_t Empty::read<apache::thrift::BinaryProtocolReader>(apache::thrift::BinaryProtocolReader*);
template uint32_t Empty::write<apache::thrift::BinaryProtocolWriter>(apache::thrift::BinaryProtocolWriter*) const;
template uint32_t Empty::serializedSize<apache::thrift::BinaryProtocolWriter>(apache::thrift::BinaryProtocolWriter*) const;
template uint32_t Empty::serializedSizeZC<apache::thrift::BinaryProtocolWriter>(apache::thrift::BinaryProtocolWriter*) const;
template uint32_t Empty::read<apache::thrift::CompactProtocolReader>(apache::thrift::CompactProtocolReader*);
template uint32_t Empty::write<apache::thrift::CompactProtocolWriter>(apache::thrift::CompactProtocolWriter*) const;
template uint32_t Empty::serializedSize<apache::thrift::CompactProtocolWriter>(apache::thrift::CompactProtocolWriter*) const;
template uint32_t Empty::serializedSizeZC<apache::thrift::CompactProtocolWriter>(apache::thrift::CompactProtocolWriter*) const;

bool Empty::operator==(const Empty& /* rhs */) const {
  return true;
}

void swap(Empty& a, Empty& b) {
  using ::std::swap;
}

} // cpp2
namespace apache { namespace thrift {

}} // apache::thrift
namespace cpp2 {

} // cpp2