/**
 * Autogenerated by Thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#pragma once

#include "thrift/compiler/test/fixtures/fatal/gen-cpp2/module_types.h"
#include <thrift/lib/cpp2/protocol/Protocol.h>
namespace test_cpp2 { namespace cpp_reflection {

struct module_constants {
  static constexpr int32_t const constant1_ = 1357;

  static constexpr int32_t constant1() {
    return constant1_;
  }
  // consider using folly::StringPiece instead of std::string whenever possible
  // to referencing this statically allocated string constant, in order to
  // prevent unnecessary allocations

  static constexpr char const * const constant2_ = "hello";

  static constexpr char const * constant2() {
    return constant2_;
  }

  static constexpr  ::test_cpp2::cpp_reflection::enum1 const constant3_ =  ::test_cpp2::cpp_reflection::enum1::field0;

  static constexpr  ::test_cpp2::cpp_reflection::enum1 constant3() {
    return constant3_;
  }
};

class __attribute__((__deprecated__("moduleConstants suffers from the 'static initialization order fiasco' (https://isocpp.org/wiki/faq/ctors#static-init-order) and may CRASH you program. Instead, use module_constants::CONSTANT_NAME()"))) moduleConstants {
 public:
  moduleConstants() :
      constant1(1357),
      constant2(apache::thrift::StringTraits< std::string>::fromStringLiteral("hello")),
      constant3( ::test_cpp2::cpp_reflection::enum1::field0) {}

  int32_t constant1;

  std::string constant2;

   ::test_cpp2::cpp_reflection::enum1 constant3;
};

}} // test_cpp2::cpp_reflection