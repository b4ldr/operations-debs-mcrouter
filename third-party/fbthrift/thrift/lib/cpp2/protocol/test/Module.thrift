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

namespace cpp2 apache.thrift.test
cpp_include "folly/container/F14Map.h"
cpp_include "folly/container/F14Set.h"

struct StructWithEmptyMap {
  1: map<string, i64> myMap,
}

struct SubStruct {
  3: i64 mySubI64 = 17,
  12: string mySubString = "foobar",
}

union SubUnion {
  209: string text,
}

const SubUnion kSubUnion = {
  "text": "glorious",
}

struct OneOfEach {
  1: bool myBool = 1,
  2: byte myByte = 17,
  3: i16 myI16 = 1017,
  4: i32 myI32 = 100017,
  5: i64 myI64 = 5000000017,
  6: double myDouble = 5.25,
  7: float myFloat = 5.25,
  8: map<string, i64> myMap = {
    "foo": 13,
    "bar": 17,
    "baz": 19,
  },
  9: list<string> myList = [
    "foo",
    "bar",
    "baz",
  ],
  10: set<string> mySet = [
    "foo",
    "bar",
    "baz",
  ],
  11: SubStruct myStruct,
  12: SubUnion myUnion = kSubUnion,
}

struct OneOfEach2 {
  1: bool myBool = 1,
  2: byte myByte = 17,
  3: i16 myI16 = 1017,
  4: i32 myI32 = 100017,
  5: i64 myI64 = 5000000017,
  6: double myDouble = 5.25,
  7: float myFloat = 5.25,
  8: map<i32, i64> myMap,
  9: list<string> myList = [
    "foo",
    "bar",
    "baz",
  ],
  10: set<string> mySet = [
    "foo",
    "bar",
    "baz",
  ],
  11: SubStruct myStruct,
  12: SubUnion myUnion = kSubUnion,
}

struct OneOfEach3 {
  1: bool myBool = 1,
  2: byte myByte = 17,
  3: i16 myI16 = 1017,
  4: i32 myI32 = 100017,
  5: i64 myI64 = 5000000017,
  6: double myDouble = 5.25,
  7: float myFloat = 5.25,
  8: map<string, i64> myMap = {
    "foo": 13,
    "bar": 17,
    "baz": 19,
  },
  9: list<double> myList,
  10: set<list<i32>> mySet,
  11: SubStruct myStruct,
  12: SubUnion myUnion = kSubUnion,
}

struct DebugHashedAssociative {
  1: map<i64, set<i64>>
     (cpp.type = "std::map<int64_t, std::set<int64_t>>")
     value,
}

struct DebugSortedAssociative {
  1: map<i64, set<i64>>
     (cpp.type = "folly::F14FastMap<int64_t, folly::F14FastSet<int64_t>>")
     value,
}

struct StructWithF14VectorContainers {
  1: map<i32, i32> (cpp.template = 'folly::F14VectorMap') m,
  2: set<i32> (cpp.template = 'folly::F14VectorSet') s,
}
