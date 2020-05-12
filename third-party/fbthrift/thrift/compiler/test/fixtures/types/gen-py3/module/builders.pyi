#
# Autogenerated by Thrift
#
# DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
#  @generated
#

import typing as _typing

import folly.iobuf as __iobuf
import thrift.py3.builder

import include.types as _include_types
import include.builders as _include_builders

import module.types as _module_types


class decorated_struct_Builder(thrift.py3.builder.StructBuilder):
    field: _typing.Optional[str]

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class ContainerStruct_Builder(thrift.py3.builder.StructBuilder):
    fieldA: _typing.Optional[list]
    fieldB: _typing.Optional[list]
    fieldC: _typing.Optional[list]
    fieldD: _typing.Optional[list]
    fieldE: _typing.Optional[list]
    fieldF: _typing.Optional[set]
    fieldG: _typing.Optional[dict]
    fieldH: _typing.Optional[dict]

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class CppTypeStruct_Builder(thrift.py3.builder.StructBuilder):
    fieldA: _typing.Optional[list]

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class VirtualStruct_Builder(thrift.py3.builder.StructBuilder):
    MyIntField: _typing.Optional[int]

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class MyStructWithForwardRefEnum_Builder(thrift.py3.builder.StructBuilder):
    a: _typing.Optional[_module_types.MyForwardRefEnum]
    b: _typing.Optional[_module_types.MyForwardRefEnum]

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class TrivialNumeric_Builder(thrift.py3.builder.StructBuilder):
    a: _typing.Optional[int]
    b: _typing.Optional[bool]

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class TrivialNestedWithDefault_Builder(thrift.py3.builder.StructBuilder):
    z: _typing.Optional[int]
    n: _typing.Any

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class ComplexString_Builder(thrift.py3.builder.StructBuilder):
    a: _typing.Optional[str]
    b: _typing.Optional[dict]

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class ComplexNestedWithDefault_Builder(thrift.py3.builder.StructBuilder):
    z: _typing.Optional[str]
    n: _typing.Any

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class MinPadding_Builder(thrift.py3.builder.StructBuilder):
    small: _typing.Optional[int]
    big: _typing.Optional[int]
    medium: _typing.Optional[int]
    biggish: _typing.Optional[int]
    tiny: _typing.Optional[int]

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class MyStruct_Builder(thrift.py3.builder.StructBuilder):
    MyIntField: _typing.Optional[int]
    MyStringField: _typing.Optional[str]
    majorVer: _typing.Optional[int]
    data: _typing.Any

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class MyDataItem_Builder(thrift.py3.builder.StructBuilder):

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class Renaming_Builder(thrift.py3.builder.StructBuilder):
    foo: _typing.Optional[int]

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class AnnotatedTypes_Builder(thrift.py3.builder.StructBuilder):
    binary_field: _typing.Optional[bytes]
    list_field: _typing.Optional[list]

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class ForwardUsageRoot_Builder(thrift.py3.builder.StructBuilder):
    ForwardUsageStruct: _typing.Any
    ForwardUsageByRef: _typing.Any

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class ForwardUsageStruct_Builder(thrift.py3.builder.StructBuilder):
    foo: _typing.Any

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class ForwardUsageByRef_Builder(thrift.py3.builder.StructBuilder):
    foo: _typing.Any

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class NoexceptMoveEmpty_Builder(thrift.py3.builder.StructBuilder):

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class NoexceptMoveSimpleStruct_Builder(thrift.py3.builder.StructBuilder):
    boolField: _typing.Optional[int]

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class NoexceptMoveComplexStruct_Builder(thrift.py3.builder.StructBuilder):
    MyBoolField: _typing.Optional[bool]
    MyIntField: _typing.Optional[int]
    MyStringField: _typing.Optional[str]
    MyStringField2: _typing.Optional[str]
    MyBinaryField: _typing.Optional[bytes]
    MyBinaryField2: _typing.Optional[bytes]
    MyBinaryField3: _typing.Optional[bytes]
    MyBinaryListField4: _typing.Optional[list]
    MyMapEnumAndInt: _typing.Optional[dict]

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


class NoExceptMoveUnion_Builder(thrift.py3.builder.StructBuilder):
    string_field: _typing.Optional[str]
    i32_field: _typing.Optional[int]

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...


