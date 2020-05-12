#
# Autogenerated by Thrift
#
# DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
#  @generated
#

import folly.iobuf as __iobuf
import thrift.py3.types
import thrift.py3.exceptions
from thrift.py3.types import NOTSET, NOTSETTYPE
import typing as _typing
from typing_extensions import Final

import sys
import itertools
import include.types as _include_types


__property__ = property


class has_bitwise_ops(thrift.py3.types.Enum):
    none: has_bitwise_ops = ...
    zero: has_bitwise_ops = ...
    one: has_bitwise_ops = ...
    two: has_bitwise_ops = ...
    three: has_bitwise_ops = ...


class is_unscoped(thrift.py3.types.Enum):
    hello: is_unscoped = ...
    world: is_unscoped = ...


class MyForwardRefEnum(thrift.py3.types.Enum):
    ZERO: MyForwardRefEnum = ...
    NONZERO: MyForwardRefEnum = ...


class MyEnumA(thrift.py3.types.Enum):
    fieldA: MyEnumA = ...
    fieldB: MyEnumA = ...
    fieldC: MyEnumA = ...


class decorated_struct(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    field: Final[str] = ...

    def __init__(
        self, *,
        field: _typing.Optional[str]=None
    ) -> None: ...

    def __call__(
        self, *,
        field: _typing.Union[str, NOTSETTYPE, None]=NOTSET
    ) -> decorated_struct: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['decorated_struct'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'decorated_struct') -> bool: ...
    def __gt__(self, other: 'decorated_struct') -> bool: ...
    def __le__(self, other: 'decorated_struct') -> bool: ...
    def __ge__(self, other: 'decorated_struct') -> bool: ...


class ContainerStruct(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    fieldA: Final[_typing.Sequence[int]] = ...

    fieldB: Final[_typing.Sequence[int]] = ...

    fieldC: Final[_typing.Sequence[int]] = ...

    fieldD: Final[_typing.Sequence[int]] = ...

    fieldE: Final[_typing.Sequence[int]] = ...

    fieldF: Final[_typing.AbstractSet[int]] = ...

    fieldG: Final[_typing.Mapping[int, str]] = ...

    fieldH: Final[_typing.Mapping[int, str]] = ...

    def __init__(
        self, *,
        fieldA: _typing.Optional[_typing.Sequence[int]]=None,
        fieldB: _typing.Optional[_typing.Sequence[int]]=None,
        fieldC: _typing.Optional[_typing.Sequence[int]]=None,
        fieldD: _typing.Optional[_typing.Sequence[int]]=None,
        fieldE: _typing.Optional[_typing.Sequence[int]]=None,
        fieldF: _typing.Optional[_typing.AbstractSet[int]]=None,
        fieldG: _typing.Optional[_typing.Mapping[int, str]]=None,
        fieldH: _typing.Optional[_typing.Mapping[int, str]]=None
    ) -> None: ...

    def __call__(
        self, *,
        fieldA: _typing.Union[_typing.Sequence[int], NOTSETTYPE, None]=NOTSET,
        fieldB: _typing.Union[_typing.Sequence[int], NOTSETTYPE, None]=NOTSET,
        fieldC: _typing.Union[_typing.Sequence[int], NOTSETTYPE, None]=NOTSET,
        fieldD: _typing.Union[_typing.Sequence[int], NOTSETTYPE, None]=NOTSET,
        fieldE: _typing.Union[_typing.Sequence[int], NOTSETTYPE, None]=NOTSET,
        fieldF: _typing.Union[_typing.AbstractSet[int], NOTSETTYPE, None]=NOTSET,
        fieldG: _typing.Union[_typing.Mapping[int, str], NOTSETTYPE, None]=NOTSET,
        fieldH: _typing.Union[_typing.Mapping[int, str], NOTSETTYPE, None]=NOTSET
    ) -> ContainerStruct: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['ContainerStruct'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...


class CppTypeStruct(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    fieldA: Final[_typing.Sequence[int]] = ...

    def __init__(
        self, *,
        fieldA: _typing.Optional[_typing.Sequence[int]]=None
    ) -> None: ...

    def __call__(
        self, *,
        fieldA: _typing.Union[_typing.Sequence[int], NOTSETTYPE, None]=NOTSET
    ) -> CppTypeStruct: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['CppTypeStruct'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'CppTypeStruct') -> bool: ...
    def __gt__(self, other: 'CppTypeStruct') -> bool: ...
    def __le__(self, other: 'CppTypeStruct') -> bool: ...
    def __ge__(self, other: 'CppTypeStruct') -> bool: ...


class VirtualStruct(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    MyIntField: Final[int] = ...

    def __init__(
        self, *,
        MyIntField: _typing.Optional[int]=None
    ) -> None: ...

    def __call__(
        self, *,
        MyIntField: _typing.Union[int, NOTSETTYPE, None]=NOTSET
    ) -> VirtualStruct: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['VirtualStruct'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'VirtualStruct') -> bool: ...
    def __gt__(self, other: 'VirtualStruct') -> bool: ...
    def __le__(self, other: 'VirtualStruct') -> bool: ...
    def __ge__(self, other: 'VirtualStruct') -> bool: ...


class MyStructWithForwardRefEnum(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    a: Final[MyForwardRefEnum] = ...

    b: Final[MyForwardRefEnum] = ...

    def __init__(
        self, *,
        a: _typing.Optional[MyForwardRefEnum]=None,
        b: _typing.Optional[MyForwardRefEnum]=None
    ) -> None: ...

    def __call__(
        self, *,
        a: _typing.Union[MyForwardRefEnum, NOTSETTYPE, None]=NOTSET,
        b: _typing.Union[MyForwardRefEnum, NOTSETTYPE, None]=NOTSET
    ) -> MyStructWithForwardRefEnum: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['MyStructWithForwardRefEnum'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'MyStructWithForwardRefEnum') -> bool: ...
    def __gt__(self, other: 'MyStructWithForwardRefEnum') -> bool: ...
    def __le__(self, other: 'MyStructWithForwardRefEnum') -> bool: ...
    def __ge__(self, other: 'MyStructWithForwardRefEnum') -> bool: ...


class TrivialNumeric(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    a: Final[int] = ...

    b: Final[bool] = ...

    def __init__(
        self, *,
        a: _typing.Optional[int]=None,
        b: _typing.Optional[bool]=None
    ) -> None: ...

    def __call__(
        self, *,
        a: _typing.Union[int, NOTSETTYPE, None]=NOTSET,
        b: _typing.Union[bool, NOTSETTYPE, None]=NOTSET
    ) -> TrivialNumeric: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['TrivialNumeric'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'TrivialNumeric') -> bool: ...
    def __gt__(self, other: 'TrivialNumeric') -> bool: ...
    def __le__(self, other: 'TrivialNumeric') -> bool: ...
    def __ge__(self, other: 'TrivialNumeric') -> bool: ...


class TrivialNestedWithDefault(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    z: Final[int] = ...

    n: Final['TrivialNumeric'] = ...

    def __init__(
        self, *,
        z: _typing.Optional[int]=None,
        n: _typing.Optional['TrivialNumeric']=None
    ) -> None: ...

    def __call__(
        self, *,
        z: _typing.Union[int, NOTSETTYPE, None]=NOTSET,
        n: _typing.Union['TrivialNumeric', NOTSETTYPE, None]=NOTSET
    ) -> TrivialNestedWithDefault: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['TrivialNestedWithDefault'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'TrivialNestedWithDefault') -> bool: ...
    def __gt__(self, other: 'TrivialNestedWithDefault') -> bool: ...
    def __le__(self, other: 'TrivialNestedWithDefault') -> bool: ...
    def __ge__(self, other: 'TrivialNestedWithDefault') -> bool: ...


class ComplexString(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    a: Final[str] = ...

    b: Final[_typing.Mapping[str, int]] = ...

    def __init__(
        self, *,
        a: _typing.Optional[str]=None,
        b: _typing.Optional[_typing.Mapping[str, int]]=None
    ) -> None: ...

    def __call__(
        self, *,
        a: _typing.Union[str, NOTSETTYPE, None]=NOTSET,
        b: _typing.Union[_typing.Mapping[str, int], NOTSETTYPE, None]=NOTSET
    ) -> ComplexString: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['ComplexString'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'ComplexString') -> bool: ...
    def __gt__(self, other: 'ComplexString') -> bool: ...
    def __le__(self, other: 'ComplexString') -> bool: ...
    def __ge__(self, other: 'ComplexString') -> bool: ...


class ComplexNestedWithDefault(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    z: Final[str] = ...

    n: Final['ComplexString'] = ...

    def __init__(
        self, *,
        z: _typing.Optional[str]=None,
        n: _typing.Optional['ComplexString']=None
    ) -> None: ...

    def __call__(
        self, *,
        z: _typing.Union[str, NOTSETTYPE, None]=NOTSET,
        n: _typing.Union['ComplexString', NOTSETTYPE, None]=NOTSET
    ) -> ComplexNestedWithDefault: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['ComplexNestedWithDefault'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'ComplexNestedWithDefault') -> bool: ...
    def __gt__(self, other: 'ComplexNestedWithDefault') -> bool: ...
    def __le__(self, other: 'ComplexNestedWithDefault') -> bool: ...
    def __ge__(self, other: 'ComplexNestedWithDefault') -> bool: ...


class MinPadding(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    small: Final[int] = ...

    big: Final[int] = ...

    medium: Final[int] = ...

    biggish: Final[int] = ...

    tiny: Final[int] = ...

    def __init__(
        self, *,
        small: int,
        big: int,
        medium: int,
        biggish: int,
        tiny: int
    ) -> None: ...

    def __call__(
        self, *,
        small: _typing.Union[int, NOTSETTYPE]=NOTSET,
        big: _typing.Union[int, NOTSETTYPE]=NOTSET,
        medium: _typing.Union[int, NOTSETTYPE]=NOTSET,
        biggish: _typing.Union[int, NOTSETTYPE]=NOTSET,
        tiny: _typing.Union[int, NOTSETTYPE]=NOTSET
    ) -> MinPadding: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['MinPadding'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'MinPadding') -> bool: ...
    def __gt__(self, other: 'MinPadding') -> bool: ...
    def __le__(self, other: 'MinPadding') -> bool: ...
    def __ge__(self, other: 'MinPadding') -> bool: ...


class MyStruct(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    MyIntField: Final[int] = ...

    MyStringField: Final[str] = ...

    majorVer: Final[int] = ...

    data: Final['MyDataItem'] = ...

    def __init__(
        self, *,
        MyIntField: _typing.Optional[int]=None,
        MyStringField: _typing.Optional[str]=None,
        majorVer: _typing.Optional[int]=None,
        data: _typing.Optional['MyDataItem']=None
    ) -> None: ...

    def __call__(
        self, *,
        MyIntField: _typing.Union[int, NOTSETTYPE, None]=NOTSET,
        MyStringField: _typing.Union[str, NOTSETTYPE, None]=NOTSET,
        majorVer: _typing.Union[int, NOTSETTYPE, None]=NOTSET,
        data: _typing.Union['MyDataItem', NOTSETTYPE, None]=NOTSET
    ) -> MyStruct: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['MyStruct'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'MyStruct') -> bool: ...
    def __gt__(self, other: 'MyStruct') -> bool: ...
    def __le__(self, other: 'MyStruct') -> bool: ...
    def __ge__(self, other: 'MyStruct') -> bool: ...


class MyDataItem(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    def __init__(
        self, 
    ) -> None: ...

    def __call__(
        self, 
    ) -> MyDataItem: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['MyDataItem'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'MyDataItem') -> bool: ...
    def __gt__(self, other: 'MyDataItem') -> bool: ...
    def __le__(self, other: 'MyDataItem') -> bool: ...
    def __ge__(self, other: 'MyDataItem') -> bool: ...


class Renaming(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    foo: Final[int] = ...

    def __init__(
        self, *,
        foo: _typing.Optional[int]=None
    ) -> None: ...

    def __call__(
        self, *,
        foo: _typing.Union[int, NOTSETTYPE, None]=NOTSET
    ) -> Renaming: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['Renaming'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'Renaming') -> bool: ...
    def __gt__(self, other: 'Renaming') -> bool: ...
    def __le__(self, other: 'Renaming') -> bool: ...
    def __ge__(self, other: 'Renaming') -> bool: ...


class AnnotatedTypes(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    binary_field: Final[bytes] = ...

    list_field: Final[_typing.Sequence[_typing.Mapping[int, str]]] = ...

    def __init__(
        self, *,
        binary_field: _typing.Optional[bytes]=None,
        list_field: _typing.Optional[_typing.Sequence[_typing.Mapping[int, str]]]=None
    ) -> None: ...

    def __call__(
        self, *,
        binary_field: _typing.Union[bytes, NOTSETTYPE, None]=NOTSET,
        list_field: _typing.Union[_typing.Sequence[_typing.Mapping[int, str]], NOTSETTYPE, None]=NOTSET
    ) -> AnnotatedTypes: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['AnnotatedTypes'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...


class ForwardUsageRoot(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    ForwardUsageStruct: Final[_typing.Optional['ForwardUsageStruct']] = ...

    ForwardUsageByRef: Final[_typing.Optional['ForwardUsageByRef']] = ...

    def __init__(
        self, *,
        ForwardUsageStruct: _typing.Optional['ForwardUsageStruct']=None,
        ForwardUsageByRef: _typing.Optional['ForwardUsageByRef']=None
    ) -> None: ...

    def __call__(
        self, *,
        ForwardUsageStruct: _typing.Union['ForwardUsageStruct', NOTSETTYPE, None]=NOTSET,
        ForwardUsageByRef: _typing.Union['ForwardUsageByRef', NOTSETTYPE, None]=NOTSET
    ) -> ForwardUsageRoot: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['ForwardUsageRoot'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'ForwardUsageRoot') -> bool: ...
    def __gt__(self, other: 'ForwardUsageRoot') -> bool: ...
    def __le__(self, other: 'ForwardUsageRoot') -> bool: ...
    def __ge__(self, other: 'ForwardUsageRoot') -> bool: ...


class ForwardUsageStruct(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    foo: Final[_typing.Optional['ForwardUsageRoot']] = ...

    def __init__(
        self, *,
        foo: _typing.Optional['ForwardUsageRoot']=None
    ) -> None: ...

    def __call__(
        self, *,
        foo: _typing.Union['ForwardUsageRoot', NOTSETTYPE, None]=NOTSET
    ) -> ForwardUsageStruct: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['ForwardUsageStruct'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'ForwardUsageStruct') -> bool: ...
    def __gt__(self, other: 'ForwardUsageStruct') -> bool: ...
    def __le__(self, other: 'ForwardUsageStruct') -> bool: ...
    def __ge__(self, other: 'ForwardUsageStruct') -> bool: ...


class ForwardUsageByRef(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    foo: Final[_typing.Optional['ForwardUsageRoot']] = ...

    def __init__(
        self, *,
        foo: _typing.Optional['ForwardUsageRoot']=None
    ) -> None: ...

    def __call__(
        self, *,
        foo: _typing.Union['ForwardUsageRoot', NOTSETTYPE, None]=NOTSET
    ) -> ForwardUsageByRef: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['ForwardUsageByRef'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'ForwardUsageByRef') -> bool: ...
    def __gt__(self, other: 'ForwardUsageByRef') -> bool: ...
    def __le__(self, other: 'ForwardUsageByRef') -> bool: ...
    def __ge__(self, other: 'ForwardUsageByRef') -> bool: ...


class NoexceptMoveEmpty(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    def __init__(
        self, 
    ) -> None: ...

    def __call__(
        self, 
    ) -> NoexceptMoveEmpty: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['NoexceptMoveEmpty'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'NoexceptMoveEmpty') -> bool: ...
    def __gt__(self, other: 'NoexceptMoveEmpty') -> bool: ...
    def __le__(self, other: 'NoexceptMoveEmpty') -> bool: ...
    def __ge__(self, other: 'NoexceptMoveEmpty') -> bool: ...


class NoexceptMoveSimpleStruct(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    boolField: Final[int] = ...

    def __init__(
        self, *,
        boolField: _typing.Optional[int]=None
    ) -> None: ...

    def __call__(
        self, *,
        boolField: _typing.Union[int, NOTSETTYPE, None]=NOTSET
    ) -> NoexceptMoveSimpleStruct: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['NoexceptMoveSimpleStruct'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'NoexceptMoveSimpleStruct') -> bool: ...
    def __gt__(self, other: 'NoexceptMoveSimpleStruct') -> bool: ...
    def __le__(self, other: 'NoexceptMoveSimpleStruct') -> bool: ...
    def __ge__(self, other: 'NoexceptMoveSimpleStruct') -> bool: ...


class NoexceptMoveComplexStruct(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    MyBoolField: Final[bool] = ...

    MyIntField: Final[int] = ...

    MyStringField: Final[str] = ...

    MyStringField2: Final[str] = ...

    MyBinaryField: Final[bytes] = ...

    MyBinaryField2: Final[_typing.Optional[bytes]] = ...

    MyBinaryField3: Final[bytes] = ...

    MyBinaryListField4: Final[_typing.Sequence[bytes]] = ...

    MyMapEnumAndInt: Final[_typing.Mapping[MyEnumA, str]] = ...

    def __init__(
        self, *,
        MyBoolField: _typing.Optional[bool]=None,
        MyIntField: _typing.Optional[int]=None,
        MyStringField: _typing.Optional[str]=None,
        MyStringField2: _typing.Optional[str]=None,
        MyBinaryField: _typing.Optional[bytes]=None,
        MyBinaryField2: _typing.Optional[bytes]=None,
        MyBinaryField3: bytes,
        MyBinaryListField4: _typing.Optional[_typing.Sequence[bytes]]=None,
        MyMapEnumAndInt: _typing.Optional[_typing.Mapping[MyEnumA, str]]=None
    ) -> None: ...

    def __call__(
        self, *,
        MyBoolField: _typing.Union[bool, NOTSETTYPE, None]=NOTSET,
        MyIntField: _typing.Union[int, NOTSETTYPE, None]=NOTSET,
        MyStringField: _typing.Union[str, NOTSETTYPE, None]=NOTSET,
        MyStringField2: _typing.Union[str, NOTSETTYPE, None]=NOTSET,
        MyBinaryField: _typing.Union[bytes, NOTSETTYPE, None]=NOTSET,
        MyBinaryField2: _typing.Union[bytes, NOTSETTYPE, None]=NOTSET,
        MyBinaryField3: _typing.Union[bytes, NOTSETTYPE]=NOTSET,
        MyBinaryListField4: _typing.Union[_typing.Sequence[bytes], NOTSETTYPE, None]=NOTSET,
        MyMapEnumAndInt: _typing.Union[_typing.Mapping[MyEnumA, str], NOTSETTYPE, None]=NOTSET
    ) -> NoexceptMoveComplexStruct: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['NoexceptMoveComplexStruct'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'NoexceptMoveComplexStruct') -> bool: ...
    def __gt__(self, other: 'NoexceptMoveComplexStruct') -> bool: ...
    def __le__(self, other: 'NoexceptMoveComplexStruct') -> bool: ...
    def __ge__(self, other: 'NoexceptMoveComplexStruct') -> bool: ...


class NoExceptMoveUnion(thrift.py3.types.Union, _typing.Hashable):
    string_field: Final[str] = ...

    i32_field: Final[int] = ...

    def __init__(
        self, *,
        string_field: _typing.Optional[str]=None,
        i32_field: _typing.Optional[int]=None
    ) -> None: ...

    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'NoExceptMoveUnion') -> bool: ...
    def __gt__(self, other: 'NoExceptMoveUnion') -> bool: ...
    def __le__(self, other: 'NoExceptMoveUnion') -> bool: ...
    def __ge__(self, other: 'NoExceptMoveUnion') -> bool: ...

    class Type(thrift.py3.types.Enum):
        EMPTY: NoExceptMoveUnion.Type = ...
        string_field: NoExceptMoveUnion.Type = ...
        i32_field: NoExceptMoveUnion.Type = ...

    @staticmethod
    def fromValue(value: _typing.Union[None, str, int]) -> NoExceptMoveUnion: ...
    @__property__
    def value(self) -> _typing.Union[None, str, int]: ...
    @__property__
    def type(self) -> "NoExceptMoveUnion.Type": ...
    def get_type(self) -> "NoExceptMoveUnion.Type": ...


class std_unordered_map__Map__i32_string(_typing.Mapping[int, str], _typing.Hashable):
    def __init__(self, items: _typing.Mapping[int, str]=None) -> None: ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __contains__(self, x: object) -> bool: ...
    def __copy__(self) -> _typing.Mapping[int, str]: ...
    def __getitem__(self, key: int) -> str: ...
    def __iter__(self) -> _typing.Iterator[int]: ...


_List__i64T = _typing.TypeVar('_List__i64T', bound=_typing.Sequence[int])


class List__i64(_typing.Sequence[int], _typing.Hashable):
    def __init__(self, items: _typing.Sequence[int]=None) -> None: ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __contains__(self, x: object) -> bool: ...
    def __copy__(self) -> _typing.Sequence[int]: ...
    @_typing.overload
    def __getitem__(self, i: int) -> int: ...
    @_typing.overload
    def __getitem__(self, s: slice) -> _typing.Sequence[int]: ...
    def count(self, item: _typing.Any) -> int: ...
    def index(self, item: _typing.Any, start: int = ..., stop: int = ...) -> int: ...
    def __add__(self, other: _typing.Sequence[int]) -> 'List__i64': ...
    def __radd__(self, other: _List__i64T) -> _List__i64T: ...
    def __reversed__(self) -> _typing.Iterator[int]: ...
    def __iter__(self) -> _typing.Iterator[int]: ...


class Map__binary_i64(_typing.Mapping[bytes, int], _typing.Hashable):
    def __init__(self, items: _typing.Mapping[bytes, int]=None) -> None: ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __contains__(self, x: object) -> bool: ...
    def __copy__(self) -> _typing.Mapping[bytes, int]: ...
    def __getitem__(self, key: bytes) -> int: ...
    def __iter__(self) -> _typing.Iterator[bytes]: ...


_List__i32T = _typing.TypeVar('_List__i32T', bound=_typing.Sequence[int])


class List__i32(_typing.Sequence[int], _typing.Hashable):
    def __init__(self, items: _typing.Sequence[int]=None) -> None: ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __contains__(self, x: object) -> bool: ...
    def __copy__(self) -> _typing.Sequence[int]: ...
    @_typing.overload
    def __getitem__(self, i: int) -> int: ...
    @_typing.overload
    def __getitem__(self, s: slice) -> _typing.Sequence[int]: ...
    def count(self, item: _typing.Any) -> int: ...
    def index(self, item: _typing.Any, start: int = ..., stop: int = ...) -> int: ...
    def __add__(self, other: _typing.Sequence[int]) -> 'List__i32': ...
    def __radd__(self, other: _List__i32T) -> _List__i32T: ...
    def __reversed__(self) -> _typing.Iterator[int]: ...
    def __iter__(self) -> _typing.Iterator[int]: ...


_std_list__List__i32T = _typing.TypeVar('_std_list__List__i32T', bound=_typing.Sequence[int])


class std_list__List__i32(_typing.Sequence[int], _typing.Hashable):
    def __init__(self, items: _typing.Sequence[int]=None) -> None: ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __contains__(self, x: object) -> bool: ...
    def __copy__(self) -> _typing.Sequence[int]: ...
    @_typing.overload
    def __getitem__(self, i: int) -> int: ...
    @_typing.overload
    def __getitem__(self, s: slice) -> _typing.Sequence[int]: ...
    def count(self, item: _typing.Any) -> int: ...
    def index(self, item: _typing.Any, start: int = ..., stop: int = ...) -> int: ...
    def __add__(self, other: _typing.Sequence[int]) -> 'std_list__List__i32': ...
    def __radd__(self, other: _std_list__List__i32T) -> _std_list__List__i32T: ...
    def __reversed__(self) -> _typing.Iterator[int]: ...
    def __iter__(self) -> _typing.Iterator[int]: ...


_std_deque__List__i32T = _typing.TypeVar('_std_deque__List__i32T', bound=_typing.Sequence[int])


class std_deque__List__i32(_typing.Sequence[int], _typing.Hashable):
    def __init__(self, items: _typing.Sequence[int]=None) -> None: ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __contains__(self, x: object) -> bool: ...
    def __copy__(self) -> _typing.Sequence[int]: ...
    @_typing.overload
    def __getitem__(self, i: int) -> int: ...
    @_typing.overload
    def __getitem__(self, s: slice) -> _typing.Sequence[int]: ...
    def count(self, item: _typing.Any) -> int: ...
    def index(self, item: _typing.Any, start: int = ..., stop: int = ...) -> int: ...
    def __add__(self, other: _typing.Sequence[int]) -> 'std_deque__List__i32': ...
    def __radd__(self, other: _std_deque__List__i32T) -> _std_deque__List__i32T: ...
    def __reversed__(self) -> _typing.Iterator[int]: ...
    def __iter__(self) -> _typing.Iterator[int]: ...


_folly_fbvector__List__i32T = _typing.TypeVar('_folly_fbvector__List__i32T', bound=_typing.Sequence[int])


class folly_fbvector__List__i32(_typing.Sequence[int], _typing.Hashable):
    def __init__(self, items: _typing.Sequence[int]=None) -> None: ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __contains__(self, x: object) -> bool: ...
    def __copy__(self) -> _typing.Sequence[int]: ...
    @_typing.overload
    def __getitem__(self, i: int) -> int: ...
    @_typing.overload
    def __getitem__(self, s: slice) -> _typing.Sequence[int]: ...
    def count(self, item: _typing.Any) -> int: ...
    def index(self, item: _typing.Any, start: int = ..., stop: int = ...) -> int: ...
    def __add__(self, other: _typing.Sequence[int]) -> 'folly_fbvector__List__i32': ...
    def __radd__(self, other: _folly_fbvector__List__i32T) -> _folly_fbvector__List__i32T: ...
    def __reversed__(self) -> _typing.Iterator[int]: ...
    def __iter__(self) -> _typing.Iterator[int]: ...


_folly_small_vector__List__i32T = _typing.TypeVar('_folly_small_vector__List__i32T', bound=_typing.Sequence[int])


class folly_small_vector__List__i32(_typing.Sequence[int], _typing.Hashable):
    def __init__(self, items: _typing.Sequence[int]=None) -> None: ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __contains__(self, x: object) -> bool: ...
    def __copy__(self) -> _typing.Sequence[int]: ...
    @_typing.overload
    def __getitem__(self, i: int) -> int: ...
    @_typing.overload
    def __getitem__(self, s: slice) -> _typing.Sequence[int]: ...
    def count(self, item: _typing.Any) -> int: ...
    def index(self, item: _typing.Any, start: int = ..., stop: int = ...) -> int: ...
    def __add__(self, other: _typing.Sequence[int]) -> 'folly_small_vector__List__i32': ...
    def __radd__(self, other: _folly_small_vector__List__i32T) -> _folly_small_vector__List__i32T: ...
    def __reversed__(self) -> _typing.Iterator[int]: ...
    def __iter__(self) -> _typing.Iterator[int]: ...


class folly_sorted_vector_set__Set__i32(_typing.AbstractSet[int], _typing.Hashable):
    def __init__(self, items: _typing.AbstractSet[int]=None) -> None: ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __contains__(self, x: object) -> bool: ...
    def __copy__(self) -> _typing.AbstractSet[int]: ...
    def isdisjoint(self, other: _typing.AbstractSet[int]) -> bool: ...
    def union(self, other: _typing.AbstractSet[int]) -> 'folly_sorted_vector_set__Set__i32': ...
    def intersection(self, other: _typing.AbstractSet[int]) -> 'folly_sorted_vector_set__Set__i32': ...
    def difference(self, other: _typing.AbstractSet[int]) -> 'folly_sorted_vector_set__Set__i32': ...
    def symmetric_difference(self, other: _typing.AbstractSet[int]) -> 'folly_sorted_vector_set__Set__i32': ...
    def issubset(self, other: _typing.AbstractSet[int]) -> bool: ...
    def issuperset(self, other: _typing.AbstractSet[int]) -> bool: ...
    def __iter__(self) -> _typing.Iterator[int]: ...


class folly_sorted_vector_map__Map__i32_string(_typing.Mapping[int, str], _typing.Hashable):
    def __init__(self, items: _typing.Mapping[int, str]=None) -> None: ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __contains__(self, x: object) -> bool: ...
    def __copy__(self) -> _typing.Mapping[int, str]: ...
    def __getitem__(self, key: int) -> str: ...
    def __iter__(self) -> _typing.Iterator[int]: ...


_std_list_int32_t__List__i32T = _typing.TypeVar('_std_list_int32_t__List__i32T', bound=_typing.Sequence[int])


class std_list_int32_t__List__i32(_typing.Sequence[int], _typing.Hashable):
    def __init__(self, items: _typing.Sequence[int]=None) -> None: ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __contains__(self, x: object) -> bool: ...
    def __copy__(self) -> _typing.Sequence[int]: ...
    @_typing.overload
    def __getitem__(self, i: int) -> int: ...
    @_typing.overload
    def __getitem__(self, s: slice) -> _typing.Sequence[int]: ...
    def count(self, item: _typing.Any) -> int: ...
    def index(self, item: _typing.Any, start: int = ..., stop: int = ...) -> int: ...
    def __add__(self, other: _typing.Sequence[int]) -> 'std_list_int32_t__List__i32': ...
    def __radd__(self, other: _std_list_int32_t__List__i32T) -> _std_list_int32_t__List__i32T: ...
    def __reversed__(self) -> _typing.Iterator[int]: ...
    def __iter__(self) -> _typing.Iterator[int]: ...


class Map__string_i32(_typing.Mapping[str, int], _typing.Hashable):
    def __init__(self, items: _typing.Mapping[str, int]=None) -> None: ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __contains__(self, x: object) -> bool: ...
    def __copy__(self) -> _typing.Mapping[str, int]: ...
    def __getitem__(self, key: str) -> int: ...
    def __iter__(self) -> _typing.Iterator[str]: ...


_List__std_unordered_map__Map__i32_stringT = _typing.TypeVar('_List__std_unordered_map__Map__i32_stringT', bound=_typing.Sequence[_typing.Mapping[int, str]])


class List__std_unordered_map__Map__i32_string(_typing.Sequence[_typing.Mapping[int, str]], _typing.Hashable):
    def __init__(self, items: _typing.Sequence[_typing.Mapping[int, str]]=None) -> None: ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __contains__(self, x: object) -> bool: ...
    def __copy__(self) -> _typing.Sequence[_typing.Mapping[int, str]]: ...
    @_typing.overload
    def __getitem__(self, i: int) -> _typing.Mapping[int, str]: ...
    @_typing.overload
    def __getitem__(self, s: slice) -> _typing.Sequence[_typing.Mapping[int, str]]: ...
    def count(self, item: _typing.Any) -> int: ...
    def index(self, item: _typing.Any, start: int = ..., stop: int = ...) -> int: ...
    def __add__(self, other: _typing.Sequence[_typing.Mapping[int, str]]) -> 'List__std_unordered_map__Map__i32_string': ...
    def __radd__(self, other: _List__std_unordered_map__Map__i32_stringT) -> _List__std_unordered_map__Map__i32_stringT: ...
    def __reversed__(self) -> _typing.Iterator[_typing.Mapping[int, str]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Mapping[int, str]]: ...


_List__binaryT = _typing.TypeVar('_List__binaryT', bound=_typing.Sequence[bytes])


class List__binary(_typing.Sequence[bytes], _typing.Hashable):
    def __init__(self, items: _typing.Sequence[bytes]=None) -> None: ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __contains__(self, x: object) -> bool: ...
    def __copy__(self) -> _typing.Sequence[bytes]: ...
    @_typing.overload
    def __getitem__(self, i: int) -> bytes: ...
    @_typing.overload
    def __getitem__(self, s: slice) -> _typing.Sequence[bytes]: ...
    def count(self, item: _typing.Any) -> int: ...
    def index(self, item: _typing.Any, start: int = ..., stop: int = ...) -> int: ...
    def __add__(self, other: _typing.Sequence[bytes]) -> 'List__binary': ...
    def __radd__(self, other: _List__binaryT) -> _List__binaryT: ...
    def __reversed__(self) -> _typing.Iterator[bytes]: ...
    def __iter__(self) -> _typing.Iterator[bytes]: ...


class Map__MyEnumA_string(_typing.Mapping[MyEnumA, str], _typing.Hashable):
    def __init__(self, items: _typing.Mapping[MyEnumA, str]=None) -> None: ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __contains__(self, x: object) -> bool: ...
    def __copy__(self) -> _typing.Mapping[MyEnumA, str]: ...
    def __getitem__(self, key: MyEnumA) -> str: ...
    def __iter__(self) -> _typing.Iterator[MyEnumA]: ...


TBinary = bytes