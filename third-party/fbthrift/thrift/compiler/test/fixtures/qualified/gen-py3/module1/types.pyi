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


__property__ = property


class Enum(thrift.py3.types.Enum):
    ONE: Enum = ...
    TWO: Enum = ...
    THREE: Enum = ...


class Struct(thrift.py3.types.Struct, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    first: Final[int] = ...

    second: Final[str] = ...

    def __init__(
        self, *,
        first: _typing.Optional[int]=None,
        second: _typing.Optional[str]=None
    ) -> None: ...

    def __call__(
        self, *,
        first: _typing.Union[int, NOTSETTYPE, None]=NOTSET,
        second: _typing.Union[str, NOTSETTYPE, None]=NOTSET
    ) -> Struct: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['Struct'], bytes]]: ...
    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'Struct') -> bool: ...
    def __gt__(self, other: 'Struct') -> bool: ...
    def __le__(self, other: 'Struct') -> bool: ...
    def __ge__(self, other: 'Struct') -> bool: ...


_List__EnumT = _typing.TypeVar('_List__EnumT', bound=_typing.Sequence[Enum])


class List__Enum(_typing.Sequence[Enum], _typing.Hashable):
    def __init__(self, items: _typing.Sequence[Enum]=None) -> None: ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __contains__(self, x: object) -> bool: ...
    def __copy__(self) -> _typing.Sequence[Enum]: ...
    @_typing.overload
    def __getitem__(self, i: int) -> Enum: ...
    @_typing.overload
    def __getitem__(self, s: slice) -> _typing.Sequence[Enum]: ...
    def count(self, item: _typing.Any) -> int: ...
    def index(self, item: _typing.Any, start: int = ..., stop: int = ...) -> int: ...
    def __add__(self, other: _typing.Sequence[Enum]) -> 'List__Enum': ...
    def __radd__(self, other: _List__EnumT) -> _List__EnumT: ...
    def __reversed__(self) -> _typing.Iterator[Enum]: ...
    def __iter__(self) -> _typing.Iterator[Enum]: ...


c1: Struct = ...
e1s: List__Enum = ...
