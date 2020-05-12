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


class Banal(thrift.py3.exceptions.Error, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    def __init__(
        self, 
    ) -> None: ...

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'Banal') -> bool: ...
    def __gt__(self, other: 'Banal') -> bool: ...
    def __le__(self, other: 'Banal') -> bool: ...
    def __ge__(self, other: 'Banal') -> bool: ...


class Fiery(thrift.py3.exceptions.Error, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    message: Final[str] = ...

    def __init__(
        self, *,
        message: str
    ) -> None: ...

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'Fiery') -> bool: ...
    def __gt__(self, other: 'Fiery') -> bool: ...
    def __le__(self, other: 'Fiery') -> bool: ...
    def __ge__(self, other: 'Fiery') -> bool: ...


class Serious(thrift.py3.exceptions.Error, _typing.Hashable, _typing.Iterable[_typing.Tuple[str, _typing.Any]]):
    sonnet: Final[_typing.Optional[str]] = ...

    def __init__(
        self, *,
        sonnet: _typing.Optional[str]=None
    ) -> None: ...

    def __iter__(self) -> _typing.Iterator[_typing.Tuple[str, _typing.Any]]: ...
    def __bool__(self) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'Serious') -> bool: ...
    def __gt__(self, other: 'Serious') -> bool: ...
    def __le__(self, other: 'Serious') -> bool: ...
    def __ge__(self, other: 'Serious') -> bool: ...


