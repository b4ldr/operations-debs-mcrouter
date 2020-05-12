#
# Autogenerated by Thrift
#
# DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
#  @generated
#

# pyre-unsafe

import typing as __T  # sometimes `t` is used as a field name

from thrift import Thrift
from thrift.protocol.TProtocol import TProtocolBase

__property__ = property  # sometimes `property` is used as a field name


UTF8STRINGS: bool


class ItemEnum(int):
    OPTION_ONE: __T.ClassVar[ItemEnum]
    OPTION_TWO: __T.ClassVar[ItemEnum]

    _VALUES_TO_NAMES: __T.ClassVar[__T.Dict[ItemEnum, str]]
    _NAMES_TO_VALUES: __T.ClassVar[__T.Dict[str, ItemEnum]]


class Item:
    thrift_spec: __T.Tuple[__T.Optional[__T.Tuple[int, int, str, __T.Any, __T.Optional[int], int]]]
    thrift_field_annotations: __T.Dict[int, __T.Dict[str, str]]
    thrift_struct_annotations: __T.Dict[str, str]

    def __init__(
        self,
        key: __T.Optional[str] = ...,
        value: __T.Optional[bytes] = ...,
        enum_value: __T.Optional[ItemEnum] = ...
    ) -> None:
        ...

    @__property__
    def key(self) -> str: ...
    @key.setter
    def key(self, value: __T.Optional[str]) -> None: ...
    @__property__
    def value(self) -> __T.Optional[bytes]: ...
    @value.setter
    def value(self, value: __T.Optional[bytes]) -> None: ...
    @__property__
    def enum_value(self) -> ItemEnum: ...
    @enum_value.setter
    def enum_value(self, value: __T.Optional[ItemEnum]) -> None: ...


    def isUnion(self) -> bool: ...
    def checkRequired(self) -> None: ...
    def read(self, iprot: TProtocolBase) -> None: ...
    @__T.overload
    def readFromJson(self, json: __T.Dict[str, __T.Any], is_text: bool = ...) -> None: ...
    @__T.overload
    def readFromJson(self, json: str, is_text: bool = ...) -> None: ...
    def write(self, oprot: TProtocolBase) -> None: ...
    def __eq__(self, other: __T.Any) -> bool: ...
    def __ne__(self, other: __T.Any) -> bool: ...


