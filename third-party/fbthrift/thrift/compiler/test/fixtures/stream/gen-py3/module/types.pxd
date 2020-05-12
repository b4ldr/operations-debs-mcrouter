#
# Autogenerated by Thrift
#
# DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
#  @generated
#

from libc.stdint cimport (
    int8_t as cint8_t,
    int16_t as cint16_t,
    int32_t as cint32_t,
    int64_t as cint64_t,
    uint32_t as cuint32_t,
)
from libcpp.string cimport string
from libcpp cimport bool as cbool, nullptr, nullptr_t
from cpython cimport bool as pbool
from libcpp.memory cimport shared_ptr, unique_ptr
from libcpp.vector cimport vector
from libcpp.set cimport set as cset
from libcpp.map cimport map as cmap, pair as cpair
from thrift.py3.exceptions cimport cTException
cimport folly.iobuf as __iobuf
cimport thrift.py3.exceptions
cimport thrift.py3.types
from thrift.py3.types cimport bstring, move, optional_field_ref
from folly.optional cimport cOptional
from folly cimport cFollyTry
from cpython.ref cimport PyObject
from thrift.py3.stream cimport (
    ClientBufferedStream, cClientBufferedStream, cClientBufferedStreamWrapper,
    ResponseAndClientBufferedStream, cResponseAndClientBufferedStream,
    ServerStream, cServerStream, ResponseAndServerStream
)
from thrift.py3.common cimport RpcOptions as __RpcOptions





cdef extern from "src/gen-cpp2/module_types_custom_protocol.h" namespace "::cpp2":
    # Forward Declaration
    cdef cppclass cFooEx "::cpp2::FooEx"(cTException)

cdef extern from "src/gen-cpp2/module_types.h" namespace "::cpp2":
    cdef cppclass cFooEx__isset "::cpp2::FooEx::__isset":
        pass

    cdef cppclass cFooEx "::cpp2::FooEx"(cTException):
        cFooEx() except +
        cFooEx(const cFooEx&) except +
        bint operator==(cFooEx&)
        bint operator!=(cFooEx&)
        bint operator<(cFooEx&)
        bint operator>(cFooEx&)
        bint operator<=(cFooEx&)
        bint operator>=(cFooEx&)
        cFooEx__isset __isset


cdef extern from "<utility>" namespace "std" nogil:
    cdef shared_ptr[cFooEx] move(unique_ptr[cFooEx])
    cdef shared_ptr[cFooEx] move_shared "std::move"(shared_ptr[cFooEx])
    cdef unique_ptr[cFooEx] move_unique "std::move"(unique_ptr[cFooEx])

cdef extern from "<memory>" namespace "std" nogil:
    cdef shared_ptr[const cFooEx] const_pointer_cast "std::const_pointer_cast<const ::cpp2::FooEx>"(shared_ptr[cFooEx])

# Forward Definition of the cython struct
cdef class FooEx(thrift.py3.exceptions.Error)


cdef class FooEx(thrift.py3.exceptions.Error):
    cdef object __hash
    cdef object __weakref__
    cdef shared_ptr[cFooEx] _cpp_obj

    @staticmethod
    cdef unique_ptr[cFooEx] _make_instance(
        cFooEx* base_instance,
        bint* __isNOTSET
    ) except *

    @staticmethod
    cdef create(shared_ptr[cFooEx])






cdef extern from "<utility>" namespace "std" nogil:
    cdef cClientBufferedStream[cint32_t] move_semistream "std::move"(cClientBufferedStream[cint32_t])

cdef class ClientBufferedStream__i32(ClientBufferedStream):
    cdef unique_ptr[cClientBufferedStreamWrapper[cint32_t]] _gen

    @staticmethod
    cdef create(cClientBufferedStream[cint32_t]& c_obj, __RpcOptions rpc_options)

    @staticmethod
    cdef void callback(
        cFollyTry[cOptional[cint32_t]]&& res,
        PyObject* userdata,
    )

cdef class ServerStream__i32(ServerStream):
    pass


cdef class ResponseAndClientBufferedStream__i32_i32(ResponseAndClientBufferedStream):
    cdef ClientBufferedStream__i32 _stream
    cdef cint32_t _response

    @staticmethod
    cdef create(cResponseAndClientBufferedStream[cint32_t, cint32_t]& c_obj, __RpcOptions rpc_options)


cdef class ResponseAndServerStream__i32_i32(ResponseAndServerStream):
    pass
