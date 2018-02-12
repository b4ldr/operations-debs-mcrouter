#
# Autogenerated by Thrift
#
# DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
#  @generated
#

from libcpp.string cimport string
from libcpp cimport bool as cbool
from cpython cimport bool as pbool
from libc.stdint cimport int8_t, int16_t, int32_t, int64_t
from libcpp.memory cimport shared_ptr, unique_ptr
from libcpp.vector cimport vector
from libcpp.set cimport set as cset
from libcpp.map cimport map as cmap, pair as cpair
from thrift.py3.exceptions cimport cTException
cimport thrift.py3.exceptions
cimport thrift.py3.types
from folly.optional cimport cOptional


cdef extern from "src/gen-cpp2/module_types.h" namespace "cpp2":
    cdef cppclass cTypedEnum "cpp2::TypedEnum":
        bint operator==(cTypedEnum&)
    cTypedEnum TypedEnum__VAL1 "cpp2::TypedEnum::VAL1"
    cTypedEnum TypedEnum__VAL2 "cpp2::TypedEnum::VAL2"

cdef cTypedEnum TypedEnum_to_cpp(value)

cdef extern from "src/gen-cpp2/module_types_custom_protocol.h" namespace "cpp2":
    # Forward Declaration
    cdef cppclass cMyUnion "cpp2::MyUnion"
    # Forward Declaration
    cdef cppclass cMyField "cpp2::MyField"
    # Forward Declaration
    cdef cppclass cMyStruct "cpp2::MyStruct"
    # Forward Declaration
    cdef cppclass cStructWithUnion "cpp2::StructWithUnion"
    # Forward Declaration
    cdef cppclass cRecursiveStruct "cpp2::RecursiveStruct"
    # Forward Declaration
    cdef cppclass cStructWithContainers "cpp2::StructWithContainers"
    # Forward Declaration
    cdef cppclass cStructWithSharedConst "cpp2::StructWithSharedConst"
    # Forward Declaration
    cdef cppclass cEmpty "cpp2::Empty"
    # Forward Declaration
    cdef cppclass cStructWithRef "cpp2::StructWithRef"
    # Forward Declaration
    cdef cppclass cStructWithRefTypeUnique "cpp2::StructWithRefTypeUnique"
    # Forward Declaration
    cdef cppclass cStructWithRefTypeShared "cpp2::StructWithRefTypeShared"
    # Forward Declaration
    cdef cppclass cStructWithRefTypeSharedConst "cpp2::StructWithRefTypeSharedConst"

cdef extern from "src/gen-cpp2/module_types.h" namespace "cpp2":
    cdef enum cMyUnion__type "cpp2::MyUnion::Type":
        cMyUnion__type___EMPTY__ "cpp2::MyUnion::Type::__EMPTY__",
        cMyUnion__type_anInteger "cpp2::MyUnion::Type::anInteger",
        cMyUnion__type_aString "cpp2::MyUnion::Type::aString",

    cdef cppclass cMyUnion "cpp2::MyUnion":
        cMyUnion() except +
        cMyUnion(const cMyUnion&) except +
        bint operator==(cMyUnion&)
        cMyUnion__type getType() const
        const int32_t& get_anInteger() const
        int32_t& set_anInteger(const int32_t&)
        const string& get_aString() const
        string& set_aString(const string&)

    cdef cppclass cMyField__isset "cpp2::MyField::__isset":
        bint opt_value
        bint value
        bint req_value

    cdef cppclass cMyField "cpp2::MyField":
        cMyField() except +
        cMyField(const cMyField&) except +
        bint operator==(cMyField&)
        int64_t opt_value
        int64_t value
        int64_t req_value
        cMyField__isset __isset

    cdef cppclass cMyStruct__isset "cpp2::MyStruct::__isset":
        bint opt_ref
        bint ref
        bint req_ref

    cdef cppclass cMyStruct "cpp2::MyStruct":
        cMyStruct() except +
        cMyStruct(const cMyStruct&) except +
        bint operator==(cMyStruct&)
        unique_ptr[cMyField] opt_ref
        unique_ptr[cMyField] ref
        unique_ptr[cMyField] req_ref
        cMyStruct__isset __isset

    cdef cppclass cStructWithUnion__isset "cpp2::StructWithUnion::__isset":
        bint u
        bint aDouble
        bint f

    cdef cppclass cStructWithUnion "cpp2::StructWithUnion":
        cStructWithUnion() except +
        cStructWithUnion(const cStructWithUnion&) except +
        bint operator==(cStructWithUnion&)
        unique_ptr[cMyUnion] u
        double aDouble
        cMyField f
        cStructWithUnion__isset __isset

    cdef cppclass cRecursiveStruct__isset "cpp2::RecursiveStruct::__isset":
        bint mes

    cdef cppclass cRecursiveStruct "cpp2::RecursiveStruct":
        cRecursiveStruct() except +
        cRecursiveStruct(const cRecursiveStruct&) except +
        bint operator==(cRecursiveStruct&)
        vector[cRecursiveStruct] mes
        cRecursiveStruct__isset __isset

    cdef cppclass cStructWithContainers__isset "cpp2::StructWithContainers::__isset":
        bint list_ref
        bint set_ref
        bint map_ref
        bint list_ref_unique
        bint set_ref_shared
        bint list_ref_shared_const

    cdef cppclass cStructWithContainers "cpp2::StructWithContainers":
        cStructWithContainers() except +
        cStructWithContainers(const cStructWithContainers&) except +
        bint operator==(cStructWithContainers&)
        unique_ptr[vector[int32_t]] list_ref
        unique_ptr[cset[int32_t]] set_ref
        unique_ptr[cmap[int32_t,int32_t]] map_ref
        unique_ptr[vector[int32_t]] list_ref_unique
        shared_ptr[cset[int32_t]] set_ref_shared
        shared_ptr[const vector[int32_t]] list_ref_shared_const
        cStructWithContainers__isset __isset

    cdef cppclass cStructWithSharedConst__isset "cpp2::StructWithSharedConst::__isset":
        bint opt_shared_const
        bint shared_const
        bint req_shared_const

    cdef cppclass cStructWithSharedConst "cpp2::StructWithSharedConst":
        cStructWithSharedConst() except +
        cStructWithSharedConst(const cStructWithSharedConst&) except +
        bint operator==(cStructWithSharedConst&)
        shared_ptr[const cMyField] opt_shared_const
        shared_ptr[const cMyField] shared_const
        shared_ptr[const cMyField] req_shared_const
        cStructWithSharedConst__isset __isset

    cdef cppclass cEmpty__isset "cpp2::Empty::__isset":
        pass

    cdef cppclass cEmpty "cpp2::Empty":
        cEmpty() except +
        cEmpty(const cEmpty&) except +
        bint operator==(cEmpty&)
        cEmpty__isset __isset

    cdef cppclass cStructWithRef__isset "cpp2::StructWithRef::__isset":
        bint def_field
        bint opt_field
        bint req_field

    cdef cppclass cStructWithRef "cpp2::StructWithRef":
        cStructWithRef() except +
        cStructWithRef(const cStructWithRef&) except +
        bint operator==(cStructWithRef&)
        unique_ptr[cEmpty] def_field
        unique_ptr[cEmpty] opt_field
        unique_ptr[cEmpty] req_field
        cStructWithRef__isset __isset

    cdef cppclass cStructWithRefTypeUnique__isset "cpp2::StructWithRefTypeUnique::__isset":
        bint def_field
        bint opt_field
        bint req_field

    cdef cppclass cStructWithRefTypeUnique "cpp2::StructWithRefTypeUnique":
        cStructWithRefTypeUnique() except +
        cStructWithRefTypeUnique(const cStructWithRefTypeUnique&) except +
        bint operator==(cStructWithRefTypeUnique&)
        unique_ptr[cEmpty] def_field
        unique_ptr[cEmpty] opt_field
        unique_ptr[cEmpty] req_field
        cStructWithRefTypeUnique__isset __isset

    cdef cppclass cStructWithRefTypeShared__isset "cpp2::StructWithRefTypeShared::__isset":
        bint def_field
        bint opt_field
        bint req_field

    cdef cppclass cStructWithRefTypeShared "cpp2::StructWithRefTypeShared":
        cStructWithRefTypeShared() except +
        cStructWithRefTypeShared(const cStructWithRefTypeShared&) except +
        bint operator==(cStructWithRefTypeShared&)
        shared_ptr[cEmpty] def_field
        shared_ptr[cEmpty] opt_field
        shared_ptr[cEmpty] req_field
        cStructWithRefTypeShared__isset __isset

    cdef cppclass cStructWithRefTypeSharedConst__isset "cpp2::StructWithRefTypeSharedConst::__isset":
        bint def_field
        bint opt_field
        bint req_field

    cdef cppclass cStructWithRefTypeSharedConst "cpp2::StructWithRefTypeSharedConst":
        cStructWithRefTypeSharedConst() except +
        cStructWithRefTypeSharedConst(const cStructWithRefTypeSharedConst&) except +
        bint operator==(cStructWithRefTypeSharedConst&)
        shared_ptr[const cEmpty] def_field
        shared_ptr[const cEmpty] opt_field
        shared_ptr[const cEmpty] req_field
        cStructWithRefTypeSharedConst__isset __isset

    cdef shared_ptr[cMyField] aliasing_constructor_opt_ref "std::shared_ptr<cpp2::MyField>"(shared_ptr[cMyStruct]&, cMyField*)
    cdef shared_ptr[cMyField] aliasing_constructor_ref "std::shared_ptr<cpp2::MyField>"(shared_ptr[cMyStruct]&, cMyField*)
    cdef shared_ptr[cMyField] aliasing_constructor_req_ref "std::shared_ptr<cpp2::MyField>"(shared_ptr[cMyStruct]&, cMyField*)
    cdef shared_ptr[cMyUnion] aliasing_constructor_u "std::shared_ptr<cpp2::MyUnion>"(shared_ptr[cStructWithUnion]&, cMyUnion*)
    cdef shared_ptr[vector[int32_t]] aliasing_constructor_list_ref "std::shared_ptr<std::vector<int32_t>>"(shared_ptr[cStructWithContainers]&, vector[int32_t]*)
    cdef shared_ptr[cset[int32_t]] aliasing_constructor_set_ref "std::shared_ptr<std::set<int32_t>>"(shared_ptr[cStructWithContainers]&, cset[int32_t]*)
    cdef shared_ptr[cmap[int32_t,int32_t]] aliasing_constructor_map_ref "std::shared_ptr<std::map<int32_t,int32_t>>"(shared_ptr[cStructWithContainers]&, cmap[int32_t,int32_t]*)
    cdef shared_ptr[vector[int32_t]] aliasing_constructor_list_ref_unique "std::shared_ptr<std::vector<int32_t>>"(shared_ptr[cStructWithContainers]&, vector[int32_t]*)
    cdef shared_ptr[cset[int32_t]] aliasing_constructor_set_ref_shared "std::shared_ptr<std::set<int32_t>>"(shared_ptr[cStructWithContainers]&, cset[int32_t]*)
    cdef shared_ptr[vector[int32_t]] aliasing_constructor_list_ref_shared_const "std::shared_ptr<std::vector<int32_t>>"(shared_ptr[cStructWithContainers]&, vector[int32_t]*)
    cdef shared_ptr[cMyField] aliasing_constructor_opt_shared_const "std::shared_ptr<cpp2::MyField>"(shared_ptr[cStructWithSharedConst]&, cMyField*)
    cdef shared_ptr[cMyField] aliasing_constructor_shared_const "std::shared_ptr<cpp2::MyField>"(shared_ptr[cStructWithSharedConst]&, cMyField*)
    cdef shared_ptr[cMyField] aliasing_constructor_req_shared_const "std::shared_ptr<cpp2::MyField>"(shared_ptr[cStructWithSharedConst]&, cMyField*)
    cdef shared_ptr[cEmpty] aliasing_constructor_def_field "std::shared_ptr<cpp2::Empty>"(shared_ptr[cStructWithRef]&, cEmpty*)
    cdef shared_ptr[cEmpty] aliasing_constructor_opt_field "std::shared_ptr<cpp2::Empty>"(shared_ptr[cStructWithRef]&, cEmpty*)
    cdef shared_ptr[cEmpty] aliasing_constructor_req_field "std::shared_ptr<cpp2::Empty>"(shared_ptr[cStructWithRef]&, cEmpty*)
    cdef shared_ptr[cEmpty] aliasing_constructor_def_field "std::shared_ptr<cpp2::Empty>"(shared_ptr[cStructWithRefTypeUnique]&, cEmpty*)
    cdef shared_ptr[cEmpty] aliasing_constructor_opt_field "std::shared_ptr<cpp2::Empty>"(shared_ptr[cStructWithRefTypeUnique]&, cEmpty*)
    cdef shared_ptr[cEmpty] aliasing_constructor_req_field "std::shared_ptr<cpp2::Empty>"(shared_ptr[cStructWithRefTypeUnique]&, cEmpty*)
    cdef shared_ptr[cEmpty] aliasing_constructor_def_field "std::shared_ptr<cpp2::Empty>"(shared_ptr[cStructWithRefTypeShared]&, cEmpty*)
    cdef shared_ptr[cEmpty] aliasing_constructor_opt_field "std::shared_ptr<cpp2::Empty>"(shared_ptr[cStructWithRefTypeShared]&, cEmpty*)
    cdef shared_ptr[cEmpty] aliasing_constructor_req_field "std::shared_ptr<cpp2::Empty>"(shared_ptr[cStructWithRefTypeShared]&, cEmpty*)
    cdef shared_ptr[cEmpty] aliasing_constructor_def_field "std::shared_ptr<cpp2::Empty>"(shared_ptr[cStructWithRefTypeSharedConst]&, cEmpty*)
    cdef shared_ptr[cEmpty] aliasing_constructor_opt_field "std::shared_ptr<cpp2::Empty>"(shared_ptr[cStructWithRefTypeSharedConst]&, cEmpty*)
    cdef shared_ptr[cEmpty] aliasing_constructor_req_field "std::shared_ptr<cpp2::Empty>"(shared_ptr[cStructWithRefTypeSharedConst]&, cEmpty*)

cdef extern from "<utility>" namespace "std" nogil:
    cdef shared_ptr[cMyUnion] move(unique_ptr[cMyUnion])
    cdef shared_ptr[cMyUnion] move_shared "std::move"(shared_ptr[cMyUnion])
    cdef unique_ptr[cMyUnion] move_unique "std::move"(unique_ptr[cMyUnion])
    cdef shared_ptr[cMyField] move(unique_ptr[cMyField])
    cdef shared_ptr[cMyField] move_shared "std::move"(shared_ptr[cMyField])
    cdef unique_ptr[cMyField] move_unique "std::move"(unique_ptr[cMyField])
    cdef shared_ptr[cMyStruct] move(unique_ptr[cMyStruct])
    cdef shared_ptr[cMyStruct] move_shared "std::move"(shared_ptr[cMyStruct])
    cdef unique_ptr[cMyStruct] move_unique "std::move"(unique_ptr[cMyStruct])
    cdef shared_ptr[cStructWithUnion] move(unique_ptr[cStructWithUnion])
    cdef shared_ptr[cStructWithUnion] move_shared "std::move"(shared_ptr[cStructWithUnion])
    cdef unique_ptr[cStructWithUnion] move_unique "std::move"(unique_ptr[cStructWithUnion])
    cdef shared_ptr[cRecursiveStruct] move(unique_ptr[cRecursiveStruct])
    cdef shared_ptr[cRecursiveStruct] move_shared "std::move"(shared_ptr[cRecursiveStruct])
    cdef unique_ptr[cRecursiveStruct] move_unique "std::move"(unique_ptr[cRecursiveStruct])
    cdef shared_ptr[cStructWithContainers] move(unique_ptr[cStructWithContainers])
    cdef shared_ptr[cStructWithContainers] move_shared "std::move"(shared_ptr[cStructWithContainers])
    cdef unique_ptr[cStructWithContainers] move_unique "std::move"(unique_ptr[cStructWithContainers])
    cdef shared_ptr[cStructWithSharedConst] move(unique_ptr[cStructWithSharedConst])
    cdef shared_ptr[cStructWithSharedConst] move_shared "std::move"(shared_ptr[cStructWithSharedConst])
    cdef unique_ptr[cStructWithSharedConst] move_unique "std::move"(unique_ptr[cStructWithSharedConst])
    cdef shared_ptr[cEmpty] move(unique_ptr[cEmpty])
    cdef shared_ptr[cEmpty] move_shared "std::move"(shared_ptr[cEmpty])
    cdef unique_ptr[cEmpty] move_unique "std::move"(unique_ptr[cEmpty])
    cdef shared_ptr[cStructWithRef] move(unique_ptr[cStructWithRef])
    cdef shared_ptr[cStructWithRef] move_shared "std::move"(shared_ptr[cStructWithRef])
    cdef unique_ptr[cStructWithRef] move_unique "std::move"(unique_ptr[cStructWithRef])
    cdef shared_ptr[cStructWithRefTypeUnique] move(unique_ptr[cStructWithRefTypeUnique])
    cdef shared_ptr[cStructWithRefTypeUnique] move_shared "std::move"(shared_ptr[cStructWithRefTypeUnique])
    cdef unique_ptr[cStructWithRefTypeUnique] move_unique "std::move"(unique_ptr[cStructWithRefTypeUnique])
    cdef shared_ptr[cStructWithRefTypeShared] move(unique_ptr[cStructWithRefTypeShared])
    cdef shared_ptr[cStructWithRefTypeShared] move_shared "std::move"(shared_ptr[cStructWithRefTypeShared])
    cdef unique_ptr[cStructWithRefTypeShared] move_unique "std::move"(unique_ptr[cStructWithRefTypeShared])
    cdef shared_ptr[cStructWithRefTypeSharedConst] move(unique_ptr[cStructWithRefTypeSharedConst])
    cdef shared_ptr[cStructWithRefTypeSharedConst] move_shared "std::move"(shared_ptr[cStructWithRefTypeSharedConst])
    cdef unique_ptr[cStructWithRefTypeSharedConst] move_unique "std::move"(unique_ptr[cStructWithRefTypeSharedConst])

cdef extern from "<memory>" namespace "std" nogil:
    cdef shared_ptr[const cMyUnion] const_pointer_cast "std::const_pointer_cast<const cpp2::MyUnion>"(shared_ptr[cMyUnion])
    cdef shared_ptr[const cMyField] const_pointer_cast "std::const_pointer_cast<const cpp2::MyField>"(shared_ptr[cMyField])
    cdef shared_ptr[const cMyStruct] const_pointer_cast "std::const_pointer_cast<const cpp2::MyStruct>"(shared_ptr[cMyStruct])
    cdef shared_ptr[const cStructWithUnion] const_pointer_cast "std::const_pointer_cast<const cpp2::StructWithUnion>"(shared_ptr[cStructWithUnion])
    cdef shared_ptr[const cRecursiveStruct] const_pointer_cast "std::const_pointer_cast<const cpp2::RecursiveStruct>"(shared_ptr[cRecursiveStruct])
    cdef shared_ptr[const cStructWithContainers] const_pointer_cast "std::const_pointer_cast<const cpp2::StructWithContainers>"(shared_ptr[cStructWithContainers])
    cdef shared_ptr[const cStructWithSharedConst] const_pointer_cast "std::const_pointer_cast<const cpp2::StructWithSharedConst>"(shared_ptr[cStructWithSharedConst])
    cdef shared_ptr[const cEmpty] const_pointer_cast "std::const_pointer_cast<const cpp2::Empty>"(shared_ptr[cEmpty])
    cdef shared_ptr[const cStructWithRef] const_pointer_cast "std::const_pointer_cast<const cpp2::StructWithRef>"(shared_ptr[cStructWithRef])
    cdef shared_ptr[const cStructWithRefTypeUnique] const_pointer_cast "std::const_pointer_cast<const cpp2::StructWithRefTypeUnique>"(shared_ptr[cStructWithRefTypeUnique])
    cdef shared_ptr[const cStructWithRefTypeShared] const_pointer_cast "std::const_pointer_cast<const cpp2::StructWithRefTypeShared>"(shared_ptr[cStructWithRefTypeShared])
    cdef shared_ptr[const cStructWithRefTypeSharedConst] const_pointer_cast "std::const_pointer_cast<const cpp2::StructWithRefTypeSharedConst>"(shared_ptr[cStructWithRefTypeSharedConst])

# Forward Definition of the cython struct
cdef class MyUnion(thrift.py3.types.Union)

cdef class MyUnion(thrift.py3.types.Union):
    cdef object __hash
    cdef object __weakref__
    cdef shared_ptr[cMyUnion] _cpp_obj
    cdef readonly object type
    cdef readonly object value
    cdef _load_cache(MyUnion self)

    @staticmethod
    cdef unique_ptr[cMyUnion] _make_instance(
        cMyUnion* base_instance,
        object anInteger,
        object aString
    ) except *

    @staticmethod
    cdef create(shared_ptr[cMyUnion])

# Forward Definition of the cython struct
cdef class MyField(thrift.py3.types.Struct)

cdef class MyField(thrift.py3.types.Struct):
    cdef object __hash
    cdef object __weakref__
    cdef shared_ptr[cMyField] _cpp_obj

    @staticmethod
    cdef unique_ptr[cMyField] _make_instance(
        cMyField* base_instance,
        object opt_value,
        object value,
        object req_value
    ) except *

    @staticmethod
    cdef create(shared_ptr[cMyField])

# Forward Definition of the cython struct
cdef class MyStruct(thrift.py3.types.Struct)

cdef class MyStruct(thrift.py3.types.Struct):
    cdef object __hash
    cdef object __weakref__
    cdef shared_ptr[cMyStruct] _cpp_obj
    cdef MyField __opt_ref
    cdef MyField __ref
    cdef MyField __req_ref

    @staticmethod
    cdef unique_ptr[cMyStruct] _make_instance(
        cMyStruct* base_instance,
        object opt_ref,
        object ref,
        object req_ref
    ) except *

    @staticmethod
    cdef create(shared_ptr[cMyStruct])

# Forward Definition of the cython struct
cdef class StructWithUnion(thrift.py3.types.Struct)

cdef class StructWithUnion(thrift.py3.types.Struct):
    cdef object __hash
    cdef object __weakref__
    cdef shared_ptr[cStructWithUnion] _cpp_obj
    cdef MyUnion __u
    cdef MyField __f

    @staticmethod
    cdef unique_ptr[cStructWithUnion] _make_instance(
        cStructWithUnion* base_instance,
        object u,
        object aDouble,
        object f
    ) except *

    @staticmethod
    cdef create(shared_ptr[cStructWithUnion])

# Forward Definition of the cython struct
cdef class RecursiveStruct(thrift.py3.types.Struct)

cdef class RecursiveStruct(thrift.py3.types.Struct):
    cdef object __hash
    cdef object __weakref__
    cdef shared_ptr[cRecursiveStruct] _cpp_obj
    cdef List__RecursiveStruct __mes

    @staticmethod
    cdef unique_ptr[cRecursiveStruct] _make_instance(
        cRecursiveStruct* base_instance,
        object mes
    ) except *

    @staticmethod
    cdef create(shared_ptr[cRecursiveStruct])

# Forward Definition of the cython struct
cdef class StructWithContainers(thrift.py3.types.Struct)

cdef class StructWithContainers(thrift.py3.types.Struct):
    cdef object __hash
    cdef object __weakref__
    cdef shared_ptr[cStructWithContainers] _cpp_obj
    cdef List__i32 __list_ref
    cdef Set__i32 __set_ref
    cdef Map__i32_i32 __map_ref
    cdef List__i32 __list_ref_unique
    cdef Set__i32 __set_ref_shared
    cdef List__i32 __list_ref_shared_const

    @staticmethod
    cdef unique_ptr[cStructWithContainers] _make_instance(
        cStructWithContainers* base_instance,
        object list_ref,
        object set_ref,
        object map_ref,
        object list_ref_unique,
        object set_ref_shared,
        object list_ref_shared_const
    ) except *

    @staticmethod
    cdef create(shared_ptr[cStructWithContainers])

# Forward Definition of the cython struct
cdef class StructWithSharedConst(thrift.py3.types.Struct)

cdef class StructWithSharedConst(thrift.py3.types.Struct):
    cdef object __hash
    cdef object __weakref__
    cdef shared_ptr[cStructWithSharedConst] _cpp_obj
    cdef MyField __opt_shared_const
    cdef MyField __shared_const
    cdef MyField __req_shared_const

    @staticmethod
    cdef unique_ptr[cStructWithSharedConst] _make_instance(
        cStructWithSharedConst* base_instance,
        object opt_shared_const,
        object shared_const,
        object req_shared_const
    ) except *

    @staticmethod
    cdef create(shared_ptr[cStructWithSharedConst])

# Forward Definition of the cython struct
cdef class Empty(thrift.py3.types.Struct)

cdef class Empty(thrift.py3.types.Struct):
    cdef object __hash
    cdef object __weakref__
    cdef shared_ptr[cEmpty] _cpp_obj

    @staticmethod
    cdef unique_ptr[cEmpty] _make_instance(
        cEmpty* base_instance
    ) except *

    @staticmethod
    cdef create(shared_ptr[cEmpty])

# Forward Definition of the cython struct
cdef class StructWithRef(thrift.py3.types.Struct)

cdef class StructWithRef(thrift.py3.types.Struct):
    cdef object __hash
    cdef object __weakref__
    cdef shared_ptr[cStructWithRef] _cpp_obj
    cdef Empty __def_field
    cdef Empty __opt_field
    cdef Empty __req_field

    @staticmethod
    cdef unique_ptr[cStructWithRef] _make_instance(
        cStructWithRef* base_instance,
        object def_field,
        object opt_field,
        object req_field
    ) except *

    @staticmethod
    cdef create(shared_ptr[cStructWithRef])

# Forward Definition of the cython struct
cdef class StructWithRefTypeUnique(thrift.py3.types.Struct)

cdef class StructWithRefTypeUnique(thrift.py3.types.Struct):
    cdef object __hash
    cdef object __weakref__
    cdef shared_ptr[cStructWithRefTypeUnique] _cpp_obj
    cdef Empty __def_field
    cdef Empty __opt_field
    cdef Empty __req_field

    @staticmethod
    cdef unique_ptr[cStructWithRefTypeUnique] _make_instance(
        cStructWithRefTypeUnique* base_instance,
        object def_field,
        object opt_field,
        object req_field
    ) except *

    @staticmethod
    cdef create(shared_ptr[cStructWithRefTypeUnique])

# Forward Definition of the cython struct
cdef class StructWithRefTypeShared(thrift.py3.types.Struct)

cdef class StructWithRefTypeShared(thrift.py3.types.Struct):
    cdef object __hash
    cdef object __weakref__
    cdef shared_ptr[cStructWithRefTypeShared] _cpp_obj
    cdef Empty __def_field
    cdef Empty __opt_field
    cdef Empty __req_field

    @staticmethod
    cdef unique_ptr[cStructWithRefTypeShared] _make_instance(
        cStructWithRefTypeShared* base_instance,
        object def_field,
        object opt_field,
        object req_field
    ) except *

    @staticmethod
    cdef create(shared_ptr[cStructWithRefTypeShared])

# Forward Definition of the cython struct
cdef class StructWithRefTypeSharedConst(thrift.py3.types.Struct)

cdef class StructWithRefTypeSharedConst(thrift.py3.types.Struct):
    cdef object __hash
    cdef object __weakref__
    cdef shared_ptr[cStructWithRefTypeSharedConst] _cpp_obj
    cdef Empty __def_field
    cdef Empty __opt_field
    cdef Empty __req_field

    @staticmethod
    cdef unique_ptr[cStructWithRefTypeSharedConst] _make_instance(
        cStructWithRefTypeSharedConst* base_instance,
        object def_field,
        object opt_field,
        object req_field
    ) except *

    @staticmethod
    cdef create(shared_ptr[cStructWithRefTypeSharedConst])


cdef class List__RecursiveStruct:
    cdef object __hash
    cdef object __weakref__
    cdef shared_ptr[vector[cRecursiveStruct]] _cpp_obj
    @staticmethod
    cdef create(shared_ptr[vector[cRecursiveStruct]])
    @staticmethod
    cdef unique_ptr[vector[cRecursiveStruct]] _make_instance(object items) except *

cdef class List__i32:
    cdef object __hash
    cdef object __weakref__
    cdef shared_ptr[vector[int32_t]] _cpp_obj
    @staticmethod
    cdef create(shared_ptr[vector[int32_t]])
    @staticmethod
    cdef unique_ptr[vector[int32_t]] _make_instance(object items) except *

cdef class Set__i32:
    cdef object __hash
    cdef object __weakref__
    cdef shared_ptr[cset[int32_t]] _cpp_obj
    @staticmethod
    cdef create(shared_ptr[cset[int32_t]])
    @staticmethod
    cdef unique_ptr[cset[int32_t]] _make_instance(object items) except *

cdef class Map__i32_i32:
    cdef object __hash
    cdef object __weakref__
    cdef shared_ptr[cmap[int32_t,int32_t]] _cpp_obj
    @staticmethod
    cdef create(shared_ptr[cmap[int32_t,int32_t]])
    @staticmethod
    cdef unique_ptr[cmap[int32_t,int32_t]] _make_instance(object items) except *

cdef extern from "<utility>" namespace "std" nogil:
    cdef shared_ptr[vector[cRecursiveStruct]] move(unique_ptr[vector[cRecursiveStruct]])
    cdef unique_ptr[vector[cRecursiveStruct]] move_unique "std::move"(unique_ptr[vector[cRecursiveStruct]])
    cdef shared_ptr[vector[int32_t]] move(unique_ptr[vector[int32_t]])
    cdef unique_ptr[vector[int32_t]] move_unique "std::move"(unique_ptr[vector[int32_t]])
    cdef shared_ptr[cset[int32_t]] move(unique_ptr[cset[int32_t]])
    cdef unique_ptr[cset[int32_t]] move_unique "std::move"(unique_ptr[cset[int32_t]])
    cdef shared_ptr[cmap[int32_t,int32_t]] move(unique_ptr[cmap[int32_t,int32_t]])
    cdef unique_ptr[cmap[int32_t,int32_t]] move_unique "std::move"(unique_ptr[cmap[int32_t,int32_t]])
cdef extern from "<memory>" namespace "std" nogil:
    cdef shared_ptr[const vector[cRecursiveStruct]] const_pointer_cast "std::const_pointer_cast"(shared_ptr[vector[cRecursiveStruct]])

    cdef shared_ptr[const vector[int32_t]] const_pointer_cast "std::const_pointer_cast"(shared_ptr[vector[int32_t]])

    cdef shared_ptr[const cset[int32_t]] const_pointer_cast "std::const_pointer_cast"(shared_ptr[cset[int32_t]])

    cdef shared_ptr[const cmap[int32_t,int32_t]] const_pointer_cast "std::const_pointer_cast"(shared_ptr[cmap[int32_t,int32_t]])

cdef extern from "src/gen-cpp2/module_constants.h" namespace "cpp2":
    cdef cStructWithRef ckStructWithRef "cpp2::module_constants::kStructWithRef"()
    cdef cStructWithRefTypeUnique ckStructWithRefTypeUnique "cpp2::module_constants::kStructWithRefTypeUnique"()
    cdef cStructWithRefTypeShared ckStructWithRefTypeShared "cpp2::module_constants::kStructWithRefTypeShared"()
    cdef cStructWithRefTypeSharedConst ckStructWithRefTypeSharedConst "cpp2::module_constants::kStructWithRefTypeSharedConst"()