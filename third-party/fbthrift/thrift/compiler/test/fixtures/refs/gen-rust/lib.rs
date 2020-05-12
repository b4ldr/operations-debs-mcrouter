// @generated by Thrift. This file is probably not the place you want to edit!

#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

pub use self::consts::*;
pub use self::errors::*;
pub use self::types::*;

pub mod consts {
    lazy_static::lazy_static! {
        pub static ref kStructWithRef: crate::types::StructWithRef = crate::types::StructWithRef {
            def_field: crate::types::Empty {
            },
            opt_field: Some(crate::types::Empty {
            }),
            req_field: crate::types::Empty {
            },
        };
    }

    lazy_static::lazy_static! {
        pub static ref kStructWithRefTypeUnique: crate::types::StructWithRefTypeUnique = crate::types::StructWithRefTypeUnique {
            def_field: crate::types::Empty {
            },
            opt_field: Some(crate::types::Empty {
            }),
            req_field: crate::types::Empty {
            },
        };
    }

    lazy_static::lazy_static! {
        pub static ref kStructWithRefTypeShared: crate::types::StructWithRefTypeShared = crate::types::StructWithRefTypeShared {
            def_field: crate::types::Empty {
            },
            opt_field: Some(crate::types::Empty {
            }),
            req_field: crate::types::Empty {
            },
        };
    }

    lazy_static::lazy_static! {
        pub static ref kStructWithRefTypeSharedConst: crate::types::StructWithRefTypeSharedConst = crate::types::StructWithRefTypeSharedConst {
            def_field: crate::types::Empty {
            },
            opt_field: Some(crate::types::Empty {
            }),
            req_field: crate::types::Empty {
            },
        };
    }
}

pub mod types {
    #![allow(clippy::redundant_closure)]

    use fbthrift::{
        Deserialize, GetTType, ProtocolReader, ProtocolWriter, Serialize, TType,
    };

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum MyUnion {
        anInteger(i32),
        aString(String),
        UnknownField(i32),
    }

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct MyField {
        pub opt_value: Option<i64>,
        pub value: i64,
        pub req_value: i64,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct MyStruct {
        pub opt_ref: Option<crate::types::MyField>,
        pub ref_: crate::types::MyField,
        pub req_ref: crate::types::MyField,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct StructWithUnion {
        pub u: crate::types::MyUnion,
        pub aDouble: f64,
        pub f: crate::types::MyField,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct RecursiveStruct {
        pub mes: Option<Vec<crate::types::RecursiveStruct>>,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct StructWithContainers {
        pub list_ref: Vec<i32>,
        pub set_ref: std::collections::BTreeSet<i32>,
        pub map_ref: std::collections::BTreeMap<i32, i32>,
        pub list_ref_unique: Vec<i32>,
        pub set_ref_shared: std::collections::BTreeSet<i32>,
        pub list_ref_shared_const: Vec<i32>,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct StructWithSharedConst {
        pub opt_shared_const: Option<crate::types::MyField>,
        pub shared_const: crate::types::MyField,
        pub req_shared_const: crate::types::MyField,
    }

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Empty {
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct StructWithRef {
        pub def_field: crate::types::Empty,
        pub opt_field: Option<crate::types::Empty>,
        pub req_field: crate::types::Empty,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct StructWithRefTypeUnique {
        pub def_field: crate::types::Empty,
        pub opt_field: Option<crate::types::Empty>,
        pub req_field: crate::types::Empty,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct StructWithRefTypeShared {
        pub def_field: crate::types::Empty,
        pub opt_field: Option<crate::types::Empty>,
        pub req_field: crate::types::Empty,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct StructWithRefTypeSharedConst {
        pub def_field: crate::types::Empty,
        pub opt_field: Option<crate::types::Empty>,
        pub req_field: crate::types::Empty,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct StructWithRefAndAnnotCppNoexceptMoveCtor {
        pub def_field: crate::types::Empty,
    }

    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
    pub struct TypedEnum(pub i32);

    impl TypedEnum {
        pub const VAL1: Self = TypedEnum(0i32);
        pub const VAL2: Self = TypedEnum(1i32);
    }

    impl Default for TypedEnum {
        fn default() -> Self {
            TypedEnum(fbthrift::__UNKNOWN_ID)
        }
    }

    impl<'a> From<&'a TypedEnum> for i32 {
        #[inline]
        fn from(x: &'a TypedEnum) -> i32 {
            x.0
        }
    }

    impl From<TypedEnum> for i32 {
        #[inline]
        fn from(x: TypedEnum) -> i32 {
            x.0
        }
    }

    impl From<i32> for TypedEnum {
        #[inline]
        fn from(x: i32) -> Self {
            Self(x)
        }
    }

    impl std::fmt::Display for TypedEnum {
        fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
            let s: &str = match *self {
                TypedEnum::VAL1 => "VAL1",
                TypedEnum::VAL2 => "VAL2",
                TypedEnum(x) => return write!(fmt, "{}", x),
            };
            write!(fmt, "{}", s)
        }
    }

    impl std::fmt::Debug for TypedEnum {
        fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(fmt, "TypedEnum::{}", self)
        }
    }

    impl std::str::FromStr for TypedEnum {
        type Err = anyhow::Error;

        fn from_str(string: &str) -> std::result::Result<Self, Self::Err> {
            match string {
                "VAL1" => Ok(TypedEnum::VAL1),
                "VAL2" => Ok(TypedEnum::VAL2),
                _ => anyhow::bail!("Unable to parse {} as TypedEnum", string),
            }
        }
    }

    impl GetTType for TypedEnum {
        const TTYPE: TType = TType::I32;
    }

    impl<P: ProtocolWriter> Serialize<P> for TypedEnum {
        #[inline]
        fn write(&self, p: &mut P) {
            p.write_i32(self.into())
        }
    }

    impl<P: ProtocolReader> Deserialize<P> for TypedEnum {
        #[inline]
        fn read(p: &mut P) -> anyhow::Result<Self> {
            Ok(TypedEnum::from(p.read_i32()?))
        }
    }


    impl Default for MyUnion {
        fn default() -> Self {
            Self::UnknownField(-1)
        }
    }

    impl GetTType for MyUnion {
        const TTYPE: TType = TType::Struct;
    }

    impl<P: ProtocolWriter> Serialize<P> for MyUnion {
        fn write(&self, p: &mut P) {
            p.write_struct_begin("MyUnion");
            match self {
                MyUnion::anInteger(inner) => {
                    p.write_field_begin("anInteger", TType::I32, 1);
                    Serialize::write(inner, p);
                    p.write_field_end();
                }
                MyUnion::aString(inner) => {
                    p.write_field_begin("aString", TType::String, 2);
                    Serialize::write(inner, p);
                    p.write_field_end();
                }
                MyUnion::UnknownField(x) => {
                    p.write_field_begin("UnknownField", TType::I32, *x as i16);
                    x.write(p);
                    p.write_field_end();
                }
            }
            p.write_field_stop();
            p.write_struct_end();
        }
    }

    impl<P: ProtocolReader> Deserialize<P> for MyUnion {
        fn read(p: &mut P) -> anyhow::Result<Self> {
            let _ = p.read_struct_begin(|_| ())?;
            let mut once = false;
            let mut alt = None;
            loop {
                let (_, fty, fid) = p.read_field_begin(|_| ())?;
                match (fty, fid as i32, once) {
                    (TType::Stop, _, _) => break,
                    (TType::I32, 1, false) => {
                        once = true;
                        alt = Some(MyUnion::anInteger(Deserialize::read(p)?));
                    }
                    (TType::String, 2, false) => {
                        once = true;
                        alt = Some(MyUnion::aString(Deserialize::read(p)?));
                    }
                    (fty, _, false) => p.skip(fty)?,
                    (badty, badid, true) => return Err(From::from(::fbthrift::ApplicationException::new(
                        ::fbthrift::ApplicationExceptionErrorCode::ProtocolError,
                        format!(
                            "unwanted extra union {} field ty {:?} id {}",
                            "MyUnion",
                            badty,
                            badid,
                        ),
                    ))),
                }
                p.read_field_end()?;
            }
            p.read_struct_end()?;
            Ok(alt.unwrap_or_default())
        }
    }

    impl Default for self::MyField {
        fn default() -> Self {
            Self {
                opt_value: None,
                value: Default::default(),
                req_value: Default::default(),
            }
        }
    }

    impl GetTType for self::MyField {
        const TTYPE: TType = TType::Struct;
    }

    impl<P: ProtocolWriter> Serialize<P> for self::MyField {
        fn write(&self, p: &mut P) {
            p.write_struct_begin("MyField");
            if let Some(some) = &self.opt_value {
                p.write_field_begin("opt_value", TType::I64, 1);
                Serialize::write(some, p);
                p.write_field_end();
            }
            p.write_field_begin("value", TType::I64, 2);
            Serialize::write(&self.value, p);
            p.write_field_end();
            p.write_field_begin("req_value", TType::I64, 3);
            Serialize::write(&self.req_value, p);
            p.write_field_end();
            p.write_field_stop();
            p.write_struct_end();
        }
    }

    impl<P: ProtocolReader> Deserialize<P> for self::MyField {
        fn read(p: &mut P) -> anyhow::Result<Self> {
            let mut field_opt_value = None;
            let mut field_value = None;
            let mut field_req_value = None;
            let _ = p.read_struct_begin(|_| ())?;
            loop {
                let (_, fty, fid) = p.read_field_begin(|_| ())?;
                match (fty, fid as i32) {
                    (TType::Stop, _) => break,
                    (TType::I64, 1) => field_opt_value = Some(Deserialize::read(p)?),
                    (TType::I64, 2) => field_value = Some(Deserialize::read(p)?),
                    (TType::I64, 3) => field_req_value = Some(Deserialize::read(p)?),
                    (fty, _) => p.skip(fty)?,
                }
                p.read_field_end()?;
            }
            p.read_struct_end()?;
            Ok(Self {
                opt_value: field_opt_value,
                value: field_value.unwrap_or_default(),
                req_value: field_req_value.unwrap_or_default(),
            })
        }
    }


    impl Default for self::MyStruct {
        fn default() -> Self {
            Self {
                opt_ref: None,
                ref_: Default::default(),
                req_ref: Default::default(),
            }
        }
    }

    impl GetTType for self::MyStruct {
        const TTYPE: TType = TType::Struct;
    }

    impl<P: ProtocolWriter> Serialize<P> for self::MyStruct {
        fn write(&self, p: &mut P) {
            p.write_struct_begin("MyStruct");
            if let Some(some) = &self.opt_ref {
                p.write_field_begin("opt_ref", TType::Struct, 1);
                Serialize::write(some, p);
                p.write_field_end();
            }
            p.write_field_begin("ref", TType::Struct, 2);
            Serialize::write(&self.ref_, p);
            p.write_field_end();
            p.write_field_begin("req_ref", TType::Struct, 3);
            Serialize::write(&self.req_ref, p);
            p.write_field_end();
            p.write_field_stop();
            p.write_struct_end();
        }
    }

    impl<P: ProtocolReader> Deserialize<P> for self::MyStruct {
        fn read(p: &mut P) -> anyhow::Result<Self> {
            let mut field_opt_ref = None;
            let mut field_ref = None;
            let mut field_req_ref = None;
            let _ = p.read_struct_begin(|_| ())?;
            loop {
                let (_, fty, fid) = p.read_field_begin(|_| ())?;
                match (fty, fid as i32) {
                    (TType::Stop, _) => break,
                    (TType::Struct, 1) => field_opt_ref = Some(Deserialize::read(p)?),
                    (TType::Struct, 2) => field_ref = Some(Deserialize::read(p)?),
                    (TType::Struct, 3) => field_req_ref = Some(Deserialize::read(p)?),
                    (fty, _) => p.skip(fty)?,
                }
                p.read_field_end()?;
            }
            p.read_struct_end()?;
            Ok(Self {
                opt_ref: field_opt_ref,
                ref_: field_ref.unwrap_or_default(),
                req_ref: field_req_ref.unwrap_or_default(),
            })
        }
    }


    impl Default for self::StructWithUnion {
        fn default() -> Self {
            Self {
                u: Default::default(),
                aDouble: Default::default(),
                f: Default::default(),
            }
        }
    }

    impl GetTType for self::StructWithUnion {
        const TTYPE: TType = TType::Struct;
    }

    impl<P: ProtocolWriter> Serialize<P> for self::StructWithUnion {
        fn write(&self, p: &mut P) {
            p.write_struct_begin("StructWithUnion");
            p.write_field_begin("u", TType::Struct, 1);
            Serialize::write(&self.u, p);
            p.write_field_end();
            p.write_field_begin("aDouble", TType::Double, 2);
            Serialize::write(&self.aDouble, p);
            p.write_field_end();
            p.write_field_begin("f", TType::Struct, 3);
            Serialize::write(&self.f, p);
            p.write_field_end();
            p.write_field_stop();
            p.write_struct_end();
        }
    }

    impl<P: ProtocolReader> Deserialize<P> for self::StructWithUnion {
        fn read(p: &mut P) -> anyhow::Result<Self> {
            let mut field_u = None;
            let mut field_aDouble = None;
            let mut field_f = None;
            let _ = p.read_struct_begin(|_| ())?;
            loop {
                let (_, fty, fid) = p.read_field_begin(|_| ())?;
                match (fty, fid as i32) {
                    (TType::Stop, _) => break,
                    (TType::Struct, 1) => field_u = Some(Deserialize::read(p)?),
                    (TType::Double, 2) => field_aDouble = Some(Deserialize::read(p)?),
                    (TType::Struct, 3) => field_f = Some(Deserialize::read(p)?),
                    (fty, _) => p.skip(fty)?,
                }
                p.read_field_end()?;
            }
            p.read_struct_end()?;
            Ok(Self {
                u: field_u.unwrap_or_default(),
                aDouble: field_aDouble.unwrap_or_default(),
                f: field_f.unwrap_or_default(),
            })
        }
    }


    impl Default for self::RecursiveStruct {
        fn default() -> Self {
            Self {
                mes: None,
            }
        }
    }

    impl GetTType for self::RecursiveStruct {
        const TTYPE: TType = TType::Struct;
    }

    impl<P: ProtocolWriter> Serialize<P> for self::RecursiveStruct {
        fn write(&self, p: &mut P) {
            p.write_struct_begin("RecursiveStruct");
            if let Some(some) = &self.mes {
                p.write_field_begin("mes", TType::List, 1);
                Serialize::write(some, p);
                p.write_field_end();
            }
            p.write_field_stop();
            p.write_struct_end();
        }
    }

    impl<P: ProtocolReader> Deserialize<P> for self::RecursiveStruct {
        fn read(p: &mut P) -> anyhow::Result<Self> {
            let mut field_mes = None;
            let _ = p.read_struct_begin(|_| ())?;
            loop {
                let (_, fty, fid) = p.read_field_begin(|_| ())?;
                match (fty, fid as i32) {
                    (TType::Stop, _) => break,
                    (TType::List, 1) => field_mes = Some(Deserialize::read(p)?),
                    (fty, _) => p.skip(fty)?,
                }
                p.read_field_end()?;
            }
            p.read_struct_end()?;
            Ok(Self {
                mes: field_mes,
            })
        }
    }


    impl Default for self::StructWithContainers {
        fn default() -> Self {
            Self {
                list_ref: Default::default(),
                set_ref: Default::default(),
                map_ref: Default::default(),
                list_ref_unique: Default::default(),
                set_ref_shared: Default::default(),
                list_ref_shared_const: Default::default(),
            }
        }
    }

    impl GetTType for self::StructWithContainers {
        const TTYPE: TType = TType::Struct;
    }

    impl<P: ProtocolWriter> Serialize<P> for self::StructWithContainers {
        fn write(&self, p: &mut P) {
            p.write_struct_begin("StructWithContainers");
            p.write_field_begin("list_ref", TType::List, 1);
            Serialize::write(&self.list_ref, p);
            p.write_field_end();
            p.write_field_begin("set_ref", TType::Set, 2);
            Serialize::write(&self.set_ref, p);
            p.write_field_end();
            p.write_field_begin("map_ref", TType::Map, 3);
            Serialize::write(&self.map_ref, p);
            p.write_field_end();
            p.write_field_begin("list_ref_unique", TType::List, 4);
            Serialize::write(&self.list_ref_unique, p);
            p.write_field_end();
            p.write_field_begin("set_ref_shared", TType::Set, 5);
            Serialize::write(&self.set_ref_shared, p);
            p.write_field_end();
            p.write_field_begin("list_ref_shared_const", TType::List, 6);
            Serialize::write(&self.list_ref_shared_const, p);
            p.write_field_end();
            p.write_field_stop();
            p.write_struct_end();
        }
    }

    impl<P: ProtocolReader> Deserialize<P> for self::StructWithContainers {
        fn read(p: &mut P) -> anyhow::Result<Self> {
            let mut field_list_ref = None;
            let mut field_set_ref = None;
            let mut field_map_ref = None;
            let mut field_list_ref_unique = None;
            let mut field_set_ref_shared = None;
            let mut field_list_ref_shared_const = None;
            let _ = p.read_struct_begin(|_| ())?;
            loop {
                let (_, fty, fid) = p.read_field_begin(|_| ())?;
                match (fty, fid as i32) {
                    (TType::Stop, _) => break,
                    (TType::List, 1) => field_list_ref = Some(Deserialize::read(p)?),
                    (TType::Set, 2) => field_set_ref = Some(Deserialize::read(p)?),
                    (TType::Map, 3) => field_map_ref = Some(Deserialize::read(p)?),
                    (TType::List, 4) => field_list_ref_unique = Some(Deserialize::read(p)?),
                    (TType::Set, 5) => field_set_ref_shared = Some(Deserialize::read(p)?),
                    (TType::List, 6) => field_list_ref_shared_const = Some(Deserialize::read(p)?),
                    (fty, _) => p.skip(fty)?,
                }
                p.read_field_end()?;
            }
            p.read_struct_end()?;
            Ok(Self {
                list_ref: field_list_ref.unwrap_or_default(),
                set_ref: field_set_ref.unwrap_or_default(),
                map_ref: field_map_ref.unwrap_or_default(),
                list_ref_unique: field_list_ref_unique.unwrap_or_default(),
                set_ref_shared: field_set_ref_shared.unwrap_or_default(),
                list_ref_shared_const: field_list_ref_shared_const.unwrap_or_default(),
            })
        }
    }


    impl Default for self::StructWithSharedConst {
        fn default() -> Self {
            Self {
                opt_shared_const: None,
                shared_const: Default::default(),
                req_shared_const: Default::default(),
            }
        }
    }

    impl GetTType for self::StructWithSharedConst {
        const TTYPE: TType = TType::Struct;
    }

    impl<P: ProtocolWriter> Serialize<P> for self::StructWithSharedConst {
        fn write(&self, p: &mut P) {
            p.write_struct_begin("StructWithSharedConst");
            if let Some(some) = &self.opt_shared_const {
                p.write_field_begin("opt_shared_const", TType::Struct, 1);
                Serialize::write(some, p);
                p.write_field_end();
            }
            p.write_field_begin("shared_const", TType::Struct, 2);
            Serialize::write(&self.shared_const, p);
            p.write_field_end();
            p.write_field_begin("req_shared_const", TType::Struct, 3);
            Serialize::write(&self.req_shared_const, p);
            p.write_field_end();
            p.write_field_stop();
            p.write_struct_end();
        }
    }

    impl<P: ProtocolReader> Deserialize<P> for self::StructWithSharedConst {
        fn read(p: &mut P) -> anyhow::Result<Self> {
            let mut field_opt_shared_const = None;
            let mut field_shared_const = None;
            let mut field_req_shared_const = None;
            let _ = p.read_struct_begin(|_| ())?;
            loop {
                let (_, fty, fid) = p.read_field_begin(|_| ())?;
                match (fty, fid as i32) {
                    (TType::Stop, _) => break,
                    (TType::Struct, 1) => field_opt_shared_const = Some(Deserialize::read(p)?),
                    (TType::Struct, 2) => field_shared_const = Some(Deserialize::read(p)?),
                    (TType::Struct, 3) => field_req_shared_const = Some(Deserialize::read(p)?),
                    (fty, _) => p.skip(fty)?,
                }
                p.read_field_end()?;
            }
            p.read_struct_end()?;
            Ok(Self {
                opt_shared_const: field_opt_shared_const,
                shared_const: field_shared_const.unwrap_or_default(),
                req_shared_const: field_req_shared_const.unwrap_or_default(),
            })
        }
    }


    impl Default for self::Empty {
        fn default() -> Self {
            Self {
            }
        }
    }

    impl GetTType for self::Empty {
        const TTYPE: TType = TType::Struct;
    }

    impl<P: ProtocolWriter> Serialize<P> for self::Empty {
        fn write(&self, p: &mut P) {
            p.write_struct_begin("Empty");
            p.write_field_stop();
            p.write_struct_end();
        }
    }

    impl<P: ProtocolReader> Deserialize<P> for self::Empty {
        fn read(p: &mut P) -> anyhow::Result<Self> {
            let _ = p.read_struct_begin(|_| ())?;
            loop {
                let (_, fty, fid) = p.read_field_begin(|_| ())?;
                match (fty, fid as i32) {
                    (TType::Stop, _) => break,
                    (fty, _) => p.skip(fty)?,
                }
                p.read_field_end()?;
            }
            p.read_struct_end()?;
            Ok(Self {
            })
        }
    }


    impl Default for self::StructWithRef {
        fn default() -> Self {
            Self {
                def_field: Default::default(),
                opt_field: None,
                req_field: Default::default(),
            }
        }
    }

    impl GetTType for self::StructWithRef {
        const TTYPE: TType = TType::Struct;
    }

    impl<P: ProtocolWriter> Serialize<P> for self::StructWithRef {
        fn write(&self, p: &mut P) {
            p.write_struct_begin("StructWithRef");
            p.write_field_begin("def_field", TType::Struct, 1);
            Serialize::write(&self.def_field, p);
            p.write_field_end();
            if let Some(some) = &self.opt_field {
                p.write_field_begin("opt_field", TType::Struct, 2);
                Serialize::write(some, p);
                p.write_field_end();
            }
            p.write_field_begin("req_field", TType::Struct, 3);
            Serialize::write(&self.req_field, p);
            p.write_field_end();
            p.write_field_stop();
            p.write_struct_end();
        }
    }

    impl<P: ProtocolReader> Deserialize<P> for self::StructWithRef {
        fn read(p: &mut P) -> anyhow::Result<Self> {
            let mut field_def_field = None;
            let mut field_opt_field = None;
            let mut field_req_field = None;
            let _ = p.read_struct_begin(|_| ())?;
            loop {
                let (_, fty, fid) = p.read_field_begin(|_| ())?;
                match (fty, fid as i32) {
                    (TType::Stop, _) => break,
                    (TType::Struct, 1) => field_def_field = Some(Deserialize::read(p)?),
                    (TType::Struct, 2) => field_opt_field = Some(Deserialize::read(p)?),
                    (TType::Struct, 3) => field_req_field = Some(Deserialize::read(p)?),
                    (fty, _) => p.skip(fty)?,
                }
                p.read_field_end()?;
            }
            p.read_struct_end()?;
            Ok(Self {
                def_field: field_def_field.unwrap_or_default(),
                opt_field: field_opt_field,
                req_field: field_req_field.unwrap_or_default(),
            })
        }
    }


    impl Default for self::StructWithRefTypeUnique {
        fn default() -> Self {
            Self {
                def_field: Default::default(),
                opt_field: None,
                req_field: Default::default(),
            }
        }
    }

    impl GetTType for self::StructWithRefTypeUnique {
        const TTYPE: TType = TType::Struct;
    }

    impl<P: ProtocolWriter> Serialize<P> for self::StructWithRefTypeUnique {
        fn write(&self, p: &mut P) {
            p.write_struct_begin("StructWithRefTypeUnique");
            p.write_field_begin("def_field", TType::Struct, 1);
            Serialize::write(&self.def_field, p);
            p.write_field_end();
            if let Some(some) = &self.opt_field {
                p.write_field_begin("opt_field", TType::Struct, 2);
                Serialize::write(some, p);
                p.write_field_end();
            }
            p.write_field_begin("req_field", TType::Struct, 3);
            Serialize::write(&self.req_field, p);
            p.write_field_end();
            p.write_field_stop();
            p.write_struct_end();
        }
    }

    impl<P: ProtocolReader> Deserialize<P> for self::StructWithRefTypeUnique {
        fn read(p: &mut P) -> anyhow::Result<Self> {
            let mut field_def_field = None;
            let mut field_opt_field = None;
            let mut field_req_field = None;
            let _ = p.read_struct_begin(|_| ())?;
            loop {
                let (_, fty, fid) = p.read_field_begin(|_| ())?;
                match (fty, fid as i32) {
                    (TType::Stop, _) => break,
                    (TType::Struct, 1) => field_def_field = Some(Deserialize::read(p)?),
                    (TType::Struct, 2) => field_opt_field = Some(Deserialize::read(p)?),
                    (TType::Struct, 3) => field_req_field = Some(Deserialize::read(p)?),
                    (fty, _) => p.skip(fty)?,
                }
                p.read_field_end()?;
            }
            p.read_struct_end()?;
            Ok(Self {
                def_field: field_def_field.unwrap_or_default(),
                opt_field: field_opt_field,
                req_field: field_req_field.unwrap_or_default(),
            })
        }
    }


    impl Default for self::StructWithRefTypeShared {
        fn default() -> Self {
            Self {
                def_field: Default::default(),
                opt_field: None,
                req_field: Default::default(),
            }
        }
    }

    impl GetTType for self::StructWithRefTypeShared {
        const TTYPE: TType = TType::Struct;
    }

    impl<P: ProtocolWriter> Serialize<P> for self::StructWithRefTypeShared {
        fn write(&self, p: &mut P) {
            p.write_struct_begin("StructWithRefTypeShared");
            p.write_field_begin("def_field", TType::Struct, 1);
            Serialize::write(&self.def_field, p);
            p.write_field_end();
            if let Some(some) = &self.opt_field {
                p.write_field_begin("opt_field", TType::Struct, 2);
                Serialize::write(some, p);
                p.write_field_end();
            }
            p.write_field_begin("req_field", TType::Struct, 3);
            Serialize::write(&self.req_field, p);
            p.write_field_end();
            p.write_field_stop();
            p.write_struct_end();
        }
    }

    impl<P: ProtocolReader> Deserialize<P> for self::StructWithRefTypeShared {
        fn read(p: &mut P) -> anyhow::Result<Self> {
            let mut field_def_field = None;
            let mut field_opt_field = None;
            let mut field_req_field = None;
            let _ = p.read_struct_begin(|_| ())?;
            loop {
                let (_, fty, fid) = p.read_field_begin(|_| ())?;
                match (fty, fid as i32) {
                    (TType::Stop, _) => break,
                    (TType::Struct, 1) => field_def_field = Some(Deserialize::read(p)?),
                    (TType::Struct, 2) => field_opt_field = Some(Deserialize::read(p)?),
                    (TType::Struct, 3) => field_req_field = Some(Deserialize::read(p)?),
                    (fty, _) => p.skip(fty)?,
                }
                p.read_field_end()?;
            }
            p.read_struct_end()?;
            Ok(Self {
                def_field: field_def_field.unwrap_or_default(),
                opt_field: field_opt_field,
                req_field: field_req_field.unwrap_or_default(),
            })
        }
    }


    impl Default for self::StructWithRefTypeSharedConst {
        fn default() -> Self {
            Self {
                def_field: Default::default(),
                opt_field: None,
                req_field: Default::default(),
            }
        }
    }

    impl GetTType for self::StructWithRefTypeSharedConst {
        const TTYPE: TType = TType::Struct;
    }

    impl<P: ProtocolWriter> Serialize<P> for self::StructWithRefTypeSharedConst {
        fn write(&self, p: &mut P) {
            p.write_struct_begin("StructWithRefTypeSharedConst");
            p.write_field_begin("def_field", TType::Struct, 1);
            Serialize::write(&self.def_field, p);
            p.write_field_end();
            if let Some(some) = &self.opt_field {
                p.write_field_begin("opt_field", TType::Struct, 2);
                Serialize::write(some, p);
                p.write_field_end();
            }
            p.write_field_begin("req_field", TType::Struct, 3);
            Serialize::write(&self.req_field, p);
            p.write_field_end();
            p.write_field_stop();
            p.write_struct_end();
        }
    }

    impl<P: ProtocolReader> Deserialize<P> for self::StructWithRefTypeSharedConst {
        fn read(p: &mut P) -> anyhow::Result<Self> {
            let mut field_def_field = None;
            let mut field_opt_field = None;
            let mut field_req_field = None;
            let _ = p.read_struct_begin(|_| ())?;
            loop {
                let (_, fty, fid) = p.read_field_begin(|_| ())?;
                match (fty, fid as i32) {
                    (TType::Stop, _) => break,
                    (TType::Struct, 1) => field_def_field = Some(Deserialize::read(p)?),
                    (TType::Struct, 2) => field_opt_field = Some(Deserialize::read(p)?),
                    (TType::Struct, 3) => field_req_field = Some(Deserialize::read(p)?),
                    (fty, _) => p.skip(fty)?,
                }
                p.read_field_end()?;
            }
            p.read_struct_end()?;
            Ok(Self {
                def_field: field_def_field.unwrap_or_default(),
                opt_field: field_opt_field,
                req_field: field_req_field.unwrap_or_default(),
            })
        }
    }


    impl Default for self::StructWithRefAndAnnotCppNoexceptMoveCtor {
        fn default() -> Self {
            Self {
                def_field: Default::default(),
            }
        }
    }

    impl GetTType for self::StructWithRefAndAnnotCppNoexceptMoveCtor {
        const TTYPE: TType = TType::Struct;
    }

    impl<P: ProtocolWriter> Serialize<P> for self::StructWithRefAndAnnotCppNoexceptMoveCtor {
        fn write(&self, p: &mut P) {
            p.write_struct_begin("StructWithRefAndAnnotCppNoexceptMoveCtor");
            p.write_field_begin("def_field", TType::Struct, 1);
            Serialize::write(&self.def_field, p);
            p.write_field_end();
            p.write_field_stop();
            p.write_struct_end();
        }
    }

    impl<P: ProtocolReader> Deserialize<P> for self::StructWithRefAndAnnotCppNoexceptMoveCtor {
        fn read(p: &mut P) -> anyhow::Result<Self> {
            let mut field_def_field = None;
            let _ = p.read_struct_begin(|_| ())?;
            loop {
                let (_, fty, fid) = p.read_field_begin(|_| ())?;
                match (fty, fid as i32) {
                    (TType::Stop, _) => break,
                    (TType::Struct, 1) => field_def_field = Some(Deserialize::read(p)?),
                    (fty, _) => p.skip(fty)?,
                }
                p.read_field_end()?;
            }
            p.read_struct_end()?;
            Ok(Self {
                def_field: field_def_field.unwrap_or_default(),
            })
        }
    }

}

pub mod errors {
}