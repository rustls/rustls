/// A macro which defines an enum type.
macro_rules! enum_builder {
    (
    $(#[$comment:meta])*
    @U8
        $enum_vis:vis enum $enum_name:ident
        { $( $enum_var: ident => $enum_val: expr ),* }
    ) => {
        $(#[$comment])*
        #[non_exhaustive]
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        $enum_vis enum $enum_name {
            $( $enum_var),*
            ,Unknown(u8)
        }
        impl $enum_name {
            $enum_vis fn get_u8(&self) -> u8 {
                let x = self.clone();
                match x {
                    $( $enum_name::$enum_var => $enum_val),*
                    ,$enum_name::Unknown(x) => x
                }
            }
        }
        impl Codec for $enum_name {
            // NOTE(allow) fully qualified Vec is only needed in no-std mode
            #[allow(unused_qualifications)]
            fn encode(&self, bytes: &mut alloc::vec::Vec<u8>) {
                self.get_u8().encode(bytes);
            }

            fn read(r: &mut Reader) -> Result<Self, crate::error::InvalidMessage> {
                match u8::read(r) {
                    Ok(x) => Ok($enum_name::from(x)),
                    Err(_) => Err(crate::error::InvalidMessage::MissingData(stringify!($enum_name))),
                }
            }
        }
        impl From<u8> for $enum_name {
            fn from(x: u8) -> Self {
                match x {
                    $($enum_val => $enum_name::$enum_var),*
                    , x => $enum_name::Unknown(x),
                }
            }
        }
    };
    (
    $(#[$comment:meta])*
    @U16
        $enum_vis:vis enum $enum_name:ident
        { $( $enum_var: ident => $enum_val: expr ),* }
    ) => {
        $(#[$comment])*
        #[non_exhaustive]
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        $enum_vis enum $enum_name {
            $( $enum_var),*
            ,Unknown(u16)
        }
        impl $enum_name {
            $enum_vis fn get_u16(&self) -> u16 {
                let x = self.clone();
                match x {
                    $( $enum_name::$enum_var => $enum_val),*
                    ,$enum_name::Unknown(x) => x
                }
            }

            #[allow(dead_code)] // generated irrespective if there are callers
            $enum_vis fn as_str(&self) -> Option<&'static str> {
                match self {
                    $( $enum_name::$enum_var => Some(stringify!($enum_var))),*
                    ,$enum_name::Unknown(_) => None,
                }
            }
        }
        impl Codec for $enum_name {
            // NOTE(allow) fully qualified Vec is only needed in no-std mode
            #[allow(unused_qualifications)]
            fn encode(&self, bytes: &mut alloc::vec::Vec<u8>) {
                self.get_u16().encode(bytes);
            }

            fn read(r: &mut Reader) -> Result<Self, crate::error::InvalidMessage> {
                match u16::read(r) {
                    Ok(x) => Ok($enum_name::from(x)),
                    Err(_) => Err(crate::error::InvalidMessage::MissingData(stringify!($enum_name))),
                }
            }
        }
        impl From<u16> for $enum_name {
            fn from(x: u16) -> Self {
                match x {
                    $($enum_val => $enum_name::$enum_var),*
                    , x => $enum_name::Unknown(x),
                }
            }
        }
    };
}
