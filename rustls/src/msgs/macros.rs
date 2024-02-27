/// A macro which defines an enum type.
macro_rules! enum_builder {
    ($(#[$comment:meta])* @U8 $($enum:tt)+) => {
        enum_builder!(u8: $(#[$comment])* $($enum)+);
    };
    ($(#[$comment:meta])* @U16 $($enum:tt)+) => {
        enum_builder!(u16: $(#[$comment])* $($enum)+);
    };
    (
        $uint:ty:
        $(#[$comment:meta])*
        $enum_vis:vis enum $enum_name:ident
        { $( $enum_var: ident => $enum_val: expr ),* $(,)? }
    ) => {
        $(#[$comment])*
        #[non_exhaustive]
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        $enum_vis enum $enum_name {
            $( $enum_var),*
            ,Unknown($uint)
        }

        impl $enum_name {
            // NOTE(allow) generated irrespective if there are callers
            #[allow(dead_code)]
            $enum_vis fn to_array(self) -> [u8; core::mem::size_of::<$uint>()] {
                <$uint>::from(self).to_be_bytes()
            }

            // NOTE(allow) generated irrespective if there are callers
            #[allow(dead_code)]
            $enum_vis fn as_str(&self) -> Option<&'static str> {
                match self {
                    $( $enum_name::$enum_var => Some(stringify!($enum_var))),*
                    ,$enum_name::Unknown(_) => None,
                }
            }
        }

        impl Codec<'_> for $enum_name {
            // NOTE(allow) fully qualified Vec is only needed in no-std mode
            #[allow(unused_qualifications)]
            fn encode(&self, bytes: &mut alloc::vec::Vec<u8>) {
                <$uint>::from(*self).encode(bytes);
            }

            fn read(r: &mut Reader) -> Result<Self, crate::error::InvalidMessage> {
                match <$uint>::read(r) {
                    Ok(x) => Ok($enum_name::from(x)),
                    Err(_) => Err(crate::error::InvalidMessage::MissingData(stringify!($enum_name))),
                }
            }
        }

        impl From<$uint> for $enum_name {
            fn from(x: $uint) -> Self {
                match x {
                    $($enum_val => $enum_name::$enum_var),*
                    , x => $enum_name::Unknown(x),
                }
            }
        }

        impl From<$enum_name> for $uint {
            fn from(value: $enum_name) -> Self {
                match value {
                    $( $enum_name::$enum_var => $enum_val),*
                    ,$enum_name::Unknown(x) => x
                }
            }
        }
    };
}
