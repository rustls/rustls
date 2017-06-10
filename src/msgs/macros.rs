/// A macro which takes an Option<T> and returns None if it
/// is None, otherwise unwraps().
macro_rules! try_ret(
    ($e:expr) => (match $e { Some(e) => e, None => return None })
);

/// A macro which defines an enum type.
macro_rules! enum_builder {
    (@U8
        EnumName: $enum_name: ident;
        EnumVal { $( $enum_var: ident => $enum_val: expr ),* }
    ) => {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        pub enum $enum_name {
            $( $enum_var),*
            ,Unknown(u8)
        }
        impl $enum_name {
            pub fn get_u8(&self) -> u8 {
                let x = self.clone();
                match x {
                    $( $enum_name::$enum_var => $enum_val),*
                    ,$enum_name::Unknown(x) => x
                }
            }
        }
        impl Codec for $enum_name {
            fn encode(&self, bytes: &mut Vec<u8>) {
                encode_u8(self.get_u8(), bytes);
            }

            fn read(r: &mut Reader) -> Option<Self> {
                Some(match read_u8(r) {
                    None => return None,
                    $( Some($enum_val) => $enum_name::$enum_var),*
                    ,Some(x) => $enum_name::Unknown(x)
                })
            }
        }
    };
    (@U16
        EnumName: $enum_name: ident;
        EnumVal { $( $enum_var: ident => $enum_val: expr ),* }
    ) => {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        pub enum $enum_name {
            $( $enum_var),*
            ,Unknown(u16)
        }
        impl $enum_name {
            pub fn get_u16(&self) -> u16 {
                let x = self.clone();
                match x {
                    $( $enum_name::$enum_var => $enum_val),*
                    ,$enum_name::Unknown(x) => x
                }
            }
        }
        impl Codec for $enum_name {
            fn encode(&self, bytes: &mut Vec<u8>) {
                encode_u16(self.get_u16(), bytes);
            }

            fn read(r: &mut Reader) -> Option<Self> {
                Some(match read_u16(r) {
                    None => return None,
                    $( Some($enum_val) => $enum_name::$enum_var),*
                    ,Some(x) => $enum_name::Unknown(x)
                })
            }
        }
    };
}
