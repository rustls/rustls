/// A macro which defines an enum type.
macro_rules! enum_builder {
    (
        $(#[doc = $comment:literal])*
        #[repr($uint:ty)]
        $enum_vis:vis enum $enum_name:ident
        {
          $( $enum_var:ident => $enum_val:literal),* $(,)?
          $( !Debug:
            $( $enum_var_nd:ident => $enum_val_nd:literal),* $(,)?
          )?
        }
    ) => {
        $(#[doc = $comment])*
        #[non_exhaustive]
        #[derive(PartialEq, Eq, Clone, Copy)]
        $enum_vis enum $enum_name {
            $( $enum_var),*
            $(, $($enum_var_nd),* )?
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
                    $(, $( $enum_name::$enum_var_nd => Some(stringify!($enum_var_nd))),* )?
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

            fn read(r: &mut Reader<'_>) -> Result<Self, crate::error::InvalidMessage> {
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
                    $(, $($enum_val_nd => $enum_name::$enum_var_nd),* )?
                    , x => $enum_name::Unknown(x),
                }
            }
        }

        impl From<$enum_name> for $uint {
            fn from(value: $enum_name) -> Self {
                match value {
                    $( $enum_name::$enum_var => $enum_val),*
                    $(, $( $enum_name::$enum_var_nd => $enum_val_nd),* )?
                    ,$enum_name::Unknown(x) => x
                }
            }
        }

        impl core::fmt::Debug for $enum_name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self {
                    $( $enum_name::$enum_var => f.write_str(stringify!($enum_var)), )*
                    _ => write!(f, "{}(0x{:x?})", stringify!($enum_name), <$uint>::from(*self)),
                }
            }
        }
    };
}

/// A macro which defines a structure containing TLS extensions
///
/// The contents are defined by two blocks, which are merged to
/// give the struct's items.  The second block is optional.
///
/// The first block defines the items read-into by decoding,
/// and used for encoding.
///
/// The type of each item in the first block _must_ be an `Option`.
/// This records the presence of that extension.
///
/// Each item in the first block is prefixed with a match arm,
/// which must match an `ExtensionType` variant.  This maps
/// the item to its extension type.
///
/// Items in the second block are not encoded or decoded-to.
/// They therefore must have a reasonable `Default` value.
///
/// All items must have a `Default`, `Debug` and `Clone`.
macro_rules! extension_struct {
    (
        $(#[doc = $comment:literal])*
        $struct_vis:vis struct $struct_name:ident<'a>
        {
          $(
            $(#[$item_attr:meta])*
            $item_id:path => $item_vis:vis $item_slot:ident : Option<$item_ty:ty>,
          )+
        } $( + {
          $(
            $(#[$meta_attr:meta])*
            $meta_vis:vis $meta_slot:ident : $meta_ty:ty,
          )+
        })*
    ) => {
        $(#[doc = $comment])*
        #[non_exhaustive]
        #[derive(Clone, Debug, Default)]
        $struct_vis struct $struct_name<'a> {
            $(
              $(#[$item_attr])*
              $item_vis $item_slot: Option<$item_ty>,
            )+
            $($(
              $(#[$meta_attr])*
              $meta_vis $meta_slot: $meta_ty,
            )+)*
        }

        impl<'a> $struct_name<'a> {
            /// Decode `r` as `T` into `out`, only if `out` is `None`.
            fn read_once<T>(r: &mut Reader<'a>, out: &mut Option<T>) -> Result<(), InvalidMessage>
            where T: Codec<'a>,
            {
                if let Some(_) = out {
                    return Err(InvalidMessage::DuplicateExtension);
                }

                *out = Some(T::read(r)?);
                Ok(())
            }

            /// Reads one extension body for an extension named by `typ`.
            ///
            /// Returns `true` if handled, `false` otherwise.
            ///
            /// `r` is fully consumed if `typ` is unhandled.
            fn read_extension_body(
                &mut self,
                typ: ExtensionType,
                r: &mut Reader<'a>,
            ) -> Result<bool, InvalidMessage> {
                match typ {
                   $(
                      $item_id => Self::read_once(r, &mut self.$item_slot)?,
                   )*

                   // read and ignore unhandled extensions
                   _ => {
                       r.rest();
                       return Ok(false);
                   }
                }

                Ok(true)
            }

            /// Encode one extension body for `typ` into `output`.
            ///
            /// Adds nothing to `output` if `typ` is absent from this
            /// struct, either because it is `None` or unhandled by
            /// this struct.
            fn encode_one_extension(
                &self,
                typ: ExtensionType,
                output: &mut Vec<u8>,
            ) {
                match typ {
                    $(
                        $item_id => if let Some(item) = &self.$item_slot {
                            typ.encode(output);
                            item.encode(LengthPrefixedBuffer::new(ListLength::U16, output).buf);
                        },

                    )*
                    _ => {},
                }
            }

            /// Return a list of extensions whose items are `Some`
            pub(crate) fn collect_used_extensions(&self) -> Vec<ExtensionType> {
                let mut r = Vec::with_capacity(Self::ALL_EXTENSIONS.len());

                $(
                    if let Some(_) = &self.$item_slot {
                        r.push($item_id);
                    }
                )*

                r
            }

            /// Clone the value of the extension identified by `typ` from `source` to `self`.
            ///
            /// Does nothing if `typ` is not an extension handled by this object.
            pub(crate) fn clone_one_from(
                &mut self,
                source: &Self,
                typ: ExtensionType,
            )  {
                match typ {
                    $(
                        $item_id => self.$item_slot = source.$item_slot.clone(),
                    )*
                    _ => {},
                }
            }

            /// Remove the extension identified by `typ` from `self`.
            pub(crate) fn clear(&mut self, typ: ExtensionType) {
                match typ {
                    $(
                        $item_id => self.$item_slot = None,
                    )*
                    _ => {},
                }
            }

            /// Every `ExtensionType` this structure may encode/decode.
            const ALL_EXTENSIONS: &'static [ExtensionType] = &[
                $($item_id,)*
            ];
        }
    }
}
