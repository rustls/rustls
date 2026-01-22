/// A macro which defines an enum type.
macro_rules! enum_builder {
    (
        $(#[doc = $comment:literal])*
        #[repr($uint:ty)]
        $(#[$metas:meta])*
        $enum_vis:vis enum $enum_name:ident
        {
          $(
              $(#[$enum_metas:meta])*
              $enum_var:ident => $enum_val:literal
          ),*
          $(,)?
          $(
              !Debug:
              $(
                  $(#[$enum_metas_no_debug:meta])*
                  $enum_var_no_debug:ident => $enum_val_no_debug:literal
              ),*
              $(,)?
          )?
        }
    ) => {
        $(#[doc = $comment])*
        $(#[$metas])*
        #[allow(missing_docs)]
        #[non_exhaustive]
        #[derive(PartialEq, Eq, Clone, Copy, Hash)]
        $enum_vis enum $enum_name {
            $(
                $(#[$enum_metas])*
                $enum_var
            ),*
            $(
                ,
                $(
                    $(#[$enum_metas_no_debug])*
                    $enum_var_no_debug
                ),*
            )?
            ,Unknown($uint)
        }

        #[allow(missing_docs)]
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
                    $(, $( $enum_name::$enum_var_no_debug => Some(stringify!($enum_var_no_debug))),* )?
                    ,$enum_name::Unknown(_) => None,
                }
            }
        }

        impl crate::msgs::Codec<'_> for $enum_name {
            fn encode(&self, bytes: &mut alloc::vec::Vec<u8>) {
                <$uint>::from(*self).encode(bytes);
            }

            fn read(r: &mut crate::msgs::Reader<'_>) -> Result<Self, crate::error::InvalidMessage> {
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
                    $(, $($enum_val_no_debug => $enum_name::$enum_var_no_debug),* )?
                    , x => $enum_name::Unknown(x),
                }
            }
        }

        impl From<$enum_name> for $uint {
            fn from(value: $enum_name) -> Self {
                match value {
                    $( $enum_name::$enum_var => $enum_val),*
                    $(, $( $enum_name::$enum_var_no_debug => $enum_val_no_debug),* )?
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
        $struct_vis:vis struct $struct_name:ident$(<$struct_lt:lifetime>)*
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
        #[derive(Clone, Default)]
        $struct_vis struct $struct_name$(<$struct_lt>)* {
            $(
              $(#[$item_attr])*
              $item_vis $item_slot: Option<$item_ty>,
            )+
            $($(
              $(#[$meta_attr])*
              $meta_vis $meta_slot: $meta_ty,
            )+)*
        }

        impl<'a> $struct_name$(<$struct_lt>)* {
            /// Reads one extension typ, length and body from `r`.
            ///
            /// Unhandled extensions (according to `read_extension_body()` are inserted into `unknown_extensions`)
            fn read_one(
                &mut self,
                r: &mut Reader<'a>,
                mut unknown: impl FnMut(ExtensionType) -> Result<(), InvalidMessage>,
            ) -> Result<ExtensionType, InvalidMessage> {
                let typ = ExtensionType::read(r)?;
                let len = usize::from(u16::read(r)?);
                let mut ext_body = r.sub(len)?;
                match self.read_extension_body(typ, &mut ext_body)? {
                    true => ext_body.expect_empty(stringify!($struct_name))?,
                    false => unknown(typ)?,

                };
                Ok(typ)
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
                      $item_id => Self::read_once(r, $item_id, &mut self.$item_slot)?,
                   )*

                   // read and ignore unhandled extensions
                   _ => {
                       r.rest();
                       return Ok(false);
                   }
                }

                Ok(true)
            }

            /// Decode `r` as `T` into `out`, only if `out` is `None`.
            fn read_once<T>(r: &mut Reader<'a>, id: ExtensionType, out: &mut Option<T>) -> Result<(), InvalidMessage>
            where T: Codec<'a>,
            {
                if let Some(_) = out {
                    return Err(InvalidMessage::DuplicateExtension(u16::from(id)));
                }

                *out = Some(T::read(r)?);
                Ok(())
            }

            /// Encode one extension body for `typ` into `output`.
            ///
            /// Adds nothing to `output` if `typ` is absent from this
            /// struct, either because it is `None` or unhandled by
            /// this struct.
            fn encode_one(
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
            #[allow(dead_code)]
            pub(crate) fn collect_used(&self) -> Vec<ExtensionType> {
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
            #[allow(dead_code)]
            pub(crate) fn clone_one(
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
            #[allow(dead_code)]
            pub(crate) fn clear(&mut self, typ: ExtensionType) {
                match typ {
                    $(
                        $item_id => self.$item_slot = None,
                    )*
                    _ => {},
                }
            }

            /// Return true if all present extensions are named in `allowed`
            #[allow(dead_code)]
            pub(crate) fn only_contains(&self, allowed: &[ExtensionType]) -> bool {
                $(
                    if let Some(_) = &self.$item_slot {
                        if !allowed.contains(&$item_id) {
                            return false;
                        }
                    }
                )*

                true
            }

            /// Return true if any extension named in `exts` is present.
            #[allow(dead_code)]
            pub(crate) fn contains_any(&self, exts: &[ExtensionType]) -> bool {
                for e in exts {
                    if self.contains(*e) {
                        return true;
                    }
                }
                false
            }

            fn contains(&self, e: ExtensionType) -> bool {
                match e {
                    $(

                        $item_id => self.$item_slot.is_some(),
                    )*
                    _ => false,
                }
            }

            /// Every `ExtensionType` this structure may encode/decode.
            const ALL_EXTENSIONS: &'static [ExtensionType] = &[
                $($item_id,)*
            ];
        }

        impl<'a> core::fmt::Debug for $struct_name$(<$struct_lt>)*  {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let mut ds = f.debug_struct(stringify!($struct_name));
                $(
                    if let Some(ext) = &self.$item_slot {
                        ds.field(stringify!($item_slot), ext);
                    }
                )*
                $($(
                    ds.field(stringify!($meta_slot), &self.$meta_slot);
                )+)*
                ds.finish_non_exhaustive()
            }
        }
    }
}

/// Create a newtype wrapper around a given type.
///
/// This is used to create newtypes for the various TLS message types which is used to wrap
/// the `PayloadU8` or `SizedPayload` types. This is typically used for types where we don't need
/// anything other than access to the underlying bytes.
macro_rules! wrapped_payload(
  ($(#[$comment:meta])* $vis:vis struct $name:ident, $inner:ident$(<$len:ty, $cardinality:ty>)?,) => {
    $(#[$comment])*
    #[derive(Clone, Debug)]
    $vis struct $name($inner$(<'static, $len, $cardinality>)?);

    impl From<Vec<u8>> for $name {
        fn from(v: Vec<u8>) -> Self {
            Self($inner::from(v))
        }
    }

    impl AsRef<[u8]> for $name {
        fn as_ref(&self) -> &[u8] {
            self.0.bytes()
        }
    }

    impl Codec<'_> for $name {
        fn encode(&self, bytes: &mut Vec<u8>) {
            self.0.encode(bytes);
        }

        fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
            Ok(Self($inner::read(r)?.into_owned()))
        }
    }
  }
);
