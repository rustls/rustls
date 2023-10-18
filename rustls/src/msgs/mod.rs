#![allow(clippy::upper_case_acronyms)]
#![allow(missing_docs)]

#[macro_use]
mod macros;

pub(crate) mod alert;
pub(crate) mod base;
pub(crate) mod ccs;
pub(crate) mod codec;
pub(crate) mod deframer;
pub(crate) mod enums;
pub(crate) mod fragmenter;
pub(crate) mod handshake;
pub(crate) mod message;
pub(crate) mod persist;

#[cfg(test)]
mod handshake_test;

#[cfg(test)]
mod message_test;

#[cfg(test)]
mod tests {
    use super::codec::Reader;
    use super::message::{Message, OpaqueMessage};

    #[test]
    fn smoketest() {
        let bytes = include_bytes!("handshake-test.1.bin");
        let mut r = Reader::init(bytes);

        while r.any_left() {
            let m = OpaqueMessage::read(&mut r).unwrap();

            let out = m.clone().encode();
            assert!(!out.is_empty());

            Message::try_from(m.into_plain_message()).unwrap();
        }
    }
}
