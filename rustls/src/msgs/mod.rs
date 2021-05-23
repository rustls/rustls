#![allow(clippy::upper_case_acronyms)]

#[macro_use]
mod macros;

pub mod alert;
pub mod base;
pub mod ccs;
pub mod codec;
pub mod deframer;
#[allow(non_camel_case_types)]
pub mod enums;
pub mod fragmenter;
#[allow(non_camel_case_types)]
pub mod handshake;
pub mod hsjoiner;
pub mod message;
pub mod persist;

#[cfg(test)]
mod handshake_test;

#[cfg(test)]
mod persist_test;

#[cfg(test)]
mod enums_test;

#[cfg(test)]
mod message_test;

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    #[test]
    fn smoketest() {
        use super::message::{Message, OpaqueMessage};
        let mut bytes = include_bytes!("handshake-test.1.bin").to_vec();
        let mut offset = 0;

        while offset < bytes.len() {
            let (m, used) = OpaqueMessage::read(&mut bytes[offset..]).unwrap();
            offset += used;

            let out = m.to_owned().encode();
            assert!(out.len() > 0);

            Message::try_from(&m).unwrap();
        }
    }
}
