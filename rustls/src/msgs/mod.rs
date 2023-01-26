#![allow(clippy::upper_case_acronyms)]
#![allow(missing_docs)]

#[macro_use]
mod macros;

pub mod alert;
pub mod base;
pub mod ccs;
pub mod codec;
pub mod deframer;
pub mod enums;
pub mod fragmenter;
pub mod handshake;
pub mod message;
pub mod persist;

#[cfg(test)]
mod handshake_test;

#[cfg(test)]
mod persist_test;

#[cfg(test)]
pub(crate) mod enums_test;

#[cfg(test)]
mod message_test;

#[cfg(test)]
mod test {
    #[test]
    fn smoketest() {
        use super::message::{Message, OpaqueMessageRecv};
        let mut bytes = include_bytes!("handshake-test.1.bin").to_vec();

        let (mut cur, full_len) = (0, bytes.len());
        while cur < full_len {
            let (m, rest) = OpaqueMessageRecv::read(&mut bytes[cur..]).unwrap();
            Message::try_from(m.into_plain_message()).unwrap();
            cur = full_len - rest.len();
        }
    }
}
