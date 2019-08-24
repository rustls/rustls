#[macro_use]
mod macros;

pub mod codec;
pub mod base;
#[allow(non_camel_case_types)]
pub mod enums;
pub mod alert;
#[allow(non_camel_case_types)]
pub mod handshake;
pub mod ccs;
pub mod message;
pub mod persist;
pub mod deframer;
pub mod fragmenter;
pub mod hsjoiner;

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
    #[test]
    fn smoketest() {
        use super::codec::Reader;
        use super::message::Message;
        use super::codec::Codec;
        let bytes = include_bytes!("handshake-test.1.bin");
        let mut r = Reader::init(bytes);

        while r.any_left() {
            let mut m = Message::read(&mut r).unwrap();

            let mut out: Vec<u8> = vec![];
            m.encode(&mut out);
            assert!(out.len() > 0);

            m.decode_payload();
        }
    }
}
