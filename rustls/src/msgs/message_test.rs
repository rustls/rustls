use crate::enums::{AlertDescription, HandshakeType};
use crate::msgs::base::{PayloadU16, PayloadU24, PayloadU8};

use super::base::Payload;
use super::codec::Reader;
use super::enums::AlertLevel;
use super::message::{Message, OpaqueMessage, PlainMessage};

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

#[test]
fn test_read_fuzz_corpus() {
    fn corpus_dir() -> PathBuf {
        let from_subcrate = Path::new("../fuzz/corpus/message");
        let from_root = Path::new("fuzz/corpus/message");

        if from_root.is_dir() {
            from_root.to_path_buf()
        } else {
            from_subcrate.to_path_buf()
        }
    }

    for file in fs::read_dir(corpus_dir()).unwrap() {
        let mut f = fs::File::open(file.unwrap().path()).unwrap();
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes).unwrap();

        let mut rd = Reader::init(&bytes);
        let msg = OpaqueMessage::read(&mut rd)
            .unwrap()
            .into_plain_message();
        println!("{:?}", msg);

        let msg = match Message::try_from(msg) {
            Ok(msg) => msg,
            Err(_) => continue,
        };

        let enc = PlainMessage::from(msg)
            .into_unencrypted_opaque()
            .encode();
        assert_eq!(bytes.to_vec(), enc);
        assert_eq!(bytes[..rd.used()].to_vec(), enc);
    }
}

#[test]
fn can_read_safari_client_hello() {
    let _ = env_logger::Builder::new()
        .filter(None, log::LevelFilter::Trace)
        .try_init();

    let bytes = b"\
        \x16\x03\x01\x00\xeb\x01\x00\x00\xe7\x03\x03\xb6\x1f\xe4\x3a\x55\
        \x90\x3e\xc0\x28\x9c\x12\xe0\x5c\x84\xea\x90\x1b\xfb\x11\xfc\xbd\
        \x25\x55\xda\x9f\x51\x93\x1b\x8d\x92\x66\xfd\x00\x00\x2e\xc0\x2c\
        \xc0\x2b\xc0\x24\xc0\x23\xc0\x0a\xc0\x09\xcc\xa9\xc0\x30\xc0\x2f\
        \xc0\x28\xc0\x27\xc0\x14\xc0\x13\xcc\xa8\x00\x9d\x00\x9c\x00\x3d\
        \x00\x3c\x00\x35\x00\x2f\xc0\x08\xc0\x12\x00\x0a\x01\x00\x00\x90\
        \xff\x01\x00\x01\x00\x00\x00\x00\x0e\x00\x0c\x00\x00\x09\x31\x32\
        \x37\x2e\x30\x2e\x30\x2e\x31\x00\x17\x00\x00\x00\x0d\x00\x18\x00\
        \x16\x04\x03\x08\x04\x04\x01\x05\x03\x02\x03\x08\x05\x08\x05\x05\
        \x01\x08\x06\x06\x01\x02\x01\x00\x05\x00\x05\x01\x00\x00\x00\x00\
        \x33\x74\x00\x00\x00\x12\x00\x00\x00\x10\x00\x30\x00\x2e\x02\x68\
        \x32\x05\x68\x32\x2d\x31\x36\x05\x68\x32\x2d\x31\x35\x05\x68\x32\
        \x2d\x31\x34\x08\x73\x70\x64\x79\x2f\x33\x2e\x31\x06\x73\x70\x64\
        \x79\x2f\x33\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x0b\x00\x02\
        \x01\x00\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19";
    let mut rd = Reader::init(bytes);
    let m = OpaqueMessage::read(&mut rd).unwrap();
    println!("m = {:?}", m);
    assert!(Message::try_from(m.into_plain_message()).is_err());
}

#[test]
fn alert_is_not_handshake() {
    let m = Message::build_alert(AlertLevel::Fatal, AlertDescription::DecodeError);
    assert!(!m.is_handshake_type(HandshakeType::ClientHello));
}

#[test]
fn alert_is_not_opaque() {
    let m = Message::build_alert(AlertLevel::Fatal, AlertDescription::DecodeError);
    assert!(Message::try_from(m).is_ok());
}

#[test]
fn construct_all_types() {
    let samples = [
        &b"\x14\x03\x04\x00\x01\x01"[..],
        &b"\x15\x03\x04\x00\x02\x01\x16"[..],
        &b"\x16\x03\x04\x00\x05\x18\x00\x00\x01\x00"[..],
        &b"\x17\x03\x04\x00\x04\x11\x22\x33\x44"[..],
        &b"\x18\x03\x04\x00\x04\x11\x22\x33\x44"[..],
    ];
    for &bytes in samples.iter() {
        let m = OpaqueMessage::read(&mut Reader::init(bytes)).unwrap();
        println!("m = {:?}", m);
        let m = Message::try_from(m.into_plain_message());
        println!("m' = {:?}", m);
    }
}

#[test]
fn debug_payload() {
    assert_eq!("01020304", format!("{:?}", Payload(vec![1, 2, 3, 4])));
    assert_eq!("01020304", format!("{:?}", PayloadU8(vec![1, 2, 3, 4])));
    assert_eq!("01020304", format!("{:?}", PayloadU16(vec![1, 2, 3, 4])));
    assert_eq!("01020304", format!("{:?}", PayloadU24(vec![1, 2, 3, 4])));
}
