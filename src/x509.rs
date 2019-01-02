// Additional x509/asn1 functions to those provided in webpki/ring.

use ring::io::der;

fn wrap_in_asn1_len(bytes: &mut Vec<u8>) {
    let len = bytes.len();

    if len <= 0x7f {
        bytes.insert(0, len as u8);
    } else if len <= 0xff {
        bytes.insert(0, 0x81u8);
        bytes.insert(1, len as u8);
    } else if len <= 0xffff {
        bytes.insert(0, 0x82u8);
        bytes.insert(1, ((len >> 8) & 0xff) as u8);
        bytes.insert(2, (len & 0xff) as u8);
    }
}

/// Prepend stuff to `bytes` to put it in a DER SEQUENCE.
pub fn wrap_in_sequence(bytes: &mut Vec<u8>) {
    wrap_in_asn1_len(bytes);
    bytes.insert(0, der::Tag::Sequence as u8);
}

#[test]
fn test_empty() {
    let mut val = Vec::new();
    wrap_in_sequence(&mut val);
    assert_eq!(vec![0x30, 0x00],
               val);
}

#[test]
fn test_small() {
    let mut val = Vec::new();
    val.insert(0, 0x00);
    val.insert(1, 0x11);
    val.insert(2, 0x22);
    val.insert(3, 0x33);
    wrap_in_sequence(&mut val);
    assert_eq!(vec![0x30, 0x04, 0x00, 0x11, 0x22, 0x33],
               val);
}

#[test]
fn test_medium() {
    let mut val = Vec::new();
    val.resize(255, 0x12);
    wrap_in_sequence(&mut val);
    assert_eq!(vec![0x30, 0x81, 0xff, 0x12, 0x12, 0x12],
               val[..6].to_vec());
}

#[test]
fn test_large() {
    let mut val = Vec::new();
    val.resize(4660, 0x12);
    wrap_in_sequence(&mut val);
    assert_eq!(vec![0x30, 0x82, 0x12, 0x34, 0x12, 0x12],
               val[..6].to_vec());
}
