/* Additional x509/asn1 functions to those provided in webpki/ring. */

use ring::der;

fn wrap_in_asn1_len(bytes: &mut Vec<u8>) {
  let len = bytes.len();

  if len < 128 {
    bytes.insert(0, len as u8);
  } else if len < 256 {
    bytes.insert(0, 0x81u8);
    bytes.insert(1, len as u8);
  } else if len < 0xffff {
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
