// Additional x509/asn1 functions to those provided in webpki/ring.

use alloc::vec::Vec;

pub(crate) fn asn1_wrap(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let len = bytes.len();

    if len <= 0x7f {
        // Short form
        let mut ret = Vec::with_capacity(2 + len);
        ret.push(tag);
        ret.push(len as u8);
        ret.extend_from_slice(bytes);
        ret
    } else {
        // Long form
        let size = len.to_be_bytes();
        let leading_zero_bytes = size
            .iter()
            .position(|&x| x != 0)
            .unwrap_or(size.len());
        assert!(leading_zero_bytes < size.len());
        let encoded_bytes = size.len() - leading_zero_bytes;

        let mut ret = Vec::with_capacity(2 + encoded_bytes + len);
        ret.push(tag);

        ret.push(0x80 + encoded_bytes as u8);
        ret.extend_from_slice(&size[leading_zero_bytes..]);

        ret.extend_from_slice(bytes);
        ret
    }
}

/// Prepend stuff to `bytes` to put it in a DER SEQUENCE.
pub(crate) fn wrap_in_sequence(bytes: &[u8]) -> Vec<u8> {
    asn1_wrap(DER_SEQUENCE_TAG, bytes)
}

const DER_SEQUENCE_TAG: u8 = 0x30;

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    #[test]
    fn test_empty() {
        assert_eq!(vec![0x30, 0x00], wrap_in_sequence(&[]));
    }

    #[test]
    fn test_small() {
        assert_eq!(
            vec![0x30, 0x04, 0x00, 0x11, 0x22, 0x33],
            wrap_in_sequence(&[0x00, 0x11, 0x22, 0x33])
        );
    }

    #[test]
    fn test_medium() {
        let mut val = Vec::new();
        val.resize(255, 0x12);
        assert_eq!(
            vec![0x30, 0x81, 0xff, 0x12, 0x12, 0x12],
            wrap_in_sequence(&val)[..6]
        );
    }

    #[test]
    fn test_large() {
        let mut val = Vec::new();
        val.resize(4660, 0x12);
        wrap_in_sequence(&val);
        assert_eq!(
            vec![0x30, 0x82, 0x12, 0x34, 0x12, 0x12],
            wrap_in_sequence(&val)[..6]
        );
    }

    #[test]
    fn test_huge() {
        let mut val = Vec::new();
        val.resize(0xffff, 0x12);
        let result = wrap_in_sequence(&val);
        assert_eq!(vec![0x30, 0x82, 0xff, 0xff, 0x12, 0x12], result[..6]);
        assert_eq!(result.len(), 0xffff + 4);
    }

    #[test]
    fn test_gigantic() {
        let mut val = Vec::new();
        val.resize(0x100000, 0x12);
        let result = wrap_in_sequence(&val);
        assert_eq!(vec![0x30, 0x83, 0x10, 0x00, 0x00, 0x12, 0x12], result[..7]);
        assert_eq!(result.len(), 0x100000 + 5);
    }

    #[test]
    fn test_ludicrous() {
        let mut val = Vec::new();
        val.resize(0x1000000, 0x12);
        let result = wrap_in_sequence(&val);
        assert_eq!(
            vec![0x30, 0x84, 0x01, 0x00, 0x00, 0x00, 0x12, 0x12],
            result[..8]
        );
        assert_eq!(result.len(), 0x1000000 + 6);
    }
}
