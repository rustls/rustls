// Additional x509/asn1 functions to those provided in webpki/ring.

use alloc::vec::Vec;

/// Prepend stuff to `bytes` to put it in a DER SEQUENCE.
pub(crate) fn wrap_in_sequence(bytes: &[u8]) -> Vec<u8> {
    asn1_wrap(DER_SEQUENCE_TAG, bytes, &[])
}

/// Prepend stuff to `bytes` to put it in a DER BIT STRING.
pub(crate) fn wrap_in_bit_string(bytes: &[u8]) -> Vec<u8> {
    asn1_wrap(DER_BIT_STRING_TAG, &[0u8], bytes)
}

fn asn1_wrap(tag: u8, bytes_a: &[u8], bytes_b: &[u8]) -> Vec<u8> {
    let len = bytes_a.len() + bytes_b.len();

    if len <= 0x7f {
        // Short form
        let mut ret = Vec::with_capacity(2 + len);
        ret.push(tag);
        ret.push(len as u8);
        ret.extend_from_slice(bytes_a);
        ret.extend_from_slice(bytes_b);
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

        ret.extend_from_slice(bytes_a);
        ret.extend_from_slice(bytes_b);
        ret
    }
}

const DER_SEQUENCE_TAG: u8 = 0x30;
const DER_BIT_STRING_TAG: u8 = 0x03;

/// Given a DER-encoded `SubjectPublicKeyInfo`, return the content octets of its
/// `AlgorithmIdentifier`.
///
/// That content is the concatenation of the `algorithm` OID and its
/// `parameters`, which is exactly what a `pki_types::AlgorithmIdentifier`
/// holds (i.e. it does not include the enclosing `SEQUENCE` tag and length).
///
/// Returns `None` if `spki` is not a well-formed `SEQUENCE { SEQUENCE, .. }`.
pub(crate) fn spki_algorithm_identifier(spki: &[u8]) -> Option<&[u8]> {
    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, .. }
    let (body, _) = read_der_sequence(spki)?;
    // algorithm ::= AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters .. }
    let (alg_id, _) = read_der_sequence(body)?;
    Some(alg_id)
}

/// Read one DER `SEQUENCE` from the front of `der`, returning `(content, rest)`.
fn read_der_sequence(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    if tag != DER_SEQUENCE_TAG {
        return None;
    }
    let (len, rest) = read_der_length(rest)?;
    let content = rest.get(..len)?;
    Some((content, &rest[len..]))
}

/// Read a DER definite-length prefix, returning `(length, rest)`.
///
/// Rejects the indefinite-length form (not valid DER) and non-minimal encodings.
fn read_der_length(der: &[u8]) -> Option<(usize, &[u8])> {
    let (&first, rest) = der.split_first()?;
    match first {
        // Short form: the length is the byte itself.
        0..=0x7f => Some((usize::from(first), rest)),
        // Indefinite length is not permitted in DER.
        0x80 => None,
        // Long form: the low 7 bits give the number of subsequent length octets.
        _ => {
            let n = usize::from(first & 0x7f);
            if n > size_of::<usize>() {
                return None;
            }
            let bytes = rest.get(..n)?;
            // Reject non-minimal encodings (a leading zero length octet).
            if bytes.first() == Some(&0) {
                return None;
            }
            let mut len = 0usize;
            for &b in bytes {
                len = (len << 8) | usize::from(b);
            }
            Some((len, &rest[n..]))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

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

    #[test]
    fn test_wrap_in_bit_string() {
        // The BIT STRING encoding starts with a single octet on
        // the front saying how many bits to disregard from the
        // last octet. So this zero means "no bits" unused, which
        // is correct because our input is an string of octets.
        //
        // So if we encode &[0x55u8] with this function, we should get:
        //
        // 0x03    0x02    0x00                0x55
        // ^ tag   ^ len   ^ no unused bits    ^ value
        assert_eq!(wrap_in_bit_string(&[0x55u8]), vec![0x03, 0x02, 0x00, 0x55]);
    }
}
