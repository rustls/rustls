//! HKDF from RFC5869

use crate::crypto::{hash, hmac};

pub(crate) struct Extractor {
    salt: Box<dyn hmac::Key>,
    hmac: &'static dyn hmac::Hmac,
}

impl Extractor {
    pub(crate) fn no_salt(hmac: &'static dyn hmac::Hmac) -> Self {
        let zeroes = [0u8; hash::HASH_MAX_OUTPUT];
        Self {
            salt: hmac.open_key(&zeroes[..hmac.hash_output_len()]),
            hmac,
        }
    }

    pub(crate) fn with_salt(hmac: &'static dyn hmac::Hmac, salt: &[u8]) -> Self {
        Self {
            salt: hmac.open_key(salt),
            hmac,
        }
    }

    pub(crate) fn extract(self, ikm: &[u8]) -> Expander {
        Expander(
            self.hmac
                .open_key(self.salt.sign(&[ikm]).as_ref()),
        )
    }
}

pub(crate) struct OutputLengthError;

/// This is a PRK ready for use via `expand()` et al.
pub(crate) struct Expander(Box<dyn hmac::Key>);

/// This is a single block output from HKDF-Expand.
#[derive(Clone)]
pub(crate) struct OkmOneBlock(hmac::Tag);

impl AsRef<[u8]> for OkmOneBlock {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Expander {
    pub(crate) fn from_okm(okm: &OkmOneBlock, hmac: &'static dyn hmac::Hmac) -> Self {
        Self(hmac.open_key(okm.0.as_ref()))
    }

    fn expand_unchecked(&self, info: &[&[u8]], output: &mut [u8]) {
        let mut term = hmac::Tag::new(b"");

        for (n, chunk) in output
            .chunks_mut(self.0.tag_len())
            .enumerate()
        {
            term = self
                .0
                .sign_concat(term.as_ref(), info, &[(n + 1) as u8]);
            chunk.copy_from_slice(&term.as_ref()[..chunk.len()]);
        }
    }

    pub(crate) fn one_block_len(&self) -> usize {
        self.0.tag_len()
    }

    pub(crate) fn expand_slice(
        &self,
        info: &[&[u8]],
        output: &mut [u8],
    ) -> Result<(), OutputLengthError> {
        if output.len() > 255 * self.0.tag_len() {
            return Err(OutputLengthError);
        }

        self.expand_unchecked(info, output);
        Ok(())
    }

    pub(crate) fn expand<T, const N: usize>(&self, info: &[&[u8]]) -> T
    where
        T: From<[u8; N]>,
    {
        assert!(N <= 255 * self.0.tag_len());
        let mut output = [0u8; N];
        self.expand_unchecked(info, &mut output);
        T::from(output)
    }

    pub(crate) fn expand_one_block(&self, info: &[&[u8]]) -> OkmOneBlock {
        let mut tag = [0u8; hmac::HMAC_MAX_TAG];
        let reduced_tag = &mut tag[..self.0.tag_len()];
        self.expand_unchecked(info, reduced_tag);
        OkmOneBlock(hmac::Tag::new(reduced_tag))
    }
}

#[cfg(test)]
mod test {
    use super::Extractor;
    use crate::crypto::ring;

    struct ByteArray<const N: usize>([u8; N]);

    impl<const N: usize> From<[u8; N]> for ByteArray<N> {
        fn from(array: [u8; N]) -> Self {
            Self(array)
        }
    }

    /// Test cases from appendix A in the RFC.

    #[test]
    fn test_case_1() {
        let hmac = &ring::hmac::HMAC_SHA256;
        let ikm = &[0x0b; 22];
        let salt = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info: &[&[u8]] = &[
            &[0xf0, 0xf1, 0xf2],
            &[0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9],
        ];

        let output: ByteArray<42> = Extractor::with_salt(hmac, salt)
            .extract(ikm)
            .expand(info);

        assert_eq!(
            &output.0,
            &[
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
            ]
        );
    }

    #[test]
    fn test_case_2() {
        let hmac = &ring::hmac::HMAC_SHA256;

        let ikm: Vec<u8> = (0x00u8..=0x4f).collect();
        let salt: Vec<u8> = (0x60u8..=0xaf).collect();
        let info: Vec<u8> = (0xb0u8..=0xff).collect();

        let output: ByteArray<82> = Extractor::with_salt(hmac, &salt)
            .extract(&ikm)
            .expand(&[&info]);

        assert_eq!(
            &output.0,
            &[
                0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a,
                0x49, 0x34, 0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c,
                0x19, 0xaf, 0xa9, 0x7c, 0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb,
                0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09, 0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
                0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec,
                0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f, 0x1d, 0x87
            ]
        );
    }

    #[test]
    fn test_case_3() {
        let hmac = &ring::hmac::HMAC_SHA256;
        let ikm = &[0x0b; 22];
        let salt = &[];
        let info = &[];

        let output: ByteArray<42> = Extractor::with_salt(hmac, salt)
            .extract(ikm)
            .expand(info);

        assert_eq!(
            &output.0,
            &[
                0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
                0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f,
                0x3c, 0x73, 0x8d, 0x2d, 0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8
            ]
        );
    }

    #[test]
    fn test_salt_not_provided() {
        // can't use test case 7, because we don't have (or want) SHA1.
        //
        // this output is generated with cryptography.io:
        //
        // >>> hkdf.HKDF(algorithm=hashes.SHA384(), length=96, salt=None, info=b"hello").derive(b"\x0b" * 40)

        let hmac = &ring::hmac::HMAC_SHA384;

        let ikm = &[0x0b; 40];
        let info = &[&b"hel"[..], &b"lo"[..]];

        let output: ByteArray<96> = Extractor::no_salt(hmac)
            .extract(ikm)
            .expand(info);

        assert_eq!(
            &output.0,
            &[
                0xd5, 0x45, 0xdd, 0x3a, 0xff, 0x5b, 0x19, 0x46, 0xd4, 0x86, 0xfd, 0xb8, 0xd8, 0x88,
                0x2e, 0xe0, 0x1c, 0xc1, 0xa5, 0x48, 0xb6, 0x05, 0x75, 0xe4, 0xd7, 0x5d, 0x0f, 0x5f,
                0x23, 0x40, 0xee, 0x6c, 0x9e, 0x7c, 0x65, 0xd0, 0xee, 0x79, 0xdb, 0xb2, 0x07, 0x1d,
                0x66, 0xa5, 0x50, 0xc4, 0x8a, 0xa3, 0x93, 0x86, 0x8b, 0x7c, 0x69, 0x41, 0x6b, 0x3e,
                0x61, 0x44, 0x98, 0xb8, 0xc2, 0xfc, 0x82, 0x82, 0xae, 0xcd, 0x46, 0xcf, 0xb1, 0x47,
                0xdc, 0xd0, 0x69, 0x0d, 0x19, 0xad, 0xe6, 0x6c, 0x70, 0xfe, 0x87, 0x92, 0x04, 0xb6,
                0x82, 0x2d, 0x97, 0x7e, 0x46, 0x80, 0x4c, 0xe5, 0x76, 0x72, 0xb4, 0xb8
            ]
        );
    }

    #[test]
    fn test_output_length_bounds() {
        let hmac = &ring::hmac::HMAC_SHA256;
        let ikm = &[];
        let salt = &[];
        let info = &[];

        let mut output = [0u8; 32 * 255 + 1];
        assert!(Extractor::with_salt(hmac, salt)
            .extract(ikm)
            .expand_slice(info, &mut output)
            .is_err());
    }
}
