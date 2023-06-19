use crate::crypto;

pub(crate) fn prf(out: &mut [u8], hmac_key: &dyn crypto::hmac::Key, label: &[u8], seed: &[u8]) {
    // A(1)
    let mut current_a = hmac_key.sign(&[label, seed]);

    let chunk_size = hmac_key.tag_len();
    for chunk in out.chunks_mut(chunk_size) {
        // P_hash[i] = HMAC_hash(secret, A(i) + seed)
        let p_term = hmac_key.sign(&[current_a.as_ref(), label, seed]);
        chunk.copy_from_slice(&p_term.as_ref()[..chunk.len()]);

        // A(i+1) = HMAC_hash(secret, A(i))
        current_a = hmac_key.sign(&[current_a.as_ref()]);
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::hmac::Hmac;
    use crate::crypto::ring;

    #[test]
    fn check_sha256() {
        let secret = b"\x9b\xbe\x43\x6b\xa9\x40\xf0\x17\xb1\x76\x52\x84\x9a\x71\xdb\x35";
        let seed = b"\xa0\xba\x9f\x93\x6c\xda\x31\x18\x27\xa6\xf7\x96\xff\xd5\x19\x8c";
        let label = b"test label";
        let expect = include_bytes!("../testdata/prf-result.1.bin");
        let mut output = [0u8; 100];

        super::prf(
            &mut output,
            ring::hmac::HMAC_SHA256
                .open_key(secret)
                .as_ref(),
            label,
            seed,
        );
        assert_eq!(expect.len(), output.len());
        assert_eq!(expect.to_vec(), output.to_vec());
    }

    #[test]
    fn check_sha512() {
        let secret = b"\xb0\x32\x35\x23\xc1\x85\x35\x99\x58\x4d\x88\x56\x8b\xbb\x05\xeb";
        let seed = b"\xd4\x64\x0e\x12\xe4\xbc\xdb\xfb\x43\x7f\x03\xe6\xae\x41\x8e\xe5";
        let label = b"test label";
        let expect = include_bytes!("../testdata/prf-result.2.bin");
        let mut output = [0u8; 196];

        super::prf(
            &mut output,
            ring::hmac::HMAC_SHA512
                .open_key(secret)
                .as_ref(),
            label,
            seed,
        );
        assert_eq!(expect.len(), output.len());
        assert_eq!(expect.to_vec(), output.to_vec());
    }
}

#[cfg(bench)]
mod benchmarks {
    #[bench]
    fn bench_sha256(b: &mut test::Bencher) {
        use crate::crypto::hmac::Hmac;
        use crate::crypto::ring;

        let label = &b"extended master secret"[..];
        let seed = [0u8; 32];
        let key = &b"secret"[..];

        b.iter(|| {
            let mut out = [0u8; 48];
            super::prf(
                &mut out,
                ring::hmac::HMAC_SHA256
                    .open_key(key)
                    .as_ref(),
                &label,
                &seed,
            );
            test::black_box(out);
        });
    }
}
