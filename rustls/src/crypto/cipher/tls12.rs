use crate::crypto::cipher::{
    EncryptBuffer, InboundOpaque, Iv, NONCE_LEN, Nonce, OutboundPlain, Record, Tag, make_tls12_aad,
    record_region,
};
use crate::error::Error;
use crate::msgs::MAX_FRAGMENT_LEN;

/// GCM encryption (sealing) of a TLS 1.2 record.
///
/// This implements the GCM construction of [RFC 5288][1] and [RFC 5246 section 6.2.3.3][2] where 8
/// bytes of explicit nonce are prepended to the ciphertext.
///
/// Callers provide callbacks for encrypting ciphertext in `fragmented_encrypt` and
/// `contiguous_encrypt`.
///
/// `contiguous_encrypt` is invoked if it is provided and the plaintext in `record` is contiguous.
/// The callback is passed (in order) the nonce, AAD, the contiguous plaintext, a buffer into which
/// ciphertext is written, and another buffer into which the tag is written.
///
/// `fragmented_encrypt` is invoked if the plaintext is not contiguous or if `contiguous_encrypt` is
/// not provided. This function will gather plaintext into a single buffer and then pass into the
/// callback (in order) the nonce, AAD and the buffer containing plaintext. The callback should seal
/// in-place and return the tag.
///
/// In either case, this function is responsible for pre-pending the GCM explicit nonce to the
/// ciphertext and appending the GCM tag. Callbacks are exclusively responsible for encryption and
/// computing the tag. This function guarantees that any mutable buffer passed to callbacks has the
/// correct size for the content to be written.
///
/// Only one of `contiguous_encrypt` or `fragmented_encrypt` is ever called, so callback
/// implementations do not need to worry about concurrent access to any values closed over.
///
/// [1]: https://www.rfc-editor.org/info/rfc5288/
/// [2]: https://www.rfc-editor.org/info/rfc5246/#section-6.2.3.3
pub fn gcm_encrypt_record<'a, FE, CE>(
    mut fragmented_encrypt: FE,
    contiguous_encrypt: Option<CE>,
    record: Record<OutboundPlain<'_>>,
    seq: u64,
    iv: &Iv,
    encrypted_len: usize,
    out: &'a mut [u8],
) -> Result<Record<&'a [u8]>, Error>
where
    FE: FnMut(Nonce, [u8; TLS12_AAD_SIZE], &mut EncryptBuffer<'_>) -> Result<Tag, Error>,
    CE: FnMut(
        Nonce,
        [u8; TLS12_AAD_SIZE],
        /* contiguous plaintext */ &[u8],
        /* buffer for ciphertext */ &mut [u8],
        /* buffer for tag */ &mut [u8],
    ) -> Result<(), Error>,
{
    let nonce = Nonce::new(iv, seq);
    let aad = make_tls12_aad(
        seq,
        record.typ,
        record.version.encode(),
        record.payload.len(),
    );

    // For AES-GCM suites, prefix plaintext with explicit nonce
    // <https://www.rfc-editor.org/info/rfc5246/#section-6.2.3.3>
    let payload = match (record.payload.single_chunk(), contiguous_encrypt) {
        // Fast path: plaintext is contiguous and the provider has a special case for it.
        (Some(contiguous_plain), Some(mut fast_path)) => {
            let record_slice = record_region(out, encrypted_len)?;
            record_slice[..GCM_EXPLICIT_NONCE_LEN].copy_from_slice(&nonce.as_ref()[4..]);
            let sealed = &mut record_slice[GCM_EXPLICIT_NONCE_LEN..];
            let (ciphertext, tag) = sealed.split_at_mut(contiguous_plain.len());
            fast_path(nonce, aad, contiguous_plain, ciphertext, tag)?;
            &*record_slice
        }
        // Slow path: either plaintext is not contiguous or the provider has no special support.
        // Gather plaintext into a buffer and seal it in-place.
        _ => {
            out[..GCM_EXPLICIT_NONCE_LEN].copy_from_slice(&nonce.as_ref()[4..]);

            let mut payload = EncryptBuffer::new(
                &mut out[GCM_EXPLICIT_NONCE_LEN..],
                encrypted_len - GCM_EXPLICIT_NONCE_LEN,
            )?;
            payload.extend_from_chunks(&record.payload);
            let tag = fragmented_encrypt(nonce, aad, &mut payload)?;
            payload.extend_from_slice(tag.as_ref());

            out
        }
    };

    Ok(Record {
        typ: record.typ,
        version: record.version,
        payload,
    })
}

/// GCM decryption (opening) of a TLS 1.2 record.
///
/// This implements the GCM construction of [RFC 5288][1] and [RFC 5246 section 6.2.3.3][2] where 8
/// bytes of explicit nonce are prepended to the ciphertext.
///
/// Callers provide a callback for decrypting ciphertext in `decrypt`. The callback is passed (in
/// order) the nonce, AAD, a buffer containing the ciphertext and an offset into that buffer where
/// the ciphertext begins. The callback should unseal in place.
///
/// This function is responsible for stripping the GCM explicit nonce from the ciphertext. The
/// callback is exclusively responsible for encryption and checking the tag.
///
/// [1]: https://www.rfc-editor.org/info/rfc5288/
/// [2]: https://www.rfc-editor.org/info/rfc5246/#section-6.2.3.3
pub fn gcm_decrypt_record<'a, D>(
    mut decrypt: D,
    mut record: Record<InboundOpaque<'a>>,
    seq: u64,
    dec_salt: [u8; 4],
) -> Result<Record<&'a [u8]>, Error>
where
    D: FnMut(
        Nonce,
        [u8; TLS12_AAD_SIZE],
        /* plaintext (in/out) */ &mut [u8],
        /* position in buffer where plaintext starts */
        usize,
    ) -> Result<usize, Error>,
{
    let payload = &mut record.payload;
    if payload.len() < GCM_OVERHEAD {
        return Err(Error::DecryptError);
    }

    let nonce = {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&dec_salt);
        nonce[4..].copy_from_slice(&payload[..8]);
        Nonce::from(nonce)
    };

    let aad = make_tls12_aad(
        seq,
        record.typ,
        record.version.version(),
        payload.len() - GCM_OVERHEAD,
    );

    let plain_len = decrypt(nonce, aad, payload.as_mut(), GCM_EXPLICIT_NONCE_LEN)?;

    if plain_len > MAX_FRAGMENT_LEN.get() {
        return Err(Error::PeerSentOversizedRecord);
    }

    payload.truncate(plain_len);
    Ok(record.into_plain_record())
}

/// The length of a GCM ciphertext for the provided payload and tag lengths.
pub fn gcm_encrypted_payload_len(payload_len: usize, tag_len: usize) -> usize {
    payload_len + GCM_EXPLICIT_NONCE_LEN + tag_len
}

/// ChaCha20Poly1305 encryption (sealing) of a TLS 1.2 record.
///
/// This implements the construction of RFCs [7905][1] and [8439][2] which describe use of
/// ChaCha20Poly1305 in TLS 1.2.
///
/// Callers provide callbacks for encrypting ciphertext in `fragmented_encrypt` and
/// `contiguous_encrypt`.
///
/// `contiguous_encrypt` is invoked if it is provided and the plaintext in `record` is contiguous.
/// The callback is passed (in order) the nonce, AAD, the contiguous plaintext, a buffer into which
/// ciphertext is written, and another buffer into which the tag is written.
///
/// `fragmented_encrypt` is invoked if the plaintext is not contiguous or if `contiguous_encrypt` is
/// not provided. This function will gather plaintext into a single buffer and then pass into the
/// callback (in order) the nonce, AAD and the buffer containing plaintext. The callback should seal
/// in-place and return the tag.
///
/// In either case, this function is responsible for pre-pending the GCM explicit nonce to the
/// ciphertext and appending the GCM tag. Callbacks are exclusively responsible for encryption and
/// computing the tag. This function guarantees that any mutable buffer passed to callbacks has the
/// correct size for the content to be written.
///
/// Only one of `contiguous_encrypt` or `fragmented_encrypt` is ever called, so callback
/// implementations do not need to worry about concurrent access to any values closed over.
///
/// [1]: https://www.rfc-editor.org/info/rfc7905/
/// [2]: https://www.rfc-editor.org/info/rfc8439/
pub fn chacha20poly1305_encrypt_record<'a, FE, CE>(
    mut fragmented_encrypt: FE,
    contiguous_encrypt: Option<CE>,
    record: Record<OutboundPlain<'_>>,
    seq: u64,
    iv: &Iv,
    encrypted_len: usize,
    out: &'a mut [u8],
) -> Result<Record<&'a [u8]>, Error>
where
    FE: FnMut(Nonce, [u8; TLS12_AAD_SIZE], &mut EncryptBuffer<'_>) -> Result<Tag, Error>,
    CE: FnMut(
        Nonce,
        [u8; TLS12_AAD_SIZE],
        /* plaintext */ &[u8],
        /* buffer for ciphertext */ &mut [u8],
        /* buffer for tag */ &mut [u8],
    ) -> Result<(), Error>,
{
    let nonce = Nonce::new(iv, seq);
    let aad = make_tls12_aad(
        seq,
        record.typ,
        record.version.encode(),
        record.payload.len(),
    );

    let payload = match (record.payload.single_chunk(), contiguous_encrypt) {
        // Fast path: plaintext is contiguous and the provider has a special case for it.
        (Some(contiguous_plain), Some(mut fast_path)) => {
            let record_slice = record_region(out, encrypted_len)?;
            let (ciphertext, tag) = record_slice.split_at_mut(contiguous_plain.len());

            fast_path(nonce, aad, contiguous_plain, ciphertext, tag)?;

            &*record_slice
        }
        // Slow path: either plaintext is not contiguous or the provider has no special support.
        // Gather plaintext into a buffer and seal it in-place.
        _ => {
            let mut payload = EncryptBuffer::new(out, encrypted_len)?;
            payload.extend_from_chunks(&record.payload);
            let tag = fragmented_encrypt(nonce, aad, &mut payload)?;
            payload.extend_from_slice(tag.as_ref());
            payload.into_written()
        }
    };

    Ok(Record {
        typ: record.typ,
        version: record.version,
        payload,
    })
}

/// ChaCha20Poly1305 decryption (opening) of a TLS 1.2 record.
///
/// This implements the construction of RFCs [7905][1] and [8439][2] which describe use of
/// ChaCha20Poly1305 in TLS 1.2.
///
/// Callers provide a callback for decrypting ciphertext in `decrypt`. The callback is passed (in
/// order) the nonce, AAD, a buffer containing the ciphertext and an offset into that buffer where
/// the ciphertext begins. The callback should unseal in place.
///
/// In either case, this function is responsible for stripping the GCM explicit nonce from the
/// ciphertext. The callback is exclusively responsible for encryption and checking the tag.
///
/// [1]: https://www.rfc-editor.org/info/rfc7905/
/// [2]: https://www.rfc-editor.org/info/rfc8439/
pub fn chacha20poly1305_decrypt_record<'a, D>(
    mut decrypt: D,
    mut record: Record<InboundOpaque<'a>>,
    seq: u64,
    dec_offset: &Iv,
) -> Result<Record<&'a [u8]>, Error>
where
    D: FnMut(Nonce, [u8; TLS12_AAD_SIZE], &mut [u8]) -> Result<usize, Error>,
{
    let payload = &mut record.payload;
    if payload.len() < CHACHAPOLY1305_OVERHEAD {
        return Err(Error::DecryptError);
    }

    let nonce = Nonce::new(dec_offset, seq);
    let aad = make_tls12_aad(
        seq,
        record.typ,
        record.version.version(),
        payload.len() - CHACHAPOLY1305_OVERHEAD,
    );

    let plain_len = decrypt(nonce, aad, payload.as_mut())?;

    if plain_len > MAX_FRAGMENT_LEN.get() {
        return Err(Error::PeerSentOversizedRecord);
    }

    payload.truncate(plain_len);
    Ok(record.into_plain_record())
}

/// The length of a ChaCha20Poly1305 ciphertext for the provided payload and tag lengths.
pub fn chacha20poly1305_encrypted_payload_len(payload_len: usize, tag_len: usize) -> usize {
    payload_len + tag_len
}

/// Construct the IV for use in GCM ciphers.
///
/// This follows the specification in [RFC 5288 section 3][1].
///
/// [1]: https://www.rfc-editor.org/info/rfc5288/#section-3
pub fn gcm_iv(write_iv: &[u8], explicit: &[u8]) -> Iv {
    debug_assert_eq!(write_iv.len(), 4);
    debug_assert_eq!(explicit.len(), 8);

    // The GCM nonce is constructed from a 32-bit 'salt' derived
    // from the master-secret, and a 64-bit explicit part,
    // with no specified construction.  Thanks for that.
    //
    // We use the same construction as TLS1.3/ChaCha20Poly1305:
    // a starting point extracted from the key block, xored with
    // the sequence number.
    let mut iv = [0; NONCE_LEN];
    iv[..4].copy_from_slice(write_iv);
    iv[4..].copy_from_slice(explicit);

    Iv::new(&iv).expect("IV length is NONCE_LEN, which is within MAX_LEN")
}

/// Length of the AAD for TLS 1.2.
///
/// 8 bytes of sequence number, 1 byte of content type, 2 bytes of protocol version and 2 bytes of
/// payload length.
pub const TLS12_AAD_SIZE: usize = 8 + 1 + 2 + 2;

/// Length of `explicit_nonce` for GCM suites
///
/// <https://www.rfc-editor.org/info/rfc5246/#section-6.2.3.3>
pub const GCM_EXPLICIT_NONCE_LEN: usize = 8;

const GCM_OVERHEAD: usize = GCM_EXPLICIT_NONCE_LEN + 16;

const CHACHAPOLY1305_OVERHEAD: usize = 16;
