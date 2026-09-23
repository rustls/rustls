use crate::crypto::cipher::{
    EncryptBuffer, InboundOpaque, Iv, Nonce, OutboundPlain, Record, Tag, make_tls13_aad,
    record_region,
};
use crate::enums::ContentType;
use crate::error::Error;

/// TLS 1.3 record encryption (sealing).
///
/// This implements the record payload protection scheme of [RFC 9846 section 5.2][1].
///
/// Callers provide callbacks for encrypting ciphertext in `fragmented_encrypt` and
/// `contiguous_encrypt`.
///
/// `contiguous_encrypt` is invoked if it is provided and the plaintext in `record` is contiguous.
/// The callback is passed (in order) the nonce, AAD, the contiguous plaintext, a buffer into which
/// ciphertext is written, extra plaintext to be encrypted (the content type), and another buffer
/// into which extra ciphertext and the tag are written.
///
/// `fragmented_encrypt` is invoked if the plaintext is not contiguous or if `contiguous_encrypt` is
/// not provided. This function will gather plaintext into a single buffer and then pass into the
/// callback (in order) the nonce, AAD and the buffer containing plaintext. The callback should seal
/// in-place and return the tag.
///
/// In either case, this function is responsible for appending the content type to the plaintext and
/// appending the GCM tag to the ciphertext. Callbacks are exclusively responsible for encryption
/// and computing the tag. This function guarantees that any mutable buffer passed to callbacks has
/// the correct size for the content to be written.
///
/// Only one of `contiguous_encrypt` or `fragmented_encrypt` is ever called, so callback
/// implementations do not need to worry about concurrent access to any values closed over.
///
/// [1]: https://www.rfc-editor.org/info/rfc9846/#section-5.2
pub fn encrypt_record<'a, FE, CE>(
    mut fragmented_encrypt: FE,
    contiguous_encrypt: Option<CE>,
    record: Record<OutboundPlain<'_>>,
    seq: u64,
    iv: &Iv,
    encrypted_len: usize,
    out: &'a mut [u8],
) -> Result<Record<&'a [u8]>, Error>
where
    FE: FnMut(Nonce, [u8; TLS13_AAD_SIZE], &mut EncryptBuffer<'_>) -> Result<Tag, Error>,
    CE: FnMut(
        Nonce,
        [u8; TLS13_AAD_SIZE],
        /* contiguous plaintext */ &[u8],
        /* ciphertext */ &mut [u8],
        /* extra plaintext */ &[u8],
        /* extra ciphertext and tag */ &mut [u8],
    ) -> Result<(), Error>,
{
    let typ = ContentType::ApplicationData;
    let nonce = Nonce::new(iv, seq);
    let aad = make_tls13_aad(typ, record.version.encode(), encrypted_len);

    let payload = match (record.payload.single_chunk(), contiguous_encrypt) {
        // Fast path: plaintext is contiguous and the provider has a special case for it.
        (Some(contiguous_plain), Some(mut fast_path)) => {
            let record_slice = record_region(out, encrypted_len)?;
            let (ciphertext, typ_and_tag) = record_slice.split_at_mut(contiguous_plain.len());
            fast_path(
                nonce,
                aad,
                contiguous_plain,
                ciphertext,
                &record.typ.to_array(),
                typ_and_tag,
            )?;

            &*record_slice
        }
        // Slow path: either plaintext is not contiguous or the provider has no special support.
        // Gather plaintext into a buffer and seal it in-place.
        _ => {
            let mut payload = EncryptBuffer::new(out, encrypted_len)?;
            payload.extend_from_chunks(&record.payload);
            payload.extend_from_slice(&record.typ.to_array());
            let tag = fragmented_encrypt(nonce, aad, &mut payload)?;
            payload.extend_from_slice(tag.as_ref());
            payload.into_written()
        }
    };

    Ok(Record {
        typ,
        version: record.version,
        payload,
    })
}

/// TLS 1.3 record decryption (opening).
///
/// This implements the record payload protection scheme of [RFC 9846 section 5.2][1].
///
/// Callers provide a callback for decrypting ciphertext in `decrypt`. The callback is passed (in
/// order) the nonce, AAD and a buffer containing the ciphertext. The callback should unseal in
/// place.
///
/// In either case, this function is responsible for stripping the GCM explicit nonce from the
/// ciphertext. The callback is exclusively responsible for decryption and checking the tag.
///
/// [1]: https://www.rfc-editor.org/info/rfc9846/#section-5.2
pub fn decrypt_record<'a, D>(
    mut decrypt: D,
    tag_len: usize,
    mut record: Record<InboundOpaque<'a>>,
    seq: u64,
    iv: &Iv,
) -> Result<Record<&'a [u8]>, Error>
where
    D: FnMut(Nonce, [u8; TLS13_AAD_SIZE], &mut [u8]) -> Result<usize, Error>,
{
    let payload = &mut record.payload;
    if payload.len() < tag_len {
        return Err(Error::DecryptError);
    }

    let nonce = Nonce::new(iv, seq);
    let aad = make_tls13_aad(record.typ, record.version.version(), payload.len());

    let plain_len = decrypt(nonce, aad, payload.as_mut())?;

    payload.truncate(plain_len);
    record.into_tls13_unpadded_record()
}

/// Length of an encrypted payload in TLS 1.3.
///
/// The plaintext length, plus one byte for the content-type, plus the AEAD tag.
pub fn encrypted_payload_len(payload_len: usize, tag_len: usize) -> usize {
    payload_len + 1 + tag_len
}

/// TLS 1.3 AAD length.
///
/// 1 byte for content type, 2 bytes for version, 2 bytes for payload length.
pub const TLS13_AAD_SIZE: usize = 1 + 2 + 2;
