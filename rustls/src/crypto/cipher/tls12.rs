use core::ops::Range;

use crate::crypto::cipher::{
    EncryptInput, InboundOpaque, Iv, NONCE_LEN, Nonce, OutboundPlain, Record, Tag, make_tls12_aad,
};
use crate::error::Error;
use crate::msgs::MAX_FRAGMENT_LEN;

/// GCM encryption (sealing) of a TLS 1.2 record.
///
/// This implements the GCM construction of [RFC 5288][1] and [RFC 5246 section 6.2.3.3][2] where 8
/// bytes of explicit nonce are prepended to the ciphertext.
///
/// Callers provide a callback `encrypt` for encrypting ciphertext. Besides the AEAD nonce and
/// AAD, the callback is passed an [`EncryptInput`] value. Providers with a fast path for contiguous
/// plaintext should use [`EncryptInput::contiguous`] to gathering plaintext into a buffer. See that
/// method and [`EncryptInput::collect`] for more discussion.
///
/// If the callback appends the AEAD tag to the ciphertext, it should return `Ok(None)`. Otherwise
/// it should return `Ok(Some(tag))` and this function assumes responsibility for appending the tag
/// to ciphertext.
///
/// In either case, this function is responsible for pre-pending the GCM explicit nonce to the
/// ciphertext.
///
/// [1]: https://www.rfc-editor.org/info/rfc5288/
/// [2]: https://www.rfc-editor.org/info/rfc5246/#section-6.2.3.3
pub fn gcm_encrypt_record<'a, E>(
    mut encrypt: E,
    record: Record<OutboundPlain<'_>>,
    seq: u64,
    iv: &Iv,
    encrypted_len: usize,
    out: &'a mut [u8],
) -> Result<Record<&'a [u8]>, Error>
where
    E: FnMut(Nonce, [u8; TLS12_AAD_SIZE], &mut EncryptInput<'_>) -> Result<Option<Tag>, Error>,
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
    out[..GCM_EXPLICIT_NONCE_LEN].copy_from_slice(&nonce.as_ref()[4..]);

    let mut encrypt_input = EncryptInput::new(
        encrypted_len - GCM_EXPLICIT_NONCE_LEN,
        &record.payload,
        &[], // no extra plaintext for TLS 1.2
        &mut out[GCM_EXPLICIT_NONCE_LEN..],
    )?;

    if let Some(tag) = encrypt(nonce, aad, &mut encrypt_input)? {
        encrypt_input.out[record.payload.len()..].copy_from_slice(tag.as_ref());
    }

    Ok(Record {
        typ: record.typ,
        version: record.version,
        payload: &out[..encrypted_len],
    })
}

/// GCM decryption (opening) of a TLS 1.2 record.
///
/// This implements the GCM construction of [RFC 5288][1] and [RFC 5246 section 6.2.3.3][2] where 8
/// bytes of explicit nonce are prepended to the ciphertext.
///
/// Callers provide a callback for decrypting ciphertext in `decrypt`. The callback is passed (in
/// order) the nonce, AAD, a buffer containing the ciphertext and an offset into that buffer where
/// the ciphertext begins. The callback should unseal in place, though it may move the plaintext
/// within the buffer. The callback returns the position within the ciphertext buffer where
/// plaintext has been written.
///
/// This function is responsible for stripping the GCM explicit nonce from the ciphertext.
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
    ) -> Result<Range<usize>, Error>,
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

    let plain_position = decrypt(nonce, aad, payload.as_mut(), GCM_EXPLICIT_NONCE_LEN)?;

    if plain_position.end - plain_position.start > MAX_FRAGMENT_LEN.get() {
        return Err(Error::PeerSentOversizedRecord);
    }

    Ok(record.into_plain_record_range(plain_position))
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
/// Callers provide a callback `encrypt` for encrypting ciphertext. Besides the AEAD nonce and
/// AAD, the callback is passed an [`EncryptInput`] value. Providers with a fast path for contiguous
/// plaintext should use [`EncryptInput::contiguous`] to gathering plaintext into a buffer. See that
/// method and [`EncryptInput::collect`] for more discussion.
///
/// If the callback appends the AEAD tag to the ciphertext, it should return `Ok(None)`. Otherwise
/// it should return `Ok(Some(tag))` and this function assumes responsibility for appending the tag
/// to ciphertext.
///
/// [1]: https://www.rfc-editor.org/info/rfc7905/
/// [2]: https://www.rfc-editor.org/info/rfc8439/
pub fn chacha20poly1305_encrypt_record<'a, E>(
    mut encrypt: E,
    record: Record<OutboundPlain<'_>>,
    seq: u64,
    iv: &Iv,
    encrypted_len: usize,
    out: &'a mut [u8],
) -> Result<Record<&'a [u8]>, Error>
where
    E: FnMut(Nonce, [u8; TLS12_AAD_SIZE], &mut EncryptInput<'_>) -> Result<Option<Tag>, Error>,
{
    let nonce = Nonce::new(iv, seq);
    let aad = make_tls12_aad(
        seq,
        record.typ,
        record.version.encode(),
        record.payload.len(),
    );

    let mut encrypt_input = EncryptInput::new(
        encrypted_len,
        &record.payload,
        &[], // no extra plaintext for TLS 1.2
        out,
    )?;

    if let Some(tag) = encrypt(nonce, aad, &mut encrypt_input)? {
        out[record.payload.len()..].copy_from_slice(tag.as_ref());
    }

    Ok(Record {
        typ: record.typ,
        version: record.version,
        payload: &out[..encrypted_len],
    })
}

/// ChaCha20Poly1305 decryption (opening) of a TLS 1.2 record.
///
/// This implements the construction of RFCs [7905][1] and [8439][2] which describe use of
/// ChaCha20Poly1305 in TLS 1.2.
///
/// Callers provide a callback for decrypting ciphertext in `decrypt`. The callback is passed (in
/// order) the nonce, AAD, and a buffer containing the ciphertext. The callback should unseal in
/// place and return the length of the plaintext.
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
