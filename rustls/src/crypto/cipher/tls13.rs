use crate::crypto::cipher::{
    EncryptInput, InboundOpaque, Iv, Nonce, OutboundPlain, Record, Tag, make_tls13_aad,
};
use crate::enums::ContentType;
use crate::error::Error;

/// TLS 1.3 record encryption (sealing).
///
/// This implements the record payload protection scheme of [RFC 9846 section 5.2][1].
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
/// [1]: https://www.rfc-editor.org/info/rfc9846/#section-5.2
pub fn encrypt_record<'a, E>(
    mut encrypt: E,
    record: Record<OutboundPlain<'_>>,
    seq: u64,
    iv: &Iv,
    encrypted_len: usize,
    out: &'a mut [u8],
) -> Result<Record<&'a [u8]>, Error>
where
    E: FnMut(Nonce, [u8; TLS13_AAD_SIZE], &mut EncryptInput<'_>) -> Result<Option<Tag>, Error>,
{
    let typ = ContentType::ApplicationData;
    let nonce = Nonce::new(iv, seq);
    let aad = make_tls13_aad(typ, record.version.encode(), encrypted_len);

    // Append inner content type to plaintext.
    let extra_plain = record.typ.to_array();

    if let Some(tag) = encrypt(
        nonce,
        aad,
        &mut EncryptInput::new(encrypted_len, &record.payload, &extra_plain, out)?,
    )? {
        out[record.payload.len() + extra_plain.len()..].copy_from_slice(tag.as_ref());
    }

    Ok(Record {
        typ,
        version: record.version,
        payload: &out[..encrypted_len],
    })
}

/// TLS 1.3 record decryption (opening).
///
/// This implements the record payload protection scheme of [RFC 9846 section 5.2][1].
///
/// Callers provide a callback for decrypting ciphertext in `decrypt`. The callback is passed (in
/// order) the nonce, AAD and a buffer containing the ciphertext. The callback should unseal in
/// place and return the length of the plaintext.
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
