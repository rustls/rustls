/// Non-panicking `let (nonce, ciphertext) = ciphertext.split_at(...)`.
// TODO(XXX): remove once stabilized in https://github.com/rust-lang/rust/issues/119128
#[allow(dead_code)] // Complicated conditional compilation guards elided
pub(crate) fn try_split_at(slice: &[u8], mid: usize) -> Option<(&[u8], &[u8])> {
    match mid > slice.len() {
        true => None,
        false => Some(slice.split_at(mid)),
    }
}
