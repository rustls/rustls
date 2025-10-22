//! The single place where we generate random material for our own use.

use crate::crypto::SecureRandom;

/// Make an array of size `N` containing random material.
pub(crate) fn random_array<const N: usize>(
    secure_random: &dyn SecureRandom,
) -> Result<[u8; N], GetRandomFailed> {
    let mut v = [0; N];
    secure_random.fill(&mut v)?;
    Ok(v)
}

/// Return a uniformly random [`u32`].
pub(crate) fn random_u32(secure_random: &dyn SecureRandom) -> Result<u32, GetRandomFailed> {
    Ok(u32::from_be_bytes(random_array(secure_random)?))
}

/// Return a uniformly random [`u16`].
pub(crate) fn random_u16(secure_random: &dyn SecureRandom) -> Result<u16, GetRandomFailed> {
    Ok(u16::from_be_bytes(random_array(secure_random)?))
}

/// Random material generation failed.
#[expect(clippy::exhaustive_structs)]
#[derive(Debug)]
pub struct GetRandomFailed;
