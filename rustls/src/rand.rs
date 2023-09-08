//! The single place where we generate random material for our own use.

use crate::crypto::CryptoProvider;

/// Make a [`Vec<u8>`] of the given size containing random material.
pub(crate) fn random_vec(
    provider: &dyn CryptoProvider,
    len: usize,
) -> Result<Vec<u8>, GetRandomFailed> {
    let mut v = vec![0; len];
    provider.fill_random(&mut v)?;
    Ok(v)
}

/// Return a uniformly random [`u32`].
pub(crate) fn random_u32(provider: &dyn CryptoProvider) -> Result<u32, GetRandomFailed> {
    let mut buf = [0u8; 4];
    provider.fill_random(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

/// Random material generation failed.
#[derive(Debug)]
pub struct GetRandomFailed;
