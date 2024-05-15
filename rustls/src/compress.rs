//! Certificate compression and decompression support

use alloc::vec::Vec;
use core::fmt::Debug;

use crate::enums::CertificateCompressionAlgorithm;

/// Returns the supported `CertDecompressor` implementations enabled
/// by crate features.
pub fn default_cert_decompressors() -> &'static [&'static dyn CertDecompressor] {
    &[
        #[cfg(feature = "zlib")]
        ZLIB_DECOMPRESSOR,
    ]
}

/// An available certificate decompression algorithm.
pub trait CertDecompressor: Debug + Send + Sync {
    /// Decompress `input`, writing the result to `output`.
    ///
    /// `output` is sized to match the declared length of the decompressed data.
    ///
    /// `Err(DecompressionFailed)` should be returned if decompression produces more, or fewer
    /// bytes than fit in `output`, or if the `input` is in any way malformed.
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed>;

    /// Which algorithm this decompressor handles.
    fn algorithm(&self) -> CertificateCompressionAlgorithm;
}

/// Returns the supported `CertCompressor` implementations enabled
/// by crate features.
pub fn default_cert_compressors() -> &'static [&'static dyn CertCompressor] {
    &[
        #[cfg(feature = "zlib")]
        ZLIB_COMPRESSOR,
    ]
}

/// An available certificate compression algorithm.
pub trait CertCompressor: Debug + Send + Sync {
    /// Compress `input`, returning the result.
    ///
    /// `input` is consumed by this function so (if the underlying implementation
    /// supports it) the compression can be performed in-place.
    ///
    /// `level` is a hint as to how much effort to expend on the compression.
    ///
    /// `Err(CompressionFailed)` may be returned for any reason.
    fn compress(
        &self,
        input: Vec<u8>,
        level: CompressionLevel,
    ) -> Result<Vec<u8>, CompressionFailed>;

    /// Which algorithm this compressor handles.
    fn algorithm(&self) -> CertificateCompressionAlgorithm;
}

/// A hint for how many resources to dedicate to a compression.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CompressionLevel {
    /// This compression is happening interactively during a handshake.
    ///
    /// Implementations may wish to choose a conservative compression level.
    Interactive,

    /// The compression may be amortized over many connections.
    ///
    /// Implementations may wish to choose an aggressive compression level.
    Amortized,
}

/// A content-less error for when `CertDecompressor::decompress` fails.
#[derive(Debug)]
pub struct DecompressionFailed;

/// A content-less error for when `CertCompressor::compress` fails.
#[derive(Debug)]
pub struct CompressionFailed;

#[cfg(feature = "zlib")]
mod feat_zlib_rs {
    use zlib_rs::c_api::Z_BEST_COMPRESSION;
    use zlib_rs::{deflate, inflate, ReturnCode};

    use super::*;

    /// A certificate decompressor for the Zlib algorithm using the `zlib-rs` crate.
    pub const ZLIB_DECOMPRESSOR: &dyn CertDecompressor = &ZlibRsDecompressor;

    #[derive(Debug)]
    struct ZlibRsDecompressor;

    impl CertDecompressor for ZlibRsDecompressor {
        fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
            let output_len = output.len();
            match inflate::uncompress_slice(output, input, inflate::InflateConfig::default()) {
                (output_filled, ReturnCode::Ok) if output_filled.len() == output_len => Ok(()),
                (_, _) => Err(DecompressionFailed),
            }
        }

        fn algorithm(&self) -> CertificateCompressionAlgorithm {
            CertificateCompressionAlgorithm::Zlib
        }
    }

    /// A certificate compressor for the Zlib algorithm using the `zlib-rs` crate.
    pub const ZLIB_COMPRESSOR: &dyn CertCompressor = &ZlibRsCompressor;

    #[derive(Debug)]
    struct ZlibRsCompressor;

    impl CertCompressor for ZlibRsCompressor {
        fn compress(
            &self,
            input: Vec<u8>,
            level: CompressionLevel,
        ) -> Result<Vec<u8>, CompressionFailed> {
            let mut output = alloc::vec![0u8; deflate::compress_bound(input.len())];
            let config = match level {
                CompressionLevel::Interactive => deflate::DeflateConfig::default(),
                CompressionLevel::Amortized => deflate::DeflateConfig::new(Z_BEST_COMPRESSION),
            };
            let (output_filled, rc) = deflate::compress_slice(&mut output, &input, config);
            if rc != ReturnCode::Ok {
                return Err(CompressionFailed);
            }

            let used = output_filled.len();
            output.truncate(used);
            Ok(output)
        }

        fn algorithm(&self) -> CertificateCompressionAlgorithm {
            CertificateCompressionAlgorithm::Zlib
        }
    }
}

#[cfg(feature = "zlib")]
pub use feat_zlib_rs::{ZLIB_COMPRESSOR, ZLIB_DECOMPRESSOR};
