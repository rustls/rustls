//! Implementation of compression functions for TLS Certificate Compression

use std::io::{Result, Write};

pub(crate) mod brotli;
pub(crate) mod zlib;
pub(crate) mod zstd;

use crate::certificate::compression::brotli::BrotliParams;
use crate::certificate::compression::zlib::ZlibParams;
use crate::certificate::compression::zstd::ZstdParams;

/// A trait providing commonality between certificate compressors
pub(crate) trait CertificateCompressor: Write {
    type Writer: Write;

    fn finish(self) -> Result<Self::Writer>;
    fn into_inner(self: Box<Self>) -> Result<Self::Writer>;
}

impl<C: CertificateCompressor + ?Sized> CertificateCompressor for Box<C> {
    type Writer = C::Writer;

    fn finish(self) -> Result<Self::Writer> {
        self.into_inner()
    }

    fn into_inner(self: Box<Self>) -> Result<Self::Writer> {
        (*self).into_inner()
    }
}

/// A trait providing commonality between certificate de-compressors
pub(crate) trait CertificateDecompressor: Write {
    type Writer: Write;

    fn finish(self) -> Result<Self::Writer>;
    fn into_inner(self: Box<Self>) -> Result<Self::Writer>;
}

impl<D: CertificateDecompressor + ?Sized> CertificateDecompressor for Box<D> {
    type Writer = D::Writer;

    fn finish(self) -> Result<Self::Writer> {
        self.into_inner()
    }

    fn into_inner(self: Box<Self>) -> Result<Self::Writer> {
        (*self).into_inner()
    }
}

/// Configuration of compression algorithms
#[derive(Debug, Clone, Default)]
pub struct CertificateCompressionConfig {
    /// Brotli parameters
    pub brotli: BrotliParams,
    /// Zlib parameters
    pub zlib: ZlibParams,
    /// Zstd parameters
    pub zstd: ZstdParams,
}

impl CertificateCompressionConfig {
    /// Create a new certificate compression configuration with defaults
    pub fn new() -> Self {
        Self::default()
    }
}
