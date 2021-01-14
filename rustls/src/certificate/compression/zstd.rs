//! Zstd compression functions

use super::{CertificateCompressor, CertificateDecompressor};
use crate::TLSError;
use std::io::{Result, Write};
use zstd::stream::write::{Decoder, Encoder};

/// Configuration parameters for Zstd
#[derive(Debug, Clone)]
pub struct ZstdParams {
    compression_level: i32,
}

impl ZstdParams {
    /// Create new ZstdParams given a compression level
    ///
    /// Value must be between 0-21.
    /// A value of 0 defaults to [::zstd::DEFAULT_COMPRESSION_LEVEL]
    pub fn new(compression_level: i32) -> std::result::Result<Self, TLSError> {
        if !(0..=21).contains(&compression_level) {
            return Err(TLSError::General(
                "compression level must be between 0 and 9".to_string(),
            ));
        }

        Ok(Self { compression_level })
    }
}

impl Default for ZstdParams {
    fn default() -> Self {
        Self {
            compression_level: ::zstd::DEFAULT_COMPRESSION_LEVEL,
        }
    }
}

pub(crate) struct ZstdCompress<W: Write>(Encoder<'static, W>);

impl<W: Write> ZstdCompress<W> {
    pub fn new(writer: W, params: &ZstdParams) -> Result<Self> {
        Ok(Self(Encoder::new(writer, params.compression_level)?))
    }
}

impl<W: Write> Write for ZstdCompress<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.0.flush()
    }
}

impl<W: Write> CertificateCompressor for ZstdCompress<W> {
    type Writer = W;

    fn finish(self) -> Result<Self::Writer> {
        self.0.finish()
    }

    fn into_inner(self: Box<Self>) -> Result<Self::Writer> {
        (*self).finish()
    }
}

pub(crate) struct ZstdDecompress<W: Write>(Decoder<'static, W>);

impl<W: Write> ZstdDecompress<W> {
    pub fn new(writer: W) -> Result<Self> {
        Ok(Self(Decoder::new(writer)?))
    }
}

impl<W: Write> Write for ZstdDecompress<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.0.flush()
    }
}

impl<W: Write> CertificateDecompressor for ZstdDecompress<W> {
    type Writer = W;

    fn finish(mut self) -> Result<Self::Writer> {
        (&mut self).flush()?; // We need to flush here https://github.com/gyscos/zstd-rs/issues/80
        Ok(self.0.into_inner())
    }
    fn into_inner(self: Box<Self>) -> Result<Self::Writer> {
        (*self).finish()
    }
}
