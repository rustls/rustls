//! Zlib compression functions

use super::{CertificateCompressor, CertificateDecompressor};
use crate::TLSError;
use flate2::write::{ZlibDecoder, ZlibEncoder};
use std::io::{Result, Write};

/// Configuration parameters for Zlib
#[derive(Debug, Clone, Default)]
pub struct ZlibParams {
    compression_level: flate2::Compression,
}

impl ZlibParams {
    /// Create new ZlibParams given a compression level
    ///
    /// Value must be between 0-9, defaults to [flate2::Compression::default]
    pub fn new(compression_level: u32) -> std::result::Result<Self, TLSError> {
        if !(0..=9).contains(&compression_level) {
            return Err(TLSError::General(
                "compression level must be between 0 and 9".to_string(),
            ));
        }

        Ok(Self {
            compression_level: flate2::Compression::new(compression_level),
        })
    }
}

pub(crate) struct ZlibCompress<W: Write>(ZlibEncoder<W>);

impl<W: Write> ZlibCompress<W> {
    pub fn new(writer: W, params: &ZlibParams) -> Self {
        Self(ZlibEncoder::new(writer, params.compression_level))
    }
}

impl<W: Write> Write for ZlibCompress<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.0.flush()
    }
}

impl<W: Write> CertificateCompressor for ZlibCompress<W> {
    type Writer = W;

    fn finish(self) -> Result<Self::Writer> {
        self.0.finish()
    }

    fn into_inner(self: Box<Self>) -> Result<Self::Writer> {
        (*self).finish()
    }
}

pub(crate) struct ZlibDecompress<W: Write>(ZlibDecoder<W>);

impl<W: Write> ZlibDecompress<W> {
    pub fn new(writer: W) -> Self {
        Self(ZlibDecoder::new(writer))
    }
}

impl<W: Write> Write for ZlibDecompress<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.0.flush()
    }
}

impl<W: Write> CertificateDecompressor for ZlibDecompress<W> {
    type Writer = W;

    fn finish(self) -> Result<Self::Writer> {
        self.0.finish()
    }

    fn into_inner(self: Box<Self>) -> Result<Self::Writer> {
        (*self).finish()
    }
}
