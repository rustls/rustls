//! Brotli compression functions

use super::{CertificateCompressor, CertificateDecompressor};
use crate::TLSError;
use brotli::{enc::BrotliEncoderParams, CompressorWriter, DecompressorWriter};
use std::io::{Result, Write};

/// Configuration parameters for Brotli
#[derive(Debug, Clone)]
pub struct BrotliParams {
    buffer_size: usize,
    encoder_params: BrotliEncoderParams,
}

impl BrotliParams {
    /// Create new BrotliParams given a quality and buffer_size
    /// * quality: Value must be between 0-11,
    /// defaults to [::brotli::enc::encode::BrotliEncoderInitParams]
    /// * buffer_size: internal brotli buffer size, defaults to 4096
    pub fn new(quality: i32, buffer_size: usize) -> std::result::Result<Self, TLSError> {
        if !(0i32..=11).contains(&quality) {
            return Err(TLSError::General(
                "quality must be between 0 and 11".to_string(),
            ));
        }

        let encoder_params = BrotliEncoderParams {
            quality,
            ..Default::default()
        };

        Ok(Self {
            buffer_size,
            encoder_params,
        })
    }
}

impl Default for BrotliParams {
    fn default() -> Self {
        Self {
            // This value is used throughout the brotli crate as a default size.
            buffer_size: 4096,
            encoder_params: BrotliEncoderParams::default(),
        }
    }
}

pub(crate) struct BrotliCompress<W: Write>(CompressorWriter<W>);

impl<W: Write> BrotliCompress<W> {
    pub fn new(writer: W, params: &BrotliParams) -> Self {
        Self(CompressorWriter::with_params(
            writer,
            params.buffer_size,
            &params.encoder_params,
        ))
    }
}

impl<W: Write> Write for BrotliCompress<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.0.flush()
    }
}

impl<W: Write> CertificateCompressor for BrotliCompress<W> {
    type Writer = W;

    fn finish(mut self) -> Result<Self::Writer> {
        self.0.flush()?;
        Ok(self.0.into_inner())
    }

    fn into_inner(self: Box<Self>) -> Result<Self::Writer> {
        (*self).finish()
    }
}

pub(crate) struct BrotliDecompress<W: Write>(DecompressorWriter<W>);

impl<W: Write> BrotliDecompress<W> {
    pub fn new(writer: W, params: &BrotliParams) -> Self {
        Self(DecompressorWriter::new(writer, params.buffer_size))
    }
}

impl<W: Write> Write for BrotliDecompress<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.0.flush()
    }
}

impl<W: Write> CertificateDecompressor for BrotliDecompress<W> {
    type Writer = W;

    fn finish(mut self) -> Result<Self::Writer> {
        self.0.flush()?;

        Ok(match self.0.into_inner() {
            Ok(w) => w,
            Err(w) => w,
        })
    }

    fn into_inner(self: Box<Self>) -> Result<Self::Writer> {
        (*self).finish()
    }
}
