use rustls::compress;
use rustls::enums::CertificateCompressionAlgorithm;

#[derive(Debug, PartialEq)]
pub(crate) enum CompressionAlgs {
    None,
    All,
    One(u16),
}

#[derive(Debug)]
pub(crate) struct ShrinkingAlgorithm;

impl ShrinkingAlgorithm {
    pub(crate) const ALGORITHM: u16 = 0xff01;
}

impl compress::CertDecompressor for ShrinkingAlgorithm {
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm(Self::ALGORITHM)
    }

    fn decompress(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), compress::DecompressionFailed> {
        if output.len() != input.len() + 2 {
            return Err(compress::DecompressionFailed);
        }
        output[..2].copy_from_slice(&[0, 0]);
        output[2..].copy_from_slice(input);
        Ok(())
    }
}

impl compress::CertCompressor for ShrinkingAlgorithm {
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm(Self::ALGORITHM)
    }

    fn compress(
        &self,
        mut input: Vec<u8>,
        _: compress::CompressionLevel,
    ) -> Result<Vec<u8>, compress::CompressionFailed> {
        assert_eq!(input[..2], [0, 0]);
        input.drain(0..2);
        Ok(input)
    }
}

#[derive(Debug)]
pub(crate) struct ExpandingAlgorithm;

impl compress::CertDecompressor for ExpandingAlgorithm {
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm(0xff02)
    }

    fn decompress(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), compress::DecompressionFailed> {
        if output.len() + 4 != input.len() {
            return Err(compress::DecompressionFailed);
        }
        if input[..4] != [1, 2, 3, 4] {
            return Err(compress::DecompressionFailed);
        }
        output.copy_from_slice(&input[4..]);
        Ok(())
    }
}

impl compress::CertCompressor for ExpandingAlgorithm {
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm(0xff02)
    }

    fn compress(
        &self,
        mut input: Vec<u8>,
        _: compress::CompressionLevel,
    ) -> Result<Vec<u8>, compress::CompressionFailed> {
        input.insert(0, 1);
        input.insert(1, 2);
        input.insert(2, 3);
        input.insert(3, 4);
        Ok(input)
    }
}

#[derive(Debug)]
pub(crate) struct RandomAlgorithm;

impl compress::CertDecompressor for RandomAlgorithm {
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm(0xff03)
    }

    fn decompress(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), compress::DecompressionFailed> {
        if output.len() + 1 != input.len() {
            return Err(compress::DecompressionFailed);
        }
        output.copy_from_slice(&input[1..]);
        Ok(())
    }
}

impl compress::CertCompressor for RandomAlgorithm {
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm(0xff03)
    }

    fn compress(
        &self,
        mut input: Vec<u8>,
        _: compress::CompressionLevel,
    ) -> Result<Vec<u8>, compress::CompressionFailed> {
        let random_byte = {
            let mut bytes = [0];
            // nb. provider is irrelevant for this use
            rustls_ring::DEFAULT_PROVIDER
                .secure_random
                .fill(&mut bytes)
                .unwrap();
            bytes[0]
        };
        input.insert(0, random_byte);
        Ok(input)
    }
}
