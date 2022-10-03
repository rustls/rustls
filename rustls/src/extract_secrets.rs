/// Secrets for transmitting/receiving data over a TLS session. These can be
/// used to configure kTLS for a socket, for example.
pub struct ExtractedSecrets {
    /// secrets for the "tx" (transmit) direction
    pub tx: (u64, AlgorithmSecrets),

    /// secrets for the "rx" (receive) direction
    pub rx: (u64, AlgorithmSecrets),
}

/// Secrets specific to an AEAD algorithm. These are traffic secrets,
/// post-handshake.
pub enum AlgorithmSecrets {
    /// Secrets for the AES_128_GCM AEAD algorithm
    Aes128Gcm {
        /// key (16 bytes)
        key: [u8; 16],
        /// salt (4 bytes)
        salt: [u8; 4],
        /// initialization vector (8 bytes, chopped from key block)
        iv: [u8; 8],
    },

    /// Secrets for the AES_256_GCM AEAD algorithm
    Aes256Gcm {
        /// key (32 bytes)
        key: [u8; 32],
        /// salt (4 bytes)
        salt: [u8; 4],
        /// initialization vector (8 bytes, chopped from key block)
        iv: [u8; 8],
    },

    /// Secrets for the CHACHA20_POLY1305 AEAD algorithm
    Chacha20Poly1305 {
        /// key (32 bytes)
        key: [u8; 32],
        /// initialization vector (12 bytes)
        iv: [u8; 12],
    },
}
