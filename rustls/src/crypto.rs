/// Pluggable crypto galore.
pub trait CryptoProvider: Send + Sync + 'static {}

/// Default crypto provider.
pub struct Ring;

impl CryptoProvider for Ring {}
