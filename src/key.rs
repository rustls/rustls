/// This type contains a private key by value.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PrivateKey(pub Vec<u8>);

/// This type contains a single certificate by value.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Certificate(pub Vec<u8>);
