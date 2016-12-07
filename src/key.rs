#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PrivateKey(pub Vec<u8>);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Certificate(pub Vec<u8>);
