use crate::msgs::enums::SignatureScheme;

/// A struct representing the received Client Hello
pub struct ClientHello<'a> {
    server_name: Option<webpki::DNSNameRef<'a>>,
    sigschemes: &'a [SignatureScheme],
    alpn: Option<&'a[&'a[u8]]>,
}

impl<'a> ClientHello<'a> {
    /// Creates a new ClientHello
    pub fn new(server_name: Option<webpki::DNSNameRef<'a>>, sigschemes:  &'a [SignatureScheme],
    alpn: Option<&'a[&'a[u8]]>)->Self {
        ClientHello {server_name, sigschemes, alpn}
    }

    /// Get the server name indicator
    pub fn server_name(&self) -> Option<webpki::DNSNameRef> {
        self.server_name
    }

    /// Get the compatible signature schemes
    pub fn sigschemes(&self) -> &[SignatureScheme] {
        self.sigschemes
    }

    /// Get the alpn
    pub fn alpn(&self) -> Option<&'a[&'a[u8]]> {
        self.alpn
    }
}
