use msgs::enums::{ContentType, HandshakeType, AlertDescription};
extern crate webpki;

/// rustls reports protocol errors using this type.
#[derive(Debug)]
pub enum TLSError {
  /// We received a TLS message that isn't valid right now.
  /// `expect_types` lists the message types we can expect right now.
  /// `got_type` is the type we found.  This error is typically
  /// caused by a buggy TLS stack (the peer or this one), a broken
  /// network, or an attack.
  InappropriateMessage { expect_types: Vec<ContentType>, got_type: ContentType },

  /// We received a TLS handshake message that isn't valid right now.
  /// `expect_types` lists the handshake message types we can expect
  /// right now.  `got_type` is the type we found.
  InappropriateHandshakeMessage { expect_types: Vec<HandshakeType>, got_type: HandshakeType },

  /// The peer sent us a syntactically incorrect TLS message.
  CorruptMessage,

  /// The peer sent us a TLS message with invalid contents.
  CorruptMessagePayload(ContentType),

  /// The peer didn't give us any certificates.
  NoCertificatesPresented,

  /// We couldn't decrypt a message.  This is invariably fatal.
  DecryptError,

  /// We received a fatal alert.  This means the peer is unhappy.
  AlertReceived(AlertDescription),

  /// The presented certificate chain is invalid.
  WebPKIError(webpki::Error),

  /// A catch-all error for unlikely errors.
  General(String)
}
