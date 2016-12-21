use msgs::enums::{ContentType, HandshakeType};
use msgs::message::{Message, MessagePayload};
use error::TLSError;

#[derive(Debug, Clone)]
pub struct Expectation {
  pub content_types: &'static [ContentType],
  pub handshake_types: &'static [HandshakeType]
}

impl Expectation {
  pub fn check_message(&self, m: &Message) -> Result<(), TLSError> {
    if !self.content_types.contains(&m.typ) {
      warn!("Received a {:?} message while expecting {:?}",
            m.typ, self.content_types);
      return Err(TLSError::InappropriateMessage {
        expect_types: self.content_types.to_vec(),
        got_type: m.typ
      });
    }

    if let MessagePayload::Handshake(ref hsp) = m.payload {
      if self.handshake_types.len() > 0
        && !self.handshake_types.contains(&hsp.typ) {
        warn!("Received a {:?} handshake message while expecting {:?}",
              hsp.typ, self.handshake_types);
        return Err(TLSError::InappropriateHandshakeMessage {
          expect_types: self.handshake_types.to_vec(),
          got_type: hsp.typ
        });
      }
    }

    Ok(())
  }
}

/*
 * Server Expectations
 */
pub static SERVER_EXPECT_CLIENT_HELLO: Expectation = Expectation {
  content_types: &[ContentType::Handshake],
  handshake_types: &[HandshakeType::ClientHello]
};
pub static SERVER_EXPECT_CERTIFICATE: Expectation = Expectation {
  content_types: &[ContentType::Handshake],
  handshake_types: &[HandshakeType::Certificate]
};
pub static SERVER_EXPECT_CLIENT_KX: Expectation = Expectation {
  content_types: &[ContentType::Handshake],
  handshake_types: &[HandshakeType::ClientKeyExchange]
};
pub static SERVER_EXPECT_CERTIFICATE_VERIFY: Expectation = Expectation {
  content_types: &[ContentType::Handshake],
  handshake_types: &[HandshakeType::CertificateVerify]
};
pub static SERVER_EXPECT_CCS: Expectation = Expectation {
  content_types: &[ContentType::ChangeCipherSpec],
  handshake_types: &[]
};
pub static SERVER_EXPECT_FINISHED: Expectation = Expectation {
  content_types: &[ContentType::Handshake],
  handshake_types: &[HandshakeType::Finished]
};
pub static SERVER_TRAFFIC: Expectation = Expectation {
  content_types: &[ContentType::ApplicationData],
  handshake_types: &[]
};

/*
 * Client Expectations
 */
pub static CLIENT_EXPECT_SERVER_HELLO: Expectation = Expectation  {
  content_types: &[ContentType::Handshake],
  handshake_types: &[HandshakeType::ServerHello]
};
pub static CLIENT_EXPECT_CERTIFICATE: Expectation = Expectation  {
  content_types: &[ContentType::Handshake],
  handshake_types: &[HandshakeType::Certificate]
};
pub static CLIENT_EXPECT_SERVER_KX: Expectation = Expectation  {
  content_types: &[ContentType::Handshake],
  handshake_types: &[HandshakeType::ServerKeyExchange]
};
pub static CLIENT_EXPECT_DONE_OR_CERTREQ: Expectation = Expectation  {
  content_types: &[ContentType::Handshake],
  handshake_types: &[HandshakeType::CertificateRequest, HandshakeType::ServerHelloDone]
};
pub static CLIENT_EXPECT_SERVER_HELLO_DONE: Expectation = Expectation  {
  content_types: &[ContentType::Handshake],
  handshake_types: &[HandshakeType::ServerHelloDone]
};
pub static CLIENT_EXPECT_CCS: Expectation = Expectation  {
  content_types: &[ContentType::ChangeCipherSpec],
  handshake_types: &[]
};
pub static CLIENT_EXPECT_NEW_TICKET: Expectation = Expectation  {
  content_types: &[ContentType::Handshake],
  handshake_types: &[HandshakeType::NewSessionTicket]
};
pub static CLIENT_EXPECT_CCS_RESUME: Expectation = Expectation  {
  content_types: &[ContentType::ChangeCipherSpec],
  handshake_types: &[]
};
pub static CLIENT_EXPECT_NEW_TICKET_RESUME: Expectation = Expectation  {
  content_types: &[ContentType::Handshake],
  handshake_types: &[HandshakeType::NewSessionTicket]
};
pub static CLIENT_EXPECT_FINISHED: Expectation = Expectation  {
  content_types: &[ContentType::Handshake],
  handshake_types: &[HandshakeType::Finished]
};

pub static CLIENT_EXPECT_FINISHED_RESUME: Expectation = Expectation  {
  content_types: &[ContentType::Handshake],
  handshake_types: &[]
};
pub static CLIENT_TRAFFIC: Expectation = Expectation  {
  content_types: &[ContentType::ApplicationData],
  handshake_types: &[]
};
