use msgs::enums::{ProtocolVersion, HandshakeType};
use msgs::enums::{CipherSuite, Compression, ExtensionType, ECPointFormat, NamedCurve};
use msgs::enums::{HashAlgorithm, SignatureAlgorithm, HeartbeatMode, ServerNameType};
use msgs::base::{Payload, PayloadU8, PayloadU24};
use msgs::codec;
use msgs::codec::{Codec, Reader};

#[derive(Debug)]
pub struct Random {
  pub gmt_unix_time: u32,
  pub opaque: [u8; 28]
}

impl Codec for Random {
  fn encode(&self, bytes: &mut Vec<u8>) {
    codec::encode_u32(self.gmt_unix_time, bytes);
    bytes.extend_from_slice(&self.opaque);
  }

  fn read(r: &mut Reader) -> Option<Random> {
    let time = try_ret!(codec::read_u32(r));
    let bytes = try_ret!(r.take(28));
    let mut opaque = [0; 28];
    opaque.clone_from_slice(bytes);

    Some(Random { gmt_unix_time: time, opaque: opaque })
  }
}

impl Random {
  pub fn from_vec(bytes: &Vec<u8>) -> Random {
    assert_eq!(bytes.len(), 32);
    let mut rd = Reader::init(&bytes);
    Random::read(&mut rd).unwrap()
  }
}

#[derive(Debug)]
pub struct SessionID {
  pub bytes: Vec<u8>
}

impl Codec for SessionID {
  fn encode(&self, bytes: &mut Vec<u8>) {
    codec::encode_u8(self.bytes.len() as u8, bytes);
    bytes.extend_from_slice(&self.bytes[..]);
  }

  fn read(r: &mut Reader) -> Option<SessionID> {
    let mut ret = SessionID { bytes: Vec::new() };
    let len = try_ret!(codec::read_u8(r)) as usize;
    let sub = try_ret!(r.sub(len));
    ret.bytes.extend_from_slice(sub.rest());
    Some(ret)
  }
}

impl SessionID {
  pub fn empty() -> SessionID {
    SessionID { bytes: Vec::new() }
  }
}

#[derive(Debug)]
pub struct UnknownExtension {
  typ: ExtensionType,
  payload: Payload
}

impl UnknownExtension {
  fn encode(&self, bytes: &mut Vec<u8>) {
    self.typ.encode(bytes);
    self.payload.encode(bytes);
  }

  fn read(typ: ExtensionType, r: &mut Reader) -> Option<UnknownExtension> {
    let payload = try_ret!(Payload::read(r));
    Some(UnknownExtension { typ: typ, payload: payload })
  }
}

pub type ECPointFormatList = Vec<ECPointFormat>;

impl Codec for ECPointFormatList {
  fn encode(&self, bytes: &mut Vec<u8>) {
    codec::encode_vec_u8(bytes, self);
  }

  fn read(r: &mut Reader) -> Option<ECPointFormatList> {
    codec::read_vec_u8::<ECPointFormat>(r)
  }
}

pub trait SupportedPointFormats {
  fn supported() -> ECPointFormatList;
}

impl SupportedPointFormats for ECPointFormatList {
  fn supported() -> ECPointFormatList {
    vec![ECPointFormat::Uncompressed]
  }
}

pub type EllipticCurveList = Vec<NamedCurve>;

impl Codec for EllipticCurveList {
  fn encode(&self, bytes: &mut Vec<u8>) {
    codec::encode_vec_u16(bytes, self);
  }

  fn read(r: &mut Reader) -> Option<EllipticCurveList> {
    codec::read_vec_u16::<NamedCurve>(r)
  }
}

pub trait SupportedCurves {
  fn supported() -> EllipticCurveList;
}

impl SupportedCurves for EllipticCurveList {
  fn supported() -> EllipticCurveList {
    vec![ NamedCurve::secp256r1, NamedCurve::secp384r1 ]
  }
}

#[derive(Debug)]
pub struct SignatureAndHashAlgorithm {
  pub hash: HashAlgorithm,
  pub sign: SignatureAlgorithm
}

impl Codec for SignatureAndHashAlgorithm {
  fn encode(&self, bytes: &mut Vec<u8>) {
    self.hash.encode(bytes);
    self.sign.encode(bytes);
  }

  fn read(r: &mut Reader) -> Option<SignatureAndHashAlgorithm> {
    let hash = try_ret!(HashAlgorithm::read(r));
    let sign = try_ret!(SignatureAlgorithm::read(r));

    Some(SignatureAndHashAlgorithm { hash: hash, sign: sign })
  }
}

pub type SupportedSignatureAlgorithms = Vec<SignatureAndHashAlgorithm>;

pub trait SupportedMandatedSignatureAlgorithms {
  fn mandated() -> SupportedSignatureAlgorithms;
  fn supported() -> SupportedSignatureAlgorithms;
}

impl SupportedMandatedSignatureAlgorithms for SupportedSignatureAlgorithms {
  /* What SupportedSignatureAlgorithms are hardcoded in the RFC.
   * Yes, you cannot avoid SHA1 in standard TLS. */
  fn mandated() -> SupportedSignatureAlgorithms {
    vec![
      SignatureAndHashAlgorithm { hash: HashAlgorithm::SHA1, sign: SignatureAlgorithm::RSA },
      SignatureAndHashAlgorithm { hash: HashAlgorithm::SHA1, sign: SignatureAlgorithm::DSA },
      SignatureAndHashAlgorithm { hash: HashAlgorithm::SHA1, sign: SignatureAlgorithm::ECDSA }
    ]
  }

  fn supported() -> SupportedSignatureAlgorithms {
    /* In approximate decreasing order of security. */
    vec![
      SignatureAndHashAlgorithm { hash: HashAlgorithm::SHA512, sign: SignatureAlgorithm::ECDSA },
      SignatureAndHashAlgorithm { hash: HashAlgorithm::SHA384, sign: SignatureAlgorithm::ECDSA },
      SignatureAndHashAlgorithm { hash: HashAlgorithm::SHA256, sign: SignatureAlgorithm::ECDSA },

      SignatureAndHashAlgorithm { hash: HashAlgorithm::SHA512, sign: SignatureAlgorithm::RSA },
      SignatureAndHashAlgorithm { hash: HashAlgorithm::SHA384, sign: SignatureAlgorithm::RSA },
      SignatureAndHashAlgorithm { hash: HashAlgorithm::SHA256, sign: SignatureAlgorithm::RSA },

      /* Leave the truly crap ones for last */
      SignatureAndHashAlgorithm { hash: HashAlgorithm::SHA1, sign: SignatureAlgorithm::ECDSA },
      SignatureAndHashAlgorithm { hash: HashAlgorithm::SHA1, sign: SignatureAlgorithm::RSA },
    ]
  }
}

impl Codec for SupportedSignatureAlgorithms {
  fn encode(&self, bytes: &mut Vec<u8>) {
    codec::encode_vec_u16(bytes, self);
  }

  fn read(r: &mut Reader) -> Option<SupportedSignatureAlgorithms> {
    codec::read_vec_u16::<SignatureAndHashAlgorithm>(r)
  }
}

#[derive(Debug)]
pub enum ServerNamePayload {
  HostName(String),
  Unknown(Payload)
}

impl ServerNamePayload {
  fn read_hostname(r: &mut Reader) -> Option<ServerNamePayload> {
    let len = try_ret!(codec::read_u16(r)) as usize;
    let name = try_ret!(r.take(len));
    let hostname = String::from_utf8(name.to_vec());

    match hostname {
      Ok(n) => Some(ServerNamePayload::HostName(n)),
      _ => None
    }
  }

  fn encode_hostname(name: &String, bytes: &mut Vec<u8>) {
    codec::encode_u16(name.len() as u16, bytes);
    bytes.extend_from_slice(name.as_bytes());
  }

  fn encode(&self, bytes: &mut Vec<u8>) {
    match *self {
      ServerNamePayload::HostName(ref r) => ServerNamePayload::encode_hostname(r, bytes),
      ServerNamePayload::Unknown(ref r) => r.encode(bytes)
    }
  }
}

#[derive(Debug)]
pub struct ServerName {
  pub typ: ServerNameType,
  pub payload: ServerNamePayload
}

impl Codec for ServerName {
  fn encode(&self, bytes: &mut Vec<u8>) {
    self.typ.encode(bytes);
    self.payload.encode(bytes);
  }

  fn read(r: &mut Reader) -> Option<ServerName> {
    let typ = try_ret!(ServerNameType::read(r));

    let payload = match typ {
      ServerNameType::HostName =>
        try_ret!(ServerNamePayload::read_hostname(r)),
      _ =>
        ServerNamePayload::Unknown(try_ret!(Payload::read(r)))
    };

    Some(ServerName { typ: typ, payload: payload })
  }
}

pub type ServerNameRequest = Vec<ServerName>;

impl Codec for ServerNameRequest {
  fn encode(&self, bytes: &mut Vec<u8>) {
    codec::encode_vec_u16(bytes, self);
  }

  fn read(r: &mut Reader) -> Option<ServerNameRequest> {
    codec::read_vec_u16::<ServerName>(r)
  }
}

#[derive(Debug)]
pub enum ClientExtension {
  ECPointFormats(ECPointFormatList),
  EllipticCurves(EllipticCurveList),
  SignatureAlgorithms(SupportedSignatureAlgorithms),
  Heartbeat(HeartbeatMode),
  ServerName(ServerNameRequest),
  SessionTicketRequest,
  SessionTicketOffer(Payload),
  Unknown(UnknownExtension)
}

impl ClientExtension {
  pub fn get_type(&self) -> ExtensionType {
    match *self {
      ClientExtension::ECPointFormats(_) => ExtensionType::ECPointFormats,
      ClientExtension::EllipticCurves(_) => ExtensionType::EllipticCurves,
      ClientExtension::SignatureAlgorithms(_) => ExtensionType::SignatureAlgorithms,
      ClientExtension::Heartbeat(_) => ExtensionType::Heartbeat,
      ClientExtension::ServerName(_) => ExtensionType::ServerName,
      ClientExtension::SessionTicketRequest => ExtensionType::SessionTicket,
      ClientExtension::SessionTicketOffer(_) => ExtensionType::SessionTicket,
      ClientExtension::Unknown(ref r) => r.typ.clone()
    }
  }
}

impl Codec for ClientExtension {
  fn encode(&self, bytes: &mut Vec<u8>) {
    self.get_type().encode(bytes);

    let mut sub: Vec<u8> = Vec::new();
    match *self {
      ClientExtension::ECPointFormats(ref r) => r.encode(&mut sub),
      ClientExtension::EllipticCurves(ref r) => r.encode(&mut sub),
      ClientExtension::SignatureAlgorithms(ref r) => r.encode(&mut sub),
      ClientExtension::Heartbeat(ref r) => r.encode(&mut sub),
      ClientExtension::ServerName(ref r) => r.encode(&mut sub),
      ClientExtension::SessionTicketRequest => (),
      ClientExtension::SessionTicketOffer(ref r) => r.encode(&mut sub),
      ClientExtension::Unknown(ref r) => r.encode(&mut sub)
    }

    codec::encode_u16(sub.len() as u16, bytes);
    bytes.append(&mut sub);
  }

  fn read(r: &mut Reader) -> Option<ClientExtension> {
    let typ = try_ret!(ExtensionType::read(r));
    let len = try_ret!(codec::read_u16(r)) as usize;
    let mut sub = try_ret!(r.sub(len));

    Some(match typ {
      ExtensionType::ECPointFormats =>
        ClientExtension::ECPointFormats(try_ret!(ECPointFormatList::read(&mut sub))),
      ExtensionType::EllipticCurves =>
        ClientExtension::EllipticCurves(try_ret!(EllipticCurveList::read(&mut sub))),
      ExtensionType::SignatureAlgorithms =>
        ClientExtension::SignatureAlgorithms(try_ret!(SupportedSignatureAlgorithms::read(&mut sub))),
      ExtensionType::Heartbeat =>
        ClientExtension::Heartbeat(try_ret!(HeartbeatMode::read(&mut sub))),
      ExtensionType::ServerName =>
        ClientExtension::ServerName(try_ret!(ServerNameRequest::read(&mut sub))),
      ExtensionType::SessionTicket =>
        if sub.any_left() {
          ClientExtension::SessionTicketOffer(try_ret!(Payload::read(&mut sub)))
        } else {
          ClientExtension::SessionTicketRequest
        },
      _ =>
        ClientExtension::Unknown(try_ret!(UnknownExtension::read(typ, &mut sub)))
    })
  }
}

#[derive(Debug)]
pub enum ServerExtension {
  ECPointFormats(ECPointFormatList),
  Heartbeat(HeartbeatMode),
  ServerNameAcknowledgement,
  SessionTicketAcknowledgement,
  RenegotiationInfo(PayloadU8),
  Unknown(UnknownExtension)
}

impl ServerExtension {
  pub fn get_type(&self) -> ExtensionType {
    match *self {
      ServerExtension::ECPointFormats(_) => ExtensionType::ECPointFormats,
      ServerExtension::Heartbeat(_) => ExtensionType::Heartbeat,
      ServerExtension::ServerNameAcknowledgement => ExtensionType::ServerName,
      ServerExtension::SessionTicketAcknowledgement => ExtensionType::SessionTicket,
      ServerExtension::RenegotiationInfo(_) => ExtensionType::RenegotiationInfo,
      ServerExtension::Unknown(ref r) => r.typ.clone()
    }
  }
}

impl Codec for ServerExtension {
  fn encode(&self, bytes: &mut Vec<u8>) {
    self.get_type().encode(bytes);

    let mut sub: Vec<u8> = Vec::new();
    match *self {
      ServerExtension::ECPointFormats(ref r) => r.encode(&mut sub),
      ServerExtension::Heartbeat(ref r) => r.encode(&mut sub),
      ServerExtension::ServerNameAcknowledgement => (),
      ServerExtension::SessionTicketAcknowledgement => (),
      ServerExtension::RenegotiationInfo(ref r) => r.encode(&mut sub),
      ServerExtension::Unknown(ref r) => r.encode(&mut sub)
    }

    codec::encode_u16(sub.len() as u16, bytes);
    bytes.append(&mut sub);
  }

  fn read(r: &mut Reader) -> Option<ServerExtension> {
    let typ = try_ret!(ExtensionType::read(r));
    let len = try_ret!(codec::read_u16(r)) as usize;
    let mut sub = try_ret!(r.sub(len));

    Some(match typ {
      ExtensionType::ECPointFormats =>
        ServerExtension::ECPointFormats(try_ret!(ECPointFormatList::read(&mut sub))),
      ExtensionType::Heartbeat =>
        ServerExtension::Heartbeat(try_ret!(HeartbeatMode::read(&mut sub))),
      ExtensionType::ServerName =>
        ServerExtension::ServerNameAcknowledgement,
      ExtensionType::SessionTicket =>
        ServerExtension::SessionTicketAcknowledgement,
      ExtensionType::RenegotiationInfo =>
        ServerExtension::RenegotiationInfo(try_ret!(PayloadU8::read(&mut sub))),
      _ =>
        ServerExtension::Unknown(try_ret!(UnknownExtension::read(typ, &mut sub)))
    })
  }
}

#[derive(Debug)]
pub struct ClientHelloPayload {
  pub client_version: ProtocolVersion,
  pub random: Random,
  pub session_id: SessionID,
  pub cipher_suites: Vec<CipherSuite>,
  pub compression_methods: Vec<Compression>,
  pub extensions: Vec<ClientExtension>
}

impl Codec for ClientHelloPayload {
  fn encode(&self, bytes: &mut Vec<u8>) {
    self.client_version.encode(bytes);
    self.random.encode(bytes);
    self.session_id.encode(bytes);
    codec::encode_vec_u16(bytes, &self.cipher_suites);
    codec::encode_vec_u8(bytes, &self.compression_methods);

    if self.extensions.len() > 0 {
      codec::encode_vec_u16(bytes, &self.extensions);
    }
  }

  fn read(r: &mut Reader) -> Option<ClientHelloPayload> {

    let mut ret = ClientHelloPayload {
      client_version: try_ret!(ProtocolVersion::read(r)),
      random: try_ret!(Random::read(r)),
      session_id: try_ret!(SessionID::read(r)),
      cipher_suites: try_ret!(codec::read_vec_u16::<CipherSuite>(r)),
      compression_methods: try_ret!(codec::read_vec_u8::<Compression>(r)),
      extensions: Vec::new()
    };

    if r.any_left() {
      ret.extensions = try_ret!(codec::read_vec_u16::<ClientExtension>(r));
    }

    Some(ret)
  }
}

impl ClientHelloPayload {
  pub fn get_sni_extension(&self) -> Option<&ServerNameRequest> {
    let ext = try_ret!(self.extensions.iter().find(|x| x.get_type() == ExtensionType::ServerName));
    match *ext {
      ClientExtension::ServerName(ref req) => Some(req),
      _ => None
    }
  }

  pub fn get_sigalgs_extension(&self) -> Option<&SupportedSignatureAlgorithms> {
    let ext = try_ret!(self.extensions.iter().find(|x| x.get_type() == ExtensionType::SignatureAlgorithms));
    match *ext {
      ClientExtension::SignatureAlgorithms(ref req) => Some(req),
      _ => None
    }
  }

  pub fn get_eccurves_extension(&self) -> Option<&EllipticCurveList> {
    let ext = try_ret!(self.extensions.iter().find(|x| x.get_type() == ExtensionType::EllipticCurves));
    match *ext {
      ClientExtension::EllipticCurves(ref req) => Some(req),
      _ => None
    }
  }

  pub fn get_ecpoints_extension(&self) -> Option<&ECPointFormatList> {
    let ext = try_ret!(self.extensions.iter().find(|x| x.get_type() == ExtensionType::ECPointFormats));
    match *ext {
      ClientExtension::ECPointFormats(ref req) => Some(req),
      _ => None
    }
  }
}

#[derive(Debug)]
pub struct ServerHelloPayload {
  pub server_version: ProtocolVersion,
  pub random: Random,
  pub session_id: SessionID,
  pub cipher_suite: CipherSuite,
  pub compression_method: Compression,
  pub extensions: Vec<ServerExtension>
}

impl Codec for ServerHelloPayload {
  fn encode(&self, bytes: &mut Vec<u8>) {
    self.server_version.encode(bytes);
    self.random.encode(bytes);
    self.session_id.encode(bytes);
    self.cipher_suite.encode(bytes);
    self.compression_method.encode(bytes);

    if self.extensions.len() > 0 {
      codec::encode_vec_u16(bytes, &self.extensions);
    }
  }

  fn read(r: &mut Reader) -> Option<ServerHelloPayload> {
    let mut ret = ServerHelloPayload {
      server_version: try_ret!(ProtocolVersion::read(r)),
      random: try_ret!(Random::read(r)),
      session_id: try_ret!(SessionID::read(r)),
      cipher_suite: try_ret!(CipherSuite::read(r)),
      compression_method: try_ret!(Compression::read(r)),
      extensions: Vec::new()
    };

    if r.any_left() {
      ret.extensions = try_ret!(codec::read_vec_u16::<ServerExtension>(r));
    }

    Some(ret)
  }
}

pub type ASN1Cert = PayloadU24;
pub type CertificatePayload = Vec<ASN1Cert>;

impl Codec for CertificatePayload {
  fn encode(&self, bytes: &mut Vec<u8>) {
    codec::encode_vec_u24(bytes, self);
  }

  fn read(r: &mut Reader) -> Option<CertificatePayload> {
    codec::read_vec_u24::<ASN1Cert>(r)
  }
}

#[derive(Debug)]
pub enum ServerKeyExchangePayload {
  Unknown(Payload)
}

impl Codec for ServerKeyExchangePayload {
  fn encode(&self, bytes: &mut Vec<u8>) {
    match *self {
      ServerKeyExchangePayload::Unknown(ref x) => x.encode(bytes)
    }
  }

  fn read(r: &mut Reader) -> Option<ServerKeyExchangePayload> {
    /* read as Unknown, fully parse when we know the
     * KeyExchangeAlgorithm */
    Payload::read(r).and_then(|x| Some(ServerKeyExchangePayload::Unknown(x)))
  }
}

#[derive(Debug)]
pub enum HandshakePayload {
  HelloRequest,
  ClientHello(ClientHelloPayload),
  ServerHello(ServerHelloPayload),
  Certificate(CertificatePayload),
  ServerKeyExchange(ServerKeyExchangePayload),
  ServerHelloDone,
  Unknown(Payload)
}

impl HandshakePayload {
  fn encode(&self, bytes: &mut Vec<u8>) {
    match *self {
      HandshakePayload::HelloRequest => {},
      HandshakePayload::ClientHello(ref x) => x.encode(bytes),
      HandshakePayload::ServerHello(ref x) => x.encode(bytes),
      HandshakePayload::Certificate(ref x) => x.encode(bytes),
      HandshakePayload::ServerKeyExchange(ref x) => x.encode(bytes),
      HandshakePayload::ServerHelloDone => {}
      HandshakePayload::Unknown(ref x) => x.encode(bytes)
    }
  }
}

#[derive(Debug)]
pub struct HandshakeMessagePayload {
  pub typ: HandshakeType,
  pub payload: HandshakePayload
}

impl Codec for HandshakeMessagePayload {
  fn encode(&self, bytes: &mut Vec<u8>) {
    /* encode payload to learn length */
    let mut sub: Vec<u8> = Vec::new();
    self.payload.encode(&mut sub);

    /* output type, length, and encoded payload */
    self.typ.encode(bytes);
    codec::encode_u24(sub.len() as u32, bytes);
    bytes.append(&mut sub);
  }

  fn read(r: &mut Reader) -> Option<HandshakeMessagePayload> {
    let typ = try_ret!(HandshakeType::read(r));
    let len = try_ret!(codec::read_u24(r)) as usize;
    let mut sub = try_ret!(r.sub(len));

    let payload = match typ {
      HandshakeType::HelloRequest if sub.left() == 0 =>
        HandshakePayload::HelloRequest,
      HandshakeType::ClientHello =>
        HandshakePayload::ClientHello(try_ret!(ClientHelloPayload::read(&mut sub))),
      HandshakeType::ServerHello =>
        HandshakePayload::ServerHello(try_ret!(ServerHelloPayload::read(&mut sub))),
      HandshakeType::Certificate =>
        HandshakePayload::Certificate(try_ret!(CertificatePayload::read(&mut sub))),
      HandshakeType::ServerKeyExchange =>
        HandshakePayload::ServerKeyExchange(try_ret!(ServerKeyExchangePayload::read(&mut sub))),
      HandshakeType::ServerHelloDone if sub.left() == 0 =>
        HandshakePayload::ServerHelloDone,
      _ =>
        HandshakePayload::Unknown(try_ret!(Payload::read(&mut sub)))
    };

    Some(HandshakeMessagePayload { typ: typ, payload: payload })
  }
}
