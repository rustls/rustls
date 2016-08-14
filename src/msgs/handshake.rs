use msgs::enums::{ProtocolVersion, HandshakeType};
use msgs::enums::{CipherSuite, Compression, ExtensionType, ECPointFormat, NamedCurve};
use msgs::enums::{HashAlgorithm, SignatureAlgorithm, HeartbeatMode, ServerNameType};
use msgs::enums::ClientCertificateType;
use msgs::enums::ECCurveType;
use msgs::base::{Payload, PayloadU8, PayloadU16, PayloadU24};
use msgs::codec;
use msgs::codec::{Codec, Reader};

use std::io::Write;

macro_rules! declare_u8_vec(
  ($name:ident, $itemtype:ty) => {
    pub type $name = Vec<$itemtype>;

    impl Codec for $name {
      fn encode(&self, bytes: &mut Vec<u8>) {
        codec::encode_vec_u8(bytes, self);
      }

      fn read(r: &mut Reader) -> Option<$name> {
        codec::read_vec_u8::<$itemtype>(r)
      }
    }
  }
);

macro_rules! declare_u16_vec(
  ($name:ident, $itemtype:ty) => {
    pub type $name = Vec<$itemtype>;

    impl Codec for $name {
      fn encode(&self, bytes: &mut Vec<u8>) {
        codec::encode_vec_u16(bytes, self);
      }

      fn read(r: &mut Reader) -> Option<$name> {
        codec::read_vec_u16::<$itemtype>(r)
      }
    }
  }
);

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
  pub fn from_slice(bytes: &[u8]) -> Random {
    assert_eq!(bytes.len(), 32);
    let mut rd = Reader::init(&bytes);
    Random::read(&mut rd).unwrap()
  }

  pub fn write_slice(&self, mut bytes: &mut [u8]) {
    let mut buf = Vec::new();
    self.encode(&mut buf);
    assert_eq!(bytes.write(&buf).unwrap(), 32);
  }
}

#[derive(Debug, Clone)]
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
    self.payload.encode(bytes);
  }

  fn read(typ: ExtensionType, r: &mut Reader) -> Option<UnknownExtension> {
    let payload = try_ret!(Payload::read(r));
    Some(UnknownExtension { typ: typ, payload: payload })
  }
}

declare_u8_vec!(ECPointFormatList, ECPointFormat);

pub trait SupportedPointFormats {
  fn supported() -> ECPointFormatList;
}

impl SupportedPointFormats for ECPointFormatList {
  fn supported() -> ECPointFormatList {
    vec![ECPointFormat::Uncompressed]
  }
}

declare_u16_vec!(EllipticCurveList, NamedCurve);

pub trait SupportedCurves {
  fn supported() -> EllipticCurveList;
}

impl SupportedCurves for EllipticCurveList {
  fn supported() -> EllipticCurveList {
    vec![ NamedCurve::X25519, NamedCurve::secp384r1, NamedCurve::secp256r1 ]
  }
}

#[derive(Debug, Clone, PartialEq)]
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

declare_u16_vec!(SupportedSignatureAlgorithms, SignatureAndHashAlgorithm);

pub trait SupportedMandatedSignatureAlgorithms {
  fn mandated() -> SupportedSignatureAlgorithms;
  fn supported_verify() -> SupportedSignatureAlgorithms;
}

impl SupportedMandatedSignatureAlgorithms for SupportedSignatureAlgorithms {
  /// What SupportedSignatureAlgorithms are hardcoded in the RFC.
  /// Yes, you cannot avoid SHA1 in standard TLS.
  fn mandated() -> SupportedSignatureAlgorithms {
    vec![
      SignatureAndHashAlgorithm { hash: HashAlgorithm::SHA1, sign: SignatureAlgorithm::RSA },
      SignatureAndHashAlgorithm { hash: HashAlgorithm::SHA1, sign: SignatureAlgorithm::DSA },
      SignatureAndHashAlgorithm { hash: HashAlgorithm::SHA1, sign: SignatureAlgorithm::ECDSA }
    ]
  }

  /// Supported signature verification algorithms in decreasing order of expected security.
  fn supported_verify() -> SupportedSignatureAlgorithms {
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

declare_u16_vec!(ServerNameRequest, ServerName);

pub type ProtocolName = PayloadU8;
declare_u16_vec!(ProtocolNameList, ProtocolName);

pub trait ConvertProtocolNameList {
  fn from_strings(names: &[String]) -> Self;
  fn to_strings(&self) -> Vec<String>;
  fn to_single_string(&self) -> Option<String>;
}

impl ConvertProtocolNameList for ProtocolNameList {
  fn from_strings(names: &[String]) -> ProtocolNameList {
    let mut ret = Vec::new();

    for name in names {
      ret.push(PayloadU8::new(name.as_bytes().to_vec()));
    }

    ret
  }

  fn to_strings(&self) -> Vec<String> {
    let mut ret = Vec::new();
    for proto in self {
      match String::from_utf8(proto.0.clone()).ok() {
        Some(st) => ret.push(st),
        _ => {}
      }
    }
    ret
  }

  fn to_single_string(&self) -> Option<String> {
    if self.len() == 1 {
      String::from_utf8(self[0].0.clone()).ok()
    } else {
      None
    }
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
  Protocols(ProtocolNameList),
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
      ClientExtension::Protocols(_) => ExtensionType::ALProtocolNegotiation,
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
      ClientExtension::Protocols(ref r) => r.encode(&mut sub),
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
      ExtensionType::ALProtocolNegotiation =>
        ClientExtension::Protocols(try_ret!(ProtocolNameList::read(&mut sub))),
      _ =>
        ClientExtension::Unknown(try_ret!(UnknownExtension::read(typ, &mut sub)))
    })
  }
}

impl ClientExtension {
  /// Make a basic SNI ServerNameRequest quoting `hostname`.
  pub fn make_sni(hostname: &str) -> ClientExtension {
    let name = ServerName {
      typ: ServerNameType::HostName,
      payload: ServerNamePayload::HostName(hostname.to_string())
    };

    ClientExtension::ServerName(
      vec![ name ]
    )
  }
}

#[derive(Debug)]
pub enum ServerExtension {
  ECPointFormats(ECPointFormatList),
  Heartbeat(HeartbeatMode),
  ServerNameAcknowledgement,
  SessionTicketAcknowledgement,
  RenegotiationInfo(PayloadU8),
  Protocols(ProtocolNameList),
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
      ServerExtension::Protocols(_) => ExtensionType::ALProtocolNegotiation,
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
      ServerExtension::Protocols(ref r) => r.encode(&mut sub),
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
      ExtensionType::ALProtocolNegotiation =>
        ServerExtension::Protocols(try_ret!(ProtocolNameList::read(&mut sub))),
      _ =>
        ServerExtension::Unknown(try_ret!(UnknownExtension::read(typ, &mut sub)))
    })
  }
}

impl ServerExtension {
  pub fn make_alpn(proto: String) -> ServerExtension {
    ServerExtension::Protocols(ProtocolNameList::from_strings(&[proto]))
  }

  pub fn make_empty_renegotiation_info() -> ServerExtension {
    let empty = Vec::new();
    ServerExtension::RenegotiationInfo(PayloadU8::new(empty))
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
  pub fn find_extension(&self, ext: ExtensionType) -> Option<&ClientExtension> {
    self.extensions.iter().find(|x| x.get_type() == ext)
  }

  pub fn get_sni_extension(&self) -> Option<&ServerNameRequest> {
    let ext = try_ret!(self.find_extension(ExtensionType::ServerName));
    match *ext {
      ClientExtension::ServerName(ref req) => Some(req),
      _ => None
    }
  }

  pub fn get_sigalgs_extension(&self) -> Option<&SupportedSignatureAlgorithms> {
    let ext = try_ret!(self.find_extension(ExtensionType::SignatureAlgorithms));
    match *ext {
      ClientExtension::SignatureAlgorithms(ref req) => Some(req),
      _ => None
    }
  }

  pub fn get_eccurves_extension(&self) -> Option<&EllipticCurveList> {
    let ext = try_ret!(self.find_extension(ExtensionType::EllipticCurves));
    match *ext {
      ClientExtension::EllipticCurves(ref req) => Some(req),
      _ => None
    }
  }

  pub fn get_ecpoints_extension(&self) -> Option<&ECPointFormatList> {
    let ext = try_ret!(self.find_extension(ExtensionType::ECPointFormats));
    match *ext {
      ClientExtension::ECPointFormats(ref req) => Some(req),
      _ => None
    }
  }

  pub fn get_alpn_extension(&self) -> Option<&ProtocolNameList> {
    let ext = try_ret!(self.find_extension(ExtensionType::ALProtocolNegotiation));
    match *ext {
      ClientExtension::Protocols(ref req) => Some(req),
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

impl ServerHelloPayload {
  pub fn find_extension(&self, ext: ExtensionType) -> Option<&ServerExtension> {
    self.extensions.iter().find(|x| x.get_type() == ext)
  }

  pub fn get_alpn_protocol(&self) -> Option<String> {
    let ext = try_ret!(self.find_extension(ExtensionType::ALProtocolNegotiation));
    match *ext {
      ServerExtension::Protocols(ref protos) => protos.to_single_string(),
      _ => None
    }
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
pub enum KeyExchangeAlgorithm {
  DH,
  DHE,
  RSA,
  ECDH,
  ECDHE
}

/* We don't support arbitrary curves.  It's a terrible
 * idea and unnecessary attack surface.  Please,
 * get a grip. */
#[derive(Debug)]
pub struct ECParameters {
  pub curve_type: ECCurveType,
  pub named_curve: NamedCurve
}

impl Codec for ECParameters {
  fn encode(&self, bytes: &mut Vec<u8>) {
    self.curve_type.encode(bytes);
    self.named_curve.encode(bytes);
  }

  fn read(r: &mut Reader) -> Option<ECParameters> {
    let ct = try_ret!(ECCurveType::read(r));

    if ct != ECCurveType::NamedCurve {
      return None;
    }

    let nc = try_ret!(NamedCurve::read(r));

    Some(ECParameters { curve_type: ct, named_curve: nc })
  }
}

#[derive(Debug, Clone)]
pub struct DigitallySignedStruct {
  pub alg: SignatureAndHashAlgorithm,
  pub sig: PayloadU16
}

impl DigitallySignedStruct {
  pub fn new(alg: &SignatureAndHashAlgorithm, sig: Vec<u8>) -> DigitallySignedStruct {
    DigitallySignedStruct { alg: alg.clone(), sig: PayloadU16::new(sig) }
  }
}

impl Codec for DigitallySignedStruct {
  fn encode(&self, bytes: &mut Vec<u8>) {
    self.alg.encode(bytes);
    self.sig.encode(bytes);
  }

  fn read(r: &mut Reader) -> Option<DigitallySignedStruct> {
    let alg = try_ret!(SignatureAndHashAlgorithm::read(r));
    let sig = try_ret!(PayloadU16::read(r));

    Some(DigitallySignedStruct { alg: alg, sig: sig })
  }
}

#[derive(Debug)]
pub struct ClientECDHParams {
  pub public: PayloadU8
}

impl Codec for ClientECDHParams {
  fn encode(&self, bytes: &mut Vec<u8>) {
    self.public.encode(bytes);
  }

  fn read(r: &mut Reader) -> Option<ClientECDHParams> {
    let pb = try_ret!(PayloadU8::read(r));
    Some(ClientECDHParams { public: pb })
  }
}

#[derive(Debug)]
pub struct ServerECDHParams {
  pub curve_params: ECParameters,
  pub public: PayloadU8
}

impl ServerECDHParams {
  pub fn new(named_curve: &NamedCurve, pubkey: &Vec<u8>) -> ServerECDHParams {
    ServerECDHParams {
      curve_params: ECParameters {
        curve_type: ECCurveType::NamedCurve,
        named_curve: named_curve.clone()
      },
      public: PayloadU8::new(pubkey.clone())
    }
  }
}

impl Codec for ServerECDHParams {
  fn encode(&self, bytes: &mut Vec<u8>) {
    self.curve_params.encode(bytes);
    self.public.encode(bytes);
  }

  fn read(r: &mut Reader) -> Option<ServerECDHParams> {
    let cp = try_ret!(ECParameters::read(r));
    let pb = try_ret!(PayloadU8::read(r));

    Some(ServerECDHParams { curve_params: cp, public: pb })
  }
}

#[derive(Debug)]
pub struct ECDHEServerKeyExchange {
  pub params: ServerECDHParams,
  pub dss: DigitallySignedStruct
}

impl Codec for ECDHEServerKeyExchange {
  fn encode(&self, bytes: &mut Vec<u8>) {
    self.params.encode(bytes);
    self.dss.encode(bytes);
  }

  fn read(r: &mut Reader) -> Option<ECDHEServerKeyExchange> {
    let params = try_ret!(ServerECDHParams::read(r));
    let dss = try_ret!(DigitallySignedStruct::read(r));

    Some(ECDHEServerKeyExchange { params: params, dss: dss })
  }
}

#[derive(Debug)]
pub enum ServerKeyExchangePayload {
  ECDHE(ECDHEServerKeyExchange),
  Unknown(Payload)
}

impl Codec for ServerKeyExchangePayload {
  fn encode(&self, bytes: &mut Vec<u8>) {
    match *self {
      ServerKeyExchangePayload::ECDHE(ref x) => x.encode(bytes),
      ServerKeyExchangePayload::Unknown(ref x) => x.encode(bytes)
    }
  }

  fn read(r: &mut Reader) -> Option<ServerKeyExchangePayload> {
    /* read as Unknown, fully parse when we know the
     * KeyExchangeAlgorithm */
    Payload::read(r).and_then(|x| Some(ServerKeyExchangePayload::Unknown(x)))
  }
}

impl ServerKeyExchangePayload {
  pub fn unwrap_given_kxa(&self, kxa: &KeyExchangeAlgorithm) -> Option<ServerKeyExchangePayload> {
    if let ServerKeyExchangePayload::Unknown(ref unk) = *self {
      let mut rd = Reader::init(&unk.0);

      return match *kxa {
        KeyExchangeAlgorithm::ECDHE =>
          ECDHEServerKeyExchange::read(&mut rd).and_then(|x| Some(ServerKeyExchangePayload::ECDHE(x))),
        _ => None
      };
    }

    None
  }

  pub fn encode_params(&self, bytes: &mut Vec<u8>) {
    bytes.clear();

    match *self {
      ServerKeyExchangePayload::ECDHE(ref x) => x.params.encode(bytes),
      _ => (),
    };
  }

  pub fn get_sig(&self) -> Option<DigitallySignedStruct> {
    match *self {
      ServerKeyExchangePayload::ECDHE(ref x) => Some(x.dss.clone()),
      _ => None
    }
  }
}

/* -- CertificateRequest and sundries -- */
declare_u8_vec!(ClientCertificateTypes, ClientCertificateType);
pub type DistinguishedName = PayloadU16;
declare_u16_vec!(DistinguishedNames, DistinguishedName);

#[derive(Debug)]
pub struct CertificateRequestPayload {
  pub certtypes: ClientCertificateTypes,
  pub sigalgs: SupportedSignatureAlgorithms,
  pub canames: DistinguishedNames
}

impl Codec for CertificateRequestPayload {
  fn encode(&self, bytes: &mut Vec<u8>) {
    self.certtypes.encode(bytes);
    self.sigalgs.encode(bytes);
    self.canames.encode(bytes);
  }

  fn read(r: &mut Reader) -> Option<CertificateRequestPayload> {
    let certtypes = try_ret!(ClientCertificateTypes::read(r));
    let sigalgs = try_ret!(SupportedSignatureAlgorithms::read(r));
    let canames = try_ret!(DistinguishedNames::read(r));

    Some(CertificateRequestPayload {
      certtypes: certtypes,
      sigalgs: sigalgs,
      canames: canames
    })
  }
}

#[derive(Debug)]
pub enum HandshakePayload {
  HelloRequest,
  ClientHello(ClientHelloPayload),
  ServerHello(ServerHelloPayload),
  Certificate(CertificatePayload),
  ServerKeyExchange(ServerKeyExchangePayload),
  CertificateRequest(CertificateRequestPayload),
  CertificateVerify(DigitallySignedStruct),
  ServerHelloDone,
  ClientKeyExchange(Payload),
  Finished(Payload),
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
      HandshakePayload::ServerHelloDone => {},
      HandshakePayload::ClientKeyExchange(ref x) => x.encode(bytes),
      HandshakePayload::CertificateRequest(ref x) => x.encode(bytes),
      HandshakePayload::CertificateVerify(ref x) => x.encode(bytes),
      HandshakePayload::Finished(ref x) => x.encode(bytes),
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
      HandshakeType::ClientKeyExchange =>
        HandshakePayload::ClientKeyExchange(try_ret!(Payload::read(&mut sub))),
      HandshakeType::CertificateRequest =>
        HandshakePayload::CertificateRequest(try_ret!(CertificateRequestPayload::read(&mut sub))),
      HandshakeType::CertificateVerify =>
        HandshakePayload::CertificateVerify(try_ret!(DigitallySignedStruct::read(&mut sub))),
      HandshakeType::Finished =>
        HandshakePayload::Finished(try_ret!(Payload::read(&mut sub))),
      _ =>
        HandshakePayload::Unknown(try_ret!(Payload::read(&mut sub)))
    };

    Some(HandshakeMessagePayload { typ: typ, payload: payload })
  }
}

impl HandshakeMessagePayload {
  pub fn len(&self) -> usize {
    let mut buf = Vec::new();
    self.encode(&mut buf);
    buf.len()
  }
}
