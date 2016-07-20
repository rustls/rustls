
use msgs::codec::{encode_u8, read_u8, encode_u16, read_u16, Reader, Codec};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ProtocolVersion {
  SSLv2,
  SSLv3,
  TLSv1_0,
  TLSv1_1,
  TLSv1_2,
  Unknown(u16)
}

impl Codec for ProtocolVersion {
  fn encode(&self, bytes: &mut Vec<u8>) {
    encode_u16(self.get_u16(), bytes);
  }

  fn read(r: &mut Reader) -> Option<ProtocolVersion> {
    let u = read_u16(r);

    if u.is_none() {
      return None
    }

    Some(match u.unwrap() {
      0x0200 => ProtocolVersion::SSLv2,
      0x0300 => ProtocolVersion::SSLv3,
      0x0301 => ProtocolVersion::TLSv1_0,
      0x0302 => ProtocolVersion::TLSv1_1,
      0x0303 => ProtocolVersion::TLSv1_2,
      x => ProtocolVersion::Unknown(x)
    })
  }
}

impl ProtocolVersion {
  pub fn get_u16(&self) -> u16 {
    match *self {
      ProtocolVersion::SSLv2 => 0x0200,
      ProtocolVersion::SSLv3 => 0x0300,
      ProtocolVersion::TLSv1_0 => 0x0301,
      ProtocolVersion::TLSv1_1 => 0x0302,
      ProtocolVersion::TLSv1_2 => 0x0303,
      ProtocolVersion::Unknown(v) => v
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum HashAlgorithm {
  NONE,
  MD5,
  SHA1,
  SHA224,
  SHA256,
  SHA384,
  SHA512,
  Unknown(u8)
}

impl Codec for HashAlgorithm {
  fn encode(&self, bytes: &mut Vec<u8>) {
    encode_u8(self.get_u8(), bytes);
  }

  fn read(r: &mut Reader) -> Option<HashAlgorithm> {
    let u = read_u8(r);

    if u.is_none() {
      return None
    }

    Some(match u.unwrap() {
      0x00 => HashAlgorithm::NONE,
      0x01 => HashAlgorithm::MD5,
      0x02 => HashAlgorithm::SHA1,
      0x03 => HashAlgorithm::SHA224,
      0x04 => HashAlgorithm::SHA256,
      0x05 => HashAlgorithm::SHA384,
      0x06 => HashAlgorithm::SHA512,
      x => HashAlgorithm::Unknown(x)
    })
  }
}

impl HashAlgorithm {
  pub fn get_u8(&self) -> u8 {
    match *self {
      HashAlgorithm::NONE => 0x00,
      HashAlgorithm::MD5 => 0x01,
      HashAlgorithm::SHA1 => 0x02,
      HashAlgorithm::SHA224 => 0x03,
      HashAlgorithm::SHA256 => 0x04,
      HashAlgorithm::SHA384 => 0x05,
      HashAlgorithm::SHA512 => 0x06,
      HashAlgorithm::Unknown(v) => v
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SignatureAlgorithm {
  Anonymous,
  RSA,
  DSA,
  ECDSA,
  Unknown(u8)
}

impl Codec for SignatureAlgorithm {
  fn encode(&self, bytes: &mut Vec<u8>) {
    encode_u8(self.get_u8(), bytes);
  }

  fn read(r: &mut Reader) -> Option<SignatureAlgorithm> {
    let u = read_u8(r);

    if u.is_none() {
      return None
    }

    Some(match u.unwrap() {
      0x00 => SignatureAlgorithm::Anonymous,
      0x01 => SignatureAlgorithm::RSA,
      0x02 => SignatureAlgorithm::DSA,
      0x03 => SignatureAlgorithm::ECDSA,
      x => SignatureAlgorithm::Unknown(x)
    })
  }
}

impl SignatureAlgorithm {
  pub fn get_u8(&self) -> u8 {
    match *self {
      SignatureAlgorithm::Anonymous => 0x00,
      SignatureAlgorithm::RSA => 0x01,
      SignatureAlgorithm::DSA => 0x02,
      SignatureAlgorithm::ECDSA => 0x03,
      SignatureAlgorithm::Unknown(v) => v
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ClientCertificateType {
  RSASign,
  DSSSign,
  RSAFixedDH,
  DSSFixedDH,
  RSAEphemeralDH,
  DSSEphemeralDH,
  FortezzaDMS,
  ECDSASign,
  RSAFixedECDH,
  ECDSAFixedECDH,
  Unknown(u8)
}

impl Codec for ClientCertificateType {
  fn encode(&self, bytes: &mut Vec<u8>) {
    encode_u8(self.get_u8(), bytes);
  }

  fn read(r: &mut Reader) -> Option<ClientCertificateType> {
    let u = read_u8(r);

    if u.is_none() {
      return None
    }

    Some(match u.unwrap() {
      0x01 => ClientCertificateType::RSASign,
      0x02 => ClientCertificateType::DSSSign,
      0x03 => ClientCertificateType::RSAFixedDH,
      0x04 => ClientCertificateType::DSSFixedDH,
      0x05 => ClientCertificateType::RSAEphemeralDH,
      0x06 => ClientCertificateType::DSSEphemeralDH,
      0x14 => ClientCertificateType::FortezzaDMS,
      0x40 => ClientCertificateType::ECDSASign,
      0x41 => ClientCertificateType::RSAFixedECDH,
      0x42 => ClientCertificateType::ECDSAFixedECDH,
      x => ClientCertificateType::Unknown(x)
    })
  }
}

impl ClientCertificateType {
  pub fn get_u8(&self) -> u8 {
    match *self {
      ClientCertificateType::RSASign => 0x01,
      ClientCertificateType::DSSSign => 0x02,
      ClientCertificateType::RSAFixedDH => 0x03,
      ClientCertificateType::DSSFixedDH => 0x04,
      ClientCertificateType::RSAEphemeralDH => 0x05,
      ClientCertificateType::DSSEphemeralDH => 0x06,
      ClientCertificateType::FortezzaDMS => 0x14,
      ClientCertificateType::ECDSASign => 0x40,
      ClientCertificateType::RSAFixedECDH => 0x41,
      ClientCertificateType::ECDSAFixedECDH => 0x42,
      ClientCertificateType::Unknown(v) => v
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Compression {
  Null,
  Deflate,
  LSZ,
  Unknown(u8)
}

impl Codec for Compression {
  fn encode(&self, bytes: &mut Vec<u8>) {
    encode_u8(self.get_u8(), bytes);
  }

  fn read(r: &mut Reader) -> Option<Compression> {
    let u = read_u8(r);

    if u.is_none() {
      return None
    }

    Some(match u.unwrap() {
      0x00 => Compression::Null,
      0x01 => Compression::Deflate,
      0x40 => Compression::LSZ,
      x => Compression::Unknown(x)
    })
  }
}

impl Compression {
  pub fn get_u8(&self) -> u8 {
    match *self {
      Compression::Null => 0x00,
      Compression::Deflate => 0x01,
      Compression::LSZ => 0x40,
      Compression::Unknown(v) => v
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ContentType {
  ChangeCipherSpec,
  Alert,
  Handshake,
  ApplicationData,
  Heartbeat,
  Unknown(u8)
}

impl Codec for ContentType {
  fn encode(&self, bytes: &mut Vec<u8>) {
    encode_u8(self.get_u8(), bytes);
  }

  fn read(r: &mut Reader) -> Option<ContentType> {
    let u = read_u8(r);

    if u.is_none() {
      return None
    }

    Some(match u.unwrap() {
      0x14 => ContentType::ChangeCipherSpec,
      0x15 => ContentType::Alert,
      0x16 => ContentType::Handshake,
      0x17 => ContentType::ApplicationData,
      0x18 => ContentType::Heartbeat,
      x => ContentType::Unknown(x)
    })
  }
}

impl ContentType {
  pub fn get_u8(&self) -> u8 {
    match *self {
      ContentType::ChangeCipherSpec => 0x14,
      ContentType::Alert => 0x15,
      ContentType::Handshake => 0x16,
      ContentType::ApplicationData => 0x17,
      ContentType::Heartbeat => 0x18,
      ContentType::Unknown(v) => v
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum HandshakeType {
  HelloRequest,
  ClientHello,
  ServerHello,
  Certificate,
  ServerKeyExchange,
  CertificateRequest,
  ServerHelloDone,
  CertificateVerify,
  ClientKeyExchange,
  Finished,
  CertificateURL,
  CertificateStatus,
  Unknown(u8)
}

impl Codec for HandshakeType {
  fn encode(&self, bytes: &mut Vec<u8>) {
    encode_u8(self.get_u8(), bytes);
  }

  fn read(r: &mut Reader) -> Option<HandshakeType> {
    let u = read_u8(r);

    if u.is_none() {
      return None
    }

    Some(match u.unwrap() {
      0x00 => HandshakeType::HelloRequest,
      0x01 => HandshakeType::ClientHello,
      0x02 => HandshakeType::ServerHello,
      0x0b => HandshakeType::Certificate,
      0x0c => HandshakeType::ServerKeyExchange,
      0x0d => HandshakeType::CertificateRequest,
      0x0e => HandshakeType::ServerHelloDone,
      0x0f => HandshakeType::CertificateVerify,
      0x10 => HandshakeType::ClientKeyExchange,
      0x14 => HandshakeType::Finished,
      0x15 => HandshakeType::CertificateURL,
      0x16 => HandshakeType::CertificateStatus,
      x => HandshakeType::Unknown(x)
    })
  }
}

impl HandshakeType {
  pub fn get_u8(&self) -> u8 {
    match *self {
      HandshakeType::HelloRequest => 0x00,
      HandshakeType::ClientHello => 0x01,
      HandshakeType::ServerHello => 0x02,
      HandshakeType::Certificate => 0x0b,
      HandshakeType::ServerKeyExchange => 0x0c,
      HandshakeType::CertificateRequest => 0x0d,
      HandshakeType::ServerHelloDone => 0x0e,
      HandshakeType::CertificateVerify => 0x0f,
      HandshakeType::ClientKeyExchange => 0x10,
      HandshakeType::Finished => 0x14,
      HandshakeType::CertificateURL => 0x15,
      HandshakeType::CertificateStatus => 0x16,
      HandshakeType::Unknown(v) => v
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AlertLevel {
  Warning,
  Fatal,
  Unknown(u8)
}

impl Codec for AlertLevel {
  fn encode(&self, bytes: &mut Vec<u8>) {
    encode_u8(self.get_u8(), bytes);
  }

  fn read(r: &mut Reader) -> Option<AlertLevel> {
    let u = read_u8(r);

    if u.is_none() {
      return None
    }

    Some(match u.unwrap() {
      0x01 => AlertLevel::Warning,
      0x02 => AlertLevel::Fatal,
      x => AlertLevel::Unknown(x)
    })
  }
}

impl AlertLevel {
  pub fn get_u8(&self) -> u8 {
    match *self {
      AlertLevel::Warning => 0x01,
      AlertLevel::Fatal => 0x02,
      AlertLevel::Unknown(v) => v
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AlertDescription {
  CloseNotify,
  UnexpectedMessage,
  BadRecordMac,
  DecryptionFailed,
  RecordOverflow,
  DecompressionFailure,
  HandshakeFailure,
  NoCertificate,
  BadCertificate,
  UnsupportedCertificate,
  CertificateRevoked,
  CertificateExpired,
  CertificateUnknown,
  IllegalParameter,
  UnknownCA,
  AccessDenied,
  DecodeError,
  DecryptError,
  ExportRestriction,
  ProtocolVersion,
  InsufficientSecurity,
  InternalError,
  UserCanceled,
  NoRenegotiation,
  UnsupportedExtension,
  UnrecognisedName,
  Unknown(u8)
}

impl Codec for AlertDescription {
  fn encode(&self, bytes: &mut Vec<u8>) {
    encode_u8(self.get_u8(), bytes);
  }

  fn read(r: &mut Reader) -> Option<AlertDescription> {
    let u = read_u8(r);

    if u.is_none() {
      return None
    }

    Some(match u.unwrap() {
      0x00 => AlertDescription::CloseNotify,
      0x0a => AlertDescription::UnexpectedMessage,
      0x14 => AlertDescription::BadRecordMac,
      0x15 => AlertDescription::DecryptionFailed,
      0x16 => AlertDescription::RecordOverflow,
      0x1e => AlertDescription::DecompressionFailure,
      0x28 => AlertDescription::HandshakeFailure,
      0x29 => AlertDescription::NoCertificate,
      0x2a => AlertDescription::BadCertificate,
      0x2b => AlertDescription::UnsupportedCertificate,
      0x2c => AlertDescription::CertificateRevoked,
      0x2d => AlertDescription::CertificateExpired,
      0x2e => AlertDescription::CertificateUnknown,
      0x2f => AlertDescription::IllegalParameter,
      0x30 => AlertDescription::UnknownCA,
      0x31 => AlertDescription::AccessDenied,
      0x32 => AlertDescription::DecodeError,
      0x33 => AlertDescription::DecryptError,
      0x3c => AlertDescription::ExportRestriction,
      0x46 => AlertDescription::ProtocolVersion,
      0x47 => AlertDescription::InsufficientSecurity,
      0x50 => AlertDescription::InternalError,
      0x5a => AlertDescription::UserCanceled,
      0x64 => AlertDescription::NoRenegotiation,
      0x6e => AlertDescription::UnsupportedExtension,
      0x70 => AlertDescription::UnrecognisedName,
      x => AlertDescription::Unknown(x)
    })
  }
}

impl AlertDescription {
  pub fn get_u8(&self) -> u8 {
    match *self {
      AlertDescription::CloseNotify => 0x00,
      AlertDescription::UnexpectedMessage => 0x0a,
      AlertDescription::BadRecordMac => 0x14,
      AlertDescription::DecryptionFailed => 0x15,
      AlertDescription::RecordOverflow => 0x16,
      AlertDescription::DecompressionFailure => 0x1e,
      AlertDescription::HandshakeFailure => 0x28,
      AlertDescription::NoCertificate => 0x29,
      AlertDescription::BadCertificate => 0x2a,
      AlertDescription::UnsupportedCertificate => 0x2b,
      AlertDescription::CertificateRevoked => 0x2c,
      AlertDescription::CertificateExpired => 0x2d,
      AlertDescription::CertificateUnknown => 0x2e,
      AlertDescription::IllegalParameter => 0x2f,
      AlertDescription::UnknownCA => 0x30,
      AlertDescription::AccessDenied => 0x31,
      AlertDescription::DecodeError => 0x32,
      AlertDescription::DecryptError => 0x33,
      AlertDescription::ExportRestriction => 0x3c,
      AlertDescription::ProtocolVersion => 0x46,
      AlertDescription::InsufficientSecurity => 0x47,
      AlertDescription::InternalError => 0x50,
      AlertDescription::UserCanceled => 0x5a,
      AlertDescription::NoRenegotiation => 0x64,
      AlertDescription::UnsupportedExtension => 0x6e,
      AlertDescription::UnrecognisedName => 0x70,
      AlertDescription::Unknown(v) => v
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum HeartbeatMessageType {
  Request,
  Response,
  Unknown(u8)
}

impl Codec for HeartbeatMessageType {
  fn encode(&self, bytes: &mut Vec<u8>) {
    encode_u8(self.get_u8(), bytes);
  }

  fn read(r: &mut Reader) -> Option<HeartbeatMessageType> {
    let u = read_u8(r);

    if u.is_none() {
      return None
    }

    Some(match u.unwrap() {
      0x01 => HeartbeatMessageType::Request,
      0x02 => HeartbeatMessageType::Response,
      x => HeartbeatMessageType::Unknown(x)
    })
  }
}

impl HeartbeatMessageType {
  pub fn get_u8(&self) -> u8 {
    match *self {
      HeartbeatMessageType::Request => 0x01,
      HeartbeatMessageType::Response => 0x02,
      HeartbeatMessageType::Unknown(v) => v
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ExtensionType {
  ServerName,
  MaxFragmentLength,
  ClientCertificateUrl,
  TrustedCAKeys,
  TruncatedHMAC,
  StatusRequest,
  UserMapping,
  ClientAuthz,
  ServerAuthz,
  CertificateType,
  EllipticCurves,
  ECPointFormats,
  SRP,
  SignatureAlgorithms,
  UseSRTP,
  Heartbeat,
  ALProtocolNegotiation,
  Padding,
  SessionTicket,
  NextProtocolNegotiation,
  ChannelId,
  RenegotiationInfo,
  Unknown(u16)
}

impl Codec for ExtensionType {
  fn encode(&self, bytes: &mut Vec<u8>) {
    encode_u16(self.get_u16(), bytes);
  }

  fn read(r: &mut Reader) -> Option<ExtensionType> {
    let u = read_u16(r);

    if u.is_none() {
      return None
    }

    Some(match u.unwrap() {
      0x0000 => ExtensionType::ServerName,
      0x0001 => ExtensionType::MaxFragmentLength,
      0x0002 => ExtensionType::ClientCertificateUrl,
      0x0003 => ExtensionType::TrustedCAKeys,
      0x0004 => ExtensionType::TruncatedHMAC,
      0x0005 => ExtensionType::StatusRequest,
      0x0006 => ExtensionType::UserMapping,
      0x0007 => ExtensionType::ClientAuthz,
      0x0008 => ExtensionType::ServerAuthz,
      0x0009 => ExtensionType::CertificateType,
      0x000a => ExtensionType::EllipticCurves,
      0x000b => ExtensionType::ECPointFormats,
      0x000c => ExtensionType::SRP,
      0x000d => ExtensionType::SignatureAlgorithms,
      0x000e => ExtensionType::UseSRTP,
      0x000f => ExtensionType::Heartbeat,
      0x0010 => ExtensionType::ALProtocolNegotiation,
      0x0015 => ExtensionType::Padding,
      0x0023 => ExtensionType::SessionTicket,
      0x3374 => ExtensionType::NextProtocolNegotiation,
      0x754f => ExtensionType::ChannelId,
      0xff01 => ExtensionType::RenegotiationInfo,
      x => ExtensionType::Unknown(x)
    })
  }
}

impl ExtensionType {
  pub fn get_u16(&self) -> u16 {
    match *self {
      ExtensionType::ServerName => 0x0000,
      ExtensionType::MaxFragmentLength => 0x0001,
      ExtensionType::ClientCertificateUrl => 0x0002,
      ExtensionType::TrustedCAKeys => 0x0003,
      ExtensionType::TruncatedHMAC => 0x0004,
      ExtensionType::StatusRequest => 0x0005,
      ExtensionType::UserMapping => 0x0006,
      ExtensionType::ClientAuthz => 0x0007,
      ExtensionType::ServerAuthz => 0x0008,
      ExtensionType::CertificateType => 0x0009,
      ExtensionType::EllipticCurves => 0x000a,
      ExtensionType::ECPointFormats => 0x000b,
      ExtensionType::SRP => 0x000c,
      ExtensionType::SignatureAlgorithms => 0x000d,
      ExtensionType::UseSRTP => 0x000e,
      ExtensionType::Heartbeat => 0x000f,
      ExtensionType::ALProtocolNegotiation => 0x0010,
      ExtensionType::Padding => 0x0015,
      ExtensionType::SessionTicket => 0x0023,
      ExtensionType::NextProtocolNegotiation => 0x3374,
      ExtensionType::ChannelId => 0x754f,
      ExtensionType::RenegotiationInfo => 0xff01,
      ExtensionType::Unknown(v) => v
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ServerNameType {
  HostName,
  Unknown(u8)
}

impl Codec for ServerNameType {
  fn encode(&self, bytes: &mut Vec<u8>) {
    encode_u8(self.get_u8(), bytes);
  }

  fn read(r: &mut Reader) -> Option<ServerNameType> {
    let u = read_u8(r);

    if u.is_none() {
      return None
    }

    Some(match u.unwrap() {
      0x00 => ServerNameType::HostName,
      x => ServerNameType::Unknown(x)
    })
  }
}

impl ServerNameType {
  pub fn get_u8(&self) -> u8 {
    match *self {
      ServerNameType::HostName => 0x00,
      ServerNameType::Unknown(v) => v
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NamedCurve {
  sect163k1,
  sect163r1,
  sect163r2,
  sect193r1,
  sect193r2,
  sect233k1,
  sect233r1,
  sect239k1,
  sect283k1,
  sect283r1,
  sect409k1,
  sect409r1,
  sect571k1,
  sect571r1,
  secp160k1,
  secp160r1,
  secp160r2,
  secp192k1,
  secp192r1,
  secp224k1,
  secp224r1,
  secp256k1,
  secp256r1,
  secp384r1,
  secp521r1,
  brainpoolp256r1,
  brainpoolp384r1,
  brainpoolp512r1,
  X25519,
  X448,
  arbitrary_explicit_prime_curves,
  arbitrary_explicit_char2_curves,
  Unknown(u16)
}

impl Codec for NamedCurve {
  fn encode(&self, bytes: &mut Vec<u8>) {
    encode_u16(self.get_u16(), bytes);
  }

  fn read(r: &mut Reader) -> Option<NamedCurve> {
    let u = read_u16(r);

    if u.is_none() {
      return None
    }

    Some(match u.unwrap() {
      0x0001 => NamedCurve::sect163k1,
      0x0002 => NamedCurve::sect163r1,
      0x0003 => NamedCurve::sect163r2,
      0x0004 => NamedCurve::sect193r1,
      0x0005 => NamedCurve::sect193r2,
      0x0006 => NamedCurve::sect233k1,
      0x0007 => NamedCurve::sect233r1,
      0x0008 => NamedCurve::sect239k1,
      0x0009 => NamedCurve::sect283k1,
      0x000a => NamedCurve::sect283r1,
      0x000b => NamedCurve::sect409k1,
      0x000c => NamedCurve::sect409r1,
      0x000d => NamedCurve::sect571k1,
      0x000e => NamedCurve::sect571r1,
      0x000f => NamedCurve::secp160k1,
      0x0010 => NamedCurve::secp160r1,
      0x0011 => NamedCurve::secp160r2,
      0x0012 => NamedCurve::secp192k1,
      0x0013 => NamedCurve::secp192r1,
      0x0014 => NamedCurve::secp224k1,
      0x0015 => NamedCurve::secp224r1,
      0x0016 => NamedCurve::secp256k1,
      0x0017 => NamedCurve::secp256r1,
      0x0018 => NamedCurve::secp384r1,
      0x0019 => NamedCurve::secp521r1,
      0x001a => NamedCurve::brainpoolp256r1,
      0x001b => NamedCurve::brainpoolp384r1,
      0x001c => NamedCurve::brainpoolp512r1,
      0x001d => NamedCurve::X25519,
      0x001e => NamedCurve::X448,
      0xff01 => NamedCurve::arbitrary_explicit_prime_curves,
      0xff02 => NamedCurve::arbitrary_explicit_char2_curves,
      x => NamedCurve::Unknown(x)
    })
  }
}

impl NamedCurve {
  pub fn get_u16(&self) -> u16 {
    match *self {
      NamedCurve::sect163k1 => 0x0001,
      NamedCurve::sect163r1 => 0x0002,
      NamedCurve::sect163r2 => 0x0003,
      NamedCurve::sect193r1 => 0x0004,
      NamedCurve::sect193r2 => 0x0005,
      NamedCurve::sect233k1 => 0x0006,
      NamedCurve::sect233r1 => 0x0007,
      NamedCurve::sect239k1 => 0x0008,
      NamedCurve::sect283k1 => 0x0009,
      NamedCurve::sect283r1 => 0x000a,
      NamedCurve::sect409k1 => 0x000b,
      NamedCurve::sect409r1 => 0x000c,
      NamedCurve::sect571k1 => 0x000d,
      NamedCurve::sect571r1 => 0x000e,
      NamedCurve::secp160k1 => 0x000f,
      NamedCurve::secp160r1 => 0x0010,
      NamedCurve::secp160r2 => 0x0011,
      NamedCurve::secp192k1 => 0x0012,
      NamedCurve::secp192r1 => 0x0013,
      NamedCurve::secp224k1 => 0x0014,
      NamedCurve::secp224r1 => 0x0015,
      NamedCurve::secp256k1 => 0x0016,
      NamedCurve::secp256r1 => 0x0017,
      NamedCurve::secp384r1 => 0x0018,
      NamedCurve::secp521r1 => 0x0019,
      NamedCurve::brainpoolp256r1 => 0x001a,
      NamedCurve::brainpoolp384r1 => 0x001b,
      NamedCurve::brainpoolp512r1 => 0x001c,
      NamedCurve::X25519 => 0x001d,
      NamedCurve::X448 => 0x001e,
      NamedCurve::arbitrary_explicit_prime_curves => 0xff01,
      NamedCurve::arbitrary_explicit_char2_curves => 0xff02,
      NamedCurve::Unknown(v) => v
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CipherSuite {
  TLS_NULL_WITH_NULL_NULL,
  TLS_RSA_WITH_NULL_MD5,
  TLS_RSA_WITH_NULL_SHA,
  TLS_RSA_EXPORT_WITH_RC4_40_MD5,
  TLS_RSA_WITH_RC4_128_MD5,
  TLS_RSA_WITH_RC4_128_SHA,
  TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
  TLS_RSA_WITH_IDEA_CBC_SHA,
  TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
  TLS_RSA_WITH_DES_CBC_SHA,
  TLS_RSA_WITH_3DES_EDE_CBC_SHA,
  TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
  TLS_DH_DSS_WITH_DES_CBC_SHA,
  TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
  TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
  TLS_DH_RSA_WITH_DES_CBC_SHA,
  TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
  TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
  TLS_DHE_DSS_WITH_DES_CBC_SHA,
  TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
  TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
  TLS_DHE_RSA_WITH_DES_CBC_SHA,
  TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
  TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
  TLS_DH_anon_WITH_RC4_128_MD5,
  TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
  TLS_DH_anon_WITH_DES_CBC_SHA,
  TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
  SSL_FORTEZZA_KEA_WITH_NULL_SHA,
  SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA,
  TLS_KRB5_WITH_DES_CBC_SHA_or_SSL_FORTEZZA_KEA_WITH_RC4_128_SHA,
  TLS_KRB5_WITH_3DES_EDE_CBC_SHA,
  TLS_KRB5_WITH_RC4_128_SHA,
  TLS_KRB5_WITH_IDEA_CBC_SHA,
  TLS_KRB5_WITH_DES_CBC_MD5,
  TLS_KRB5_WITH_3DES_EDE_CBC_MD5,
  TLS_KRB5_WITH_RC4_128_MD5,
  TLS_KRB5_WITH_IDEA_CBC_MD5,
  TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA,
  TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA,
  TLS_KRB5_EXPORT_WITH_RC4_40_SHA,
  TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5,
  TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5,
  TLS_KRB5_EXPORT_WITH_RC4_40_MD5,
  TLS_PSK_WITH_NULL_SHA,
  TLS_DHE_PSK_WITH_NULL_SHA,
  TLS_RSA_PSK_WITH_NULL_SHA,
  TLS_RSA_WITH_AES_128_CBC_SHA,
  TLS_DH_DSS_WITH_AES_128_CBC_SHA,
  TLS_DH_RSA_WITH_AES_128_CBC_SHA,
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
  TLS_DH_anon_WITH_AES_128_CBC_SHA,
  TLS_RSA_WITH_AES_256_CBC_SHA,
  TLS_DH_DSS_WITH_AES_256_CBC_SHA,
  TLS_DH_RSA_WITH_AES_256_CBC_SHA,
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
  TLS_DH_anon_WITH_AES_256_CBC_SHA,
  TLS_RSA_WITH_NULL_SHA256,
  TLS_RSA_WITH_AES_128_CBC_SHA256,
  TLS_RSA_WITH_AES_256_CBC_SHA256,
  TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
  TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
  TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
  TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
  TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
  TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
  TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
  TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA,
  TLS_ECDH_ECDSA_WITH_NULL_SHA_draft,
  TLS_ECDH_ECDSA_WITH_RC4_128_SHA_draft,
  TLS_ECDH_ECDSA_WITH_DES_CBC_SHA_draft,
  TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA_draft,
  TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA_draft,
  TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA_draft,
  TLS_ECDH_ECNRA_WITH_DES_CBC_SHA_draft,
  TLS_ECDH_ECNRA_WITH_3DES_EDE_CBC_SHA_draft,
  TLS_ECMQV_ECDSA_NULL_SHA_draft,
  TLS_ECMQV_ECDSA_WITH_RC4_128_SHA_draft,
  TLS_ECMQV_ECDSA_WITH_DES_CBC_SHA_draft,
  TLS_ECMQV_ECDSA_WITH_3DES_EDE_CBC_SHA_draft,
  TLS_ECMQV_ECNRA_NULL_SHA_draft,
  TLS_ECMQV_ECNRA_WITH_RC4_128_SHA_draft,
  TLS_ECMQV_ECNRA_WITH_DES_CBC_SHA_draft,
  TLS_ECMQV_ECNRA_WITH_3DES_EDE_CBC_SHA_draft,
  TLS_ECDH_anon_NULL_WITH_SHA_draft,
  TLS_ECDH_anon_WITH_RC4_128_SHA_draft,
  TLS_ECDH_anon_WITH_DES_CBC_SHA_draft,
  TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA_draft,
  TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA_draft,
  TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA_draft,
  TLS_RSA_EXPORT1024_WITH_RC4_56_MD5,
  TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5,
  TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
  TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
  TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
  TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
  TLS_DHE_DSS_WITH_RC4_128_SHA,
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
  TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
  TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
  TLS_DH_anon_WITH_AES_128_CBC_SHA256,
  TLS_DH_anon_WITH_AES_256_CBC_SHA256,
  TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD,
  TLS_DHE_DSS_WITH_AES_128_CBC_RMD,
  TLS_DHE_DSS_WITH_AES_256_CBC_RMD,
  TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD,
  TLS_DHE_RSA_WITH_AES_128_CBC_RMD,
  TLS_DHE_RSA_WITH_AES_256_CBC_RMD,
  TLS_RSA_WITH_3DES_EDE_CBC_RMD,
  TLS_RSA_WITH_AES_128_CBC_RMD,
  TLS_RSA_WITH_AES_256_CBC_RMD,
  TLS_GOSTR341094_WITH_28147_CNT_IMIT,
  TLS_GOSTR341001_WITH_28147_CNT_IMIT,
  TLS_GOSTR341094_WITH_NULL_GOSTR3411,
  TLS_GOSTR341001_WITH_NULL_GOSTR3411,
  TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
  TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
  TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
  TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
  TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
  TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA,
  TLS_PSK_WITH_RC4_128_SHA,
  TLS_PSK_WITH_3DES_EDE_CBC_SHA,
  TLS_PSK_WITH_AES_128_CBC_SHA,
  TLS_PSK_WITH_AES_256_CBC_SHA,
  TLS_DHE_PSK_WITH_RC4_128_SHA,
  TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
  TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
  TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
  TLS_RSA_PSK_WITH_RC4_128_SHA,
  TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
  TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
  TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
  TLS_RSA_WITH_SEED_CBC_SHA,
  TLS_DH_DSS_WITH_SEED_CBC_SHA,
  TLS_DH_RSA_WITH_SEED_CBC_SHA,
  TLS_DHE_DSS_WITH_SEED_CBC_SHA,
  TLS_DHE_RSA_WITH_SEED_CBC_SHA,
  TLS_DH_anon_WITH_SEED_CBC_SHA,
  TLS_RSA_WITH_AES_128_GCM_SHA256,
  TLS_RSA_WITH_AES_256_GCM_SHA384,
  TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
  TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
  TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
  TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
  TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
  TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
  TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
  TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
  TLS_DH_anon_WITH_AES_128_GCM_SHA256,
  TLS_DH_anon_WITH_AES_256_GCM_SHA384,
  TLS_PSK_WITH_AES_128_GCM_SHA256,
  TLS_PSK_WITH_AES_256_GCM_SHA384,
  TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
  TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
  TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
  TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
  TLS_PSK_WITH_AES_128_CBC_SHA256,
  TLS_PSK_WITH_AES_256_CBC_SHA384,
  TLS_PSK_WITH_NULL_SHA256,
  TLS_PSK_WITH_NULL_SHA384,
  TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
  TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
  TLS_DHE_PSK_WITH_NULL_SHA256,
  TLS_DHE_PSK_WITH_NULL_SHA384,
  TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
  TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
  TLS_RSA_PSK_WITH_NULL_SHA256,
  TLS_RSA_PSK_WITH_NULL_SHA384,
  TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
  TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256,
  TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
  TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
  TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
  TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256,
  TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
  TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256,
  TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256,
  TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
  TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
  TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256,
  TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
  TLS_ECDH_ECDSA_WITH_NULL_SHA,
  TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
  TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
  TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
  TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
  TLS_ECDHE_ECDSA_WITH_NULL_SHA,
  TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
  TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
  TLS_ECDH_RSA_WITH_NULL_SHA,
  TLS_ECDH_RSA_WITH_RC4_128_SHA,
  TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
  TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
  TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
  TLS_ECDHE_RSA_WITH_NULL_SHA,
  TLS_ECDHE_RSA_WITH_RC4_128_SHA,
  TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
  TLS_ECDH_anon_WITH_NULL_SHA,
  TLS_ECDH_anon_WITH_RC4_128_SHA,
  TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA,
  TLS_ECDH_anon_WITH_AES_128_CBC_SHA,
  TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
  TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
  TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
  TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
  TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
  TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
  TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
  TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
  TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
  TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
  TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
  TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
  TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
  TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
  TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
  TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
  TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
  TLS_ECDHE_PSK_WITH_RC4_128_SHA,
  TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
  TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
  TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
  TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
  TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
  TLS_ECDHE_PSK_WITH_NULL_SHA,
  TLS_ECDHE_PSK_WITH_NULL_SHA256,
  TLS_ECDHE_PSK_WITH_NULL_SHA384,
  TLS_RSA_WITH_ARIA_128_CBC_SHA256,
  TLS_RSA_WITH_ARIA_256_CBC_SHA384,
  TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256,
  TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384,
  TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256,
  TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384,
  TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256,
  TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384,
  TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256,
  TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384,
  TLS_DH_anon_WITH_ARIA_128_CBC_SHA256,
  TLS_DH_anon_WITH_ARIA_256_CBC_SHA384,
  TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256,
  TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384,
  TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256,
  TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384,
  TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256,
  TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384,
  TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256,
  TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384,
  TLS_RSA_WITH_ARIA_128_GCM_SHA256,
  TLS_RSA_WITH_ARIA_256_GCM_SHA384,
  TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
  TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
  TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256,
  TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384,
  TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
  TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
  TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256,
  TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384,
  TLS_DH_anon_WITH_ARIA_128_GCM_SHA256,
  TLS_DH_anon_WITH_ARIA_256_GCM_SHA384,
  TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
  TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
  TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256,
  TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384,
  TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
  TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
  TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256,
  TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384,
  TLS_PSK_WITH_ARIA_128_CBC_SHA256,
  TLS_PSK_WITH_ARIA_256_CBC_SHA384,
  TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256,
  TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384,
  TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256,
  TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384,
  TLS_PSK_WITH_ARIA_128_GCM_SHA256,
  TLS_PSK_WITH_ARIA_256_GCM_SHA384,
  TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
  TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
  TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
  TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
  TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256,
  TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384,
  TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
  TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
  TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
  TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
  TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
  TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
  TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
  TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,
  TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
  TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,
  TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
  TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
  TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
  TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
  TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256,
  TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384,
  TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256,
  TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384,
  TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256,
  TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384,
  TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
  TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
  TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
  TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
  TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
  TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
  TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
  TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
  TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256,
  TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384,
  TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256,
  TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384,
  TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,
  TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,
  TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,
  TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384,
  TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
  TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
  TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
  TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
  TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
  TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
  TLS_RSA_WITH_AES_128_CCM,
  TLS_RSA_WITH_AES_256_CCM,
  TLS_DHE_RSA_WITH_AES_128_CCM,
  TLS_DHE_RSA_WITH_AES_256_CCM,
  TLS_RSA_WITH_AES_128_CCM_8,
  TLS_RSA_WITH_AES_256_CCM_8,
  TLS_DHE_RSA_WITH_AES_128_CCM_8,
  TLS_DHE_RSA_WITH_AES_256_CCM_8,
  TLS_PSK_WITH_AES_128_CCM,
  TLS_PSK_WITH_AES_256_CCM,
  TLS_DHE_PSK_WITH_AES_128_CCM,
  TLS_DHE_PSK_WITH_AES_256_CCM,
  TLS_PSK_WITH_AES_128_CCM_8,
  TLS_PSK_WITH_AES_256_CCM_8,
  TLS_PSK_DHE_WITH_AES_128_CCM_8,
  TLS_PSK_DHE_WITH_AES_256_CCM_8,
  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
  TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
  TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
  TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
  TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
  TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
  SSL_RSA_FIPS_WITH_DES_CBC_SHA,
  SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA,
  Unknown(u16)
}

impl Codec for CipherSuite {
  fn encode(&self, bytes: &mut Vec<u8>) {
    encode_u16(self.get_u16(), bytes);
  }

  fn read(r: &mut Reader) -> Option<CipherSuite> {
    let u = read_u16(r);

    if u.is_none() {
      return None
    }

    Some(match u.unwrap() {
      0x0000 => CipherSuite::TLS_NULL_WITH_NULL_NULL,
      0x0001 => CipherSuite::TLS_RSA_WITH_NULL_MD5,
      0x0002 => CipherSuite::TLS_RSA_WITH_NULL_SHA,
      0x0003 => CipherSuite::TLS_RSA_EXPORT_WITH_RC4_40_MD5,
      0x0004 => CipherSuite::TLS_RSA_WITH_RC4_128_MD5,
      0x0005 => CipherSuite::TLS_RSA_WITH_RC4_128_SHA,
      0x0006 => CipherSuite::TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
      0x0007 => CipherSuite::TLS_RSA_WITH_IDEA_CBC_SHA,
      0x0008 => CipherSuite::TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
      0x0009 => CipherSuite::TLS_RSA_WITH_DES_CBC_SHA,
      0x000a => CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
      0x000b => CipherSuite::TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
      0x000c => CipherSuite::TLS_DH_DSS_WITH_DES_CBC_SHA,
      0x000d => CipherSuite::TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
      0x000e => CipherSuite::TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
      0x000f => CipherSuite::TLS_DH_RSA_WITH_DES_CBC_SHA,
      0x0010 => CipherSuite::TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
      0x0011 => CipherSuite::TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
      0x0012 => CipherSuite::TLS_DHE_DSS_WITH_DES_CBC_SHA,
      0x0013 => CipherSuite::TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
      0x0014 => CipherSuite::TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
      0x0015 => CipherSuite::TLS_DHE_RSA_WITH_DES_CBC_SHA,
      0x0016 => CipherSuite::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
      0x0017 => CipherSuite::TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
      0x0018 => CipherSuite::TLS_DH_anon_WITH_RC4_128_MD5,
      0x0019 => CipherSuite::TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
      0x001a => CipherSuite::TLS_DH_anon_WITH_DES_CBC_SHA,
      0x001b => CipherSuite::TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
      0x001c => CipherSuite::SSL_FORTEZZA_KEA_WITH_NULL_SHA,
      0x001d => CipherSuite::SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA,
      0x001e => CipherSuite::TLS_KRB5_WITH_DES_CBC_SHA_or_SSL_FORTEZZA_KEA_WITH_RC4_128_SHA,
      0x001f => CipherSuite::TLS_KRB5_WITH_3DES_EDE_CBC_SHA,
      0x0020 => CipherSuite::TLS_KRB5_WITH_RC4_128_SHA,
      0x0021 => CipherSuite::TLS_KRB5_WITH_IDEA_CBC_SHA,
      0x0022 => CipherSuite::TLS_KRB5_WITH_DES_CBC_MD5,
      0x0023 => CipherSuite::TLS_KRB5_WITH_3DES_EDE_CBC_MD5,
      0x0024 => CipherSuite::TLS_KRB5_WITH_RC4_128_MD5,
      0x0025 => CipherSuite::TLS_KRB5_WITH_IDEA_CBC_MD5,
      0x0026 => CipherSuite::TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA,
      0x0027 => CipherSuite::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA,
      0x0028 => CipherSuite::TLS_KRB5_EXPORT_WITH_RC4_40_SHA,
      0x0029 => CipherSuite::TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5,
      0x002a => CipherSuite::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5,
      0x002b => CipherSuite::TLS_KRB5_EXPORT_WITH_RC4_40_MD5,
      0x002c => CipherSuite::TLS_PSK_WITH_NULL_SHA,
      0x002d => CipherSuite::TLS_DHE_PSK_WITH_NULL_SHA,
      0x002e => CipherSuite::TLS_RSA_PSK_WITH_NULL_SHA,
      0x002f => CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
      0x0030 => CipherSuite::TLS_DH_DSS_WITH_AES_128_CBC_SHA,
      0x0031 => CipherSuite::TLS_DH_RSA_WITH_AES_128_CBC_SHA,
      0x0032 => CipherSuite::TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
      0x0033 => CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
      0x0034 => CipherSuite::TLS_DH_anon_WITH_AES_128_CBC_SHA,
      0x0035 => CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
      0x0036 => CipherSuite::TLS_DH_DSS_WITH_AES_256_CBC_SHA,
      0x0037 => CipherSuite::TLS_DH_RSA_WITH_AES_256_CBC_SHA,
      0x0038 => CipherSuite::TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
      0x0039 => CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
      0x003a => CipherSuite::TLS_DH_anon_WITH_AES_256_CBC_SHA,
      0x003b => CipherSuite::TLS_RSA_WITH_NULL_SHA256,
      0x003c => CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256,
      0x003d => CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256,
      0x003e => CipherSuite::TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
      0x003f => CipherSuite::TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
      0x0040 => CipherSuite::TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
      0x0041 => CipherSuite::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
      0x0042 => CipherSuite::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
      0x0043 => CipherSuite::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
      0x0044 => CipherSuite::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
      0x0045 => CipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
      0x0046 => CipherSuite::TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA,
      0x0047 => CipherSuite::TLS_ECDH_ECDSA_WITH_NULL_SHA_draft,
      0x0048 => CipherSuite::TLS_ECDH_ECDSA_WITH_RC4_128_SHA_draft,
      0x0049 => CipherSuite::TLS_ECDH_ECDSA_WITH_DES_CBC_SHA_draft,
      0x004a => CipherSuite::TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA_draft,
      0x004b => CipherSuite::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA_draft,
      0x004c => CipherSuite::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA_draft,
      0x004d => CipherSuite::TLS_ECDH_ECNRA_WITH_DES_CBC_SHA_draft,
      0x004e => CipherSuite::TLS_ECDH_ECNRA_WITH_3DES_EDE_CBC_SHA_draft,
      0x004f => CipherSuite::TLS_ECMQV_ECDSA_NULL_SHA_draft,
      0x0050 => CipherSuite::TLS_ECMQV_ECDSA_WITH_RC4_128_SHA_draft,
      0x0051 => CipherSuite::TLS_ECMQV_ECDSA_WITH_DES_CBC_SHA_draft,
      0x0052 => CipherSuite::TLS_ECMQV_ECDSA_WITH_3DES_EDE_CBC_SHA_draft,
      0x0053 => CipherSuite::TLS_ECMQV_ECNRA_NULL_SHA_draft,
      0x0054 => CipherSuite::TLS_ECMQV_ECNRA_WITH_RC4_128_SHA_draft,
      0x0055 => CipherSuite::TLS_ECMQV_ECNRA_WITH_DES_CBC_SHA_draft,
      0x0056 => CipherSuite::TLS_ECMQV_ECNRA_WITH_3DES_EDE_CBC_SHA_draft,
      0x0057 => CipherSuite::TLS_ECDH_anon_NULL_WITH_SHA_draft,
      0x0058 => CipherSuite::TLS_ECDH_anon_WITH_RC4_128_SHA_draft,
      0x0059 => CipherSuite::TLS_ECDH_anon_WITH_DES_CBC_SHA_draft,
      0x005a => CipherSuite::TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA_draft,
      0x005b => CipherSuite::TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA_draft,
      0x005c => CipherSuite::TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA_draft,
      0x0060 => CipherSuite::TLS_RSA_EXPORT1024_WITH_RC4_56_MD5,
      0x0061 => CipherSuite::TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5,
      0x0062 => CipherSuite::TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
      0x0063 => CipherSuite::TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
      0x0064 => CipherSuite::TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
      0x0065 => CipherSuite::TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
      0x0066 => CipherSuite::TLS_DHE_DSS_WITH_RC4_128_SHA,
      0x0067 => CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
      0x0068 => CipherSuite::TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
      0x0069 => CipherSuite::TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
      0x006a => CipherSuite::TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
      0x006b => CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
      0x006c => CipherSuite::TLS_DH_anon_WITH_AES_128_CBC_SHA256,
      0x006d => CipherSuite::TLS_DH_anon_WITH_AES_256_CBC_SHA256,
      0x0072 => CipherSuite::TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD,
      0x0073 => CipherSuite::TLS_DHE_DSS_WITH_AES_128_CBC_RMD,
      0x0074 => CipherSuite::TLS_DHE_DSS_WITH_AES_256_CBC_RMD,
      0x0077 => CipherSuite::TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD,
      0x0078 => CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_RMD,
      0x0079 => CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_RMD,
      0x007c => CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_RMD,
      0x007d => CipherSuite::TLS_RSA_WITH_AES_128_CBC_RMD,
      0x007e => CipherSuite::TLS_RSA_WITH_AES_256_CBC_RMD,
      0x0080 => CipherSuite::TLS_GOSTR341094_WITH_28147_CNT_IMIT,
      0x0081 => CipherSuite::TLS_GOSTR341001_WITH_28147_CNT_IMIT,
      0x0082 => CipherSuite::TLS_GOSTR341094_WITH_NULL_GOSTR3411,
      0x0083 => CipherSuite::TLS_GOSTR341001_WITH_NULL_GOSTR3411,
      0x0084 => CipherSuite::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
      0x0085 => CipherSuite::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
      0x0086 => CipherSuite::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
      0x0087 => CipherSuite::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
      0x0088 => CipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
      0x0089 => CipherSuite::TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA,
      0x008a => CipherSuite::TLS_PSK_WITH_RC4_128_SHA,
      0x008b => CipherSuite::TLS_PSK_WITH_3DES_EDE_CBC_SHA,
      0x008c => CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA,
      0x008d => CipherSuite::TLS_PSK_WITH_AES_256_CBC_SHA,
      0x008e => CipherSuite::TLS_DHE_PSK_WITH_RC4_128_SHA,
      0x008f => CipherSuite::TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
      0x0090 => CipherSuite::TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
      0x0091 => CipherSuite::TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
      0x0092 => CipherSuite::TLS_RSA_PSK_WITH_RC4_128_SHA,
      0x0093 => CipherSuite::TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
      0x0094 => CipherSuite::TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
      0x0095 => CipherSuite::TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
      0x0096 => CipherSuite::TLS_RSA_WITH_SEED_CBC_SHA,
      0x0097 => CipherSuite::TLS_DH_DSS_WITH_SEED_CBC_SHA,
      0x0098 => CipherSuite::TLS_DH_RSA_WITH_SEED_CBC_SHA,
      0x0099 => CipherSuite::TLS_DHE_DSS_WITH_SEED_CBC_SHA,
      0x009a => CipherSuite::TLS_DHE_RSA_WITH_SEED_CBC_SHA,
      0x009b => CipherSuite::TLS_DH_anon_WITH_SEED_CBC_SHA,
      0x009c => CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
      0x009d => CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
      0x009e => CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
      0x009f => CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
      0x00a0 => CipherSuite::TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
      0x00a1 => CipherSuite::TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
      0x00a2 => CipherSuite::TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
      0x00a3 => CipherSuite::TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
      0x00a4 => CipherSuite::TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
      0x00a5 => CipherSuite::TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
      0x00a6 => CipherSuite::TLS_DH_anon_WITH_AES_128_GCM_SHA256,
      0x00a7 => CipherSuite::TLS_DH_anon_WITH_AES_256_GCM_SHA384,
      0x00a8 => CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256,
      0x00a9 => CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384,
      0x00aa => CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
      0x00ab => CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
      0x00ac => CipherSuite::TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
      0x00ad => CipherSuite::TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
      0x00ae => CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA256,
      0x00af => CipherSuite::TLS_PSK_WITH_AES_256_CBC_SHA384,
      0x00b0 => CipherSuite::TLS_PSK_WITH_NULL_SHA256,
      0x00b1 => CipherSuite::TLS_PSK_WITH_NULL_SHA384,
      0x00b2 => CipherSuite::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
      0x00b3 => CipherSuite::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
      0x00b4 => CipherSuite::TLS_DHE_PSK_WITH_NULL_SHA256,
      0x00b5 => CipherSuite::TLS_DHE_PSK_WITH_NULL_SHA384,
      0x00b6 => CipherSuite::TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
      0x00b7 => CipherSuite::TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
      0x00b8 => CipherSuite::TLS_RSA_PSK_WITH_NULL_SHA256,
      0x00b9 => CipherSuite::TLS_RSA_PSK_WITH_NULL_SHA384,
      0x00ba => CipherSuite::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
      0x00bb => CipherSuite::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256,
      0x00bc => CipherSuite::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
      0x00bd => CipherSuite::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
      0x00be => CipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
      0x00bf => CipherSuite::TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256,
      0x00c0 => CipherSuite::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
      0x00c1 => CipherSuite::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256,
      0x00c2 => CipherSuite::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256,
      0x00c3 => CipherSuite::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
      0x00c4 => CipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
      0x00c5 => CipherSuite::TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256,
      0x00ff => CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
      0xc001 => CipherSuite::TLS_ECDH_ECDSA_WITH_NULL_SHA,
      0xc002 => CipherSuite::TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
      0xc003 => CipherSuite::TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
      0xc004 => CipherSuite::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
      0xc005 => CipherSuite::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
      0xc006 => CipherSuite::TLS_ECDHE_ECDSA_WITH_NULL_SHA,
      0xc007 => CipherSuite::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
      0xc008 => CipherSuite::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
      0xc009 => CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
      0xc00a => CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
      0xc00b => CipherSuite::TLS_ECDH_RSA_WITH_NULL_SHA,
      0xc00c => CipherSuite::TLS_ECDH_RSA_WITH_RC4_128_SHA,
      0xc00d => CipherSuite::TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
      0xc00e => CipherSuite::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
      0xc00f => CipherSuite::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
      0xc010 => CipherSuite::TLS_ECDHE_RSA_WITH_NULL_SHA,
      0xc011 => CipherSuite::TLS_ECDHE_RSA_WITH_RC4_128_SHA,
      0xc012 => CipherSuite::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
      0xc013 => CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
      0xc014 => CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
      0xc015 => CipherSuite::TLS_ECDH_anon_WITH_NULL_SHA,
      0xc016 => CipherSuite::TLS_ECDH_anon_WITH_RC4_128_SHA,
      0xc017 => CipherSuite::TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA,
      0xc018 => CipherSuite::TLS_ECDH_anon_WITH_AES_128_CBC_SHA,
      0xc019 => CipherSuite::TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
      0xc01a => CipherSuite::TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
      0xc01b => CipherSuite::TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
      0xc01c => CipherSuite::TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
      0xc01d => CipherSuite::TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
      0xc01e => CipherSuite::TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
      0xc01f => CipherSuite::TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
      0xc020 => CipherSuite::TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
      0xc021 => CipherSuite::TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
      0xc022 => CipherSuite::TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
      0xc023 => CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
      0xc024 => CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
      0xc025 => CipherSuite::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
      0xc026 => CipherSuite::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
      0xc027 => CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
      0xc028 => CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
      0xc029 => CipherSuite::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
      0xc02a => CipherSuite::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
      0xc02b => CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      0xc02c => CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
      0xc02d => CipherSuite::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
      0xc02e => CipherSuite::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
      0xc02f => CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      0xc030 => CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      0xc031 => CipherSuite::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
      0xc032 => CipherSuite::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
      0xc033 => CipherSuite::TLS_ECDHE_PSK_WITH_RC4_128_SHA,
      0xc034 => CipherSuite::TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
      0xc035 => CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
      0xc036 => CipherSuite::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
      0xc037 => CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
      0xc038 => CipherSuite::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
      0xc039 => CipherSuite::TLS_ECDHE_PSK_WITH_NULL_SHA,
      0xc03a => CipherSuite::TLS_ECDHE_PSK_WITH_NULL_SHA256,
      0xc03b => CipherSuite::TLS_ECDHE_PSK_WITH_NULL_SHA384,
      0xc03c => CipherSuite::TLS_RSA_WITH_ARIA_128_CBC_SHA256,
      0xc03d => CipherSuite::TLS_RSA_WITH_ARIA_256_CBC_SHA384,
      0xc03e => CipherSuite::TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256,
      0xc03f => CipherSuite::TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384,
      0xc040 => CipherSuite::TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256,
      0xc041 => CipherSuite::TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384,
      0xc042 => CipherSuite::TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256,
      0xc043 => CipherSuite::TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384,
      0xc044 => CipherSuite::TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256,
      0xc045 => CipherSuite::TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384,
      0xc046 => CipherSuite::TLS_DH_anon_WITH_ARIA_128_CBC_SHA256,
      0xc047 => CipherSuite::TLS_DH_anon_WITH_ARIA_256_CBC_SHA384,
      0xc048 => CipherSuite::TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256,
      0xc049 => CipherSuite::TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384,
      0xc04a => CipherSuite::TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256,
      0xc04b => CipherSuite::TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384,
      0xc04c => CipherSuite::TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256,
      0xc04d => CipherSuite::TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384,
      0xc04e => CipherSuite::TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256,
      0xc04f => CipherSuite::TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384,
      0xc050 => CipherSuite::TLS_RSA_WITH_ARIA_128_GCM_SHA256,
      0xc051 => CipherSuite::TLS_RSA_WITH_ARIA_256_GCM_SHA384,
      0xc052 => CipherSuite::TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
      0xc053 => CipherSuite::TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
      0xc054 => CipherSuite::TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256,
      0xc055 => CipherSuite::TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384,
      0xc056 => CipherSuite::TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
      0xc057 => CipherSuite::TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
      0xc058 => CipherSuite::TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256,
      0xc059 => CipherSuite::TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384,
      0xc05a => CipherSuite::TLS_DH_anon_WITH_ARIA_128_GCM_SHA256,
      0xc05b => CipherSuite::TLS_DH_anon_WITH_ARIA_256_GCM_SHA384,
      0xc05c => CipherSuite::TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
      0xc05d => CipherSuite::TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
      0xc05e => CipherSuite::TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256,
      0xc05f => CipherSuite::TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384,
      0xc060 => CipherSuite::TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
      0xc061 => CipherSuite::TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
      0xc062 => CipherSuite::TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256,
      0xc063 => CipherSuite::TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384,
      0xc064 => CipherSuite::TLS_PSK_WITH_ARIA_128_CBC_SHA256,
      0xc065 => CipherSuite::TLS_PSK_WITH_ARIA_256_CBC_SHA384,
      0xc066 => CipherSuite::TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256,
      0xc067 => CipherSuite::TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384,
      0xc068 => CipherSuite::TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256,
      0xc069 => CipherSuite::TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384,
      0xc06a => CipherSuite::TLS_PSK_WITH_ARIA_128_GCM_SHA256,
      0xc06b => CipherSuite::TLS_PSK_WITH_ARIA_256_GCM_SHA384,
      0xc06c => CipherSuite::TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
      0xc06d => CipherSuite::TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
      0xc06e => CipherSuite::TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
      0xc06f => CipherSuite::TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
      0xc070 => CipherSuite::TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256,
      0xc071 => CipherSuite::TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384,
      0xc072 => CipherSuite::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
      0xc073 => CipherSuite::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
      0xc074 => CipherSuite::TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
      0xc075 => CipherSuite::TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
      0xc076 => CipherSuite::TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
      0xc077 => CipherSuite::TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
      0xc078 => CipherSuite::TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
      0xc079 => CipherSuite::TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,
      0xc07a => CipherSuite::TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
      0xc07b => CipherSuite::TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,
      0xc07c => CipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
      0xc07d => CipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
      0xc07e => CipherSuite::TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
      0xc07f => CipherSuite::TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
      0xc080 => CipherSuite::TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256,
      0xc081 => CipherSuite::TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384,
      0xc082 => CipherSuite::TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256,
      0xc083 => CipherSuite::TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384,
      0xc084 => CipherSuite::TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256,
      0xc085 => CipherSuite::TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384,
      0xc086 => CipherSuite::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
      0xc087 => CipherSuite::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
      0xc088 => CipherSuite::TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
      0xc089 => CipherSuite::TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
      0xc08a => CipherSuite::TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
      0xc08b => CipherSuite::TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
      0xc08c => CipherSuite::TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
      0xc08d => CipherSuite::TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
      0xc08e => CipherSuite::TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256,
      0xc08f => CipherSuite::TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384,
      0xc090 => CipherSuite::TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256,
      0xc091 => CipherSuite::TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384,
      0xc092 => CipherSuite::TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,
      0xc093 => CipherSuite::TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,
      0xc094 => CipherSuite::TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,
      0xc095 => CipherSuite::TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384,
      0xc096 => CipherSuite::TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
      0xc097 => CipherSuite::TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
      0xc098 => CipherSuite::TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
      0xc099 => CipherSuite::TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
      0xc09a => CipherSuite::TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
      0xc09b => CipherSuite::TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
      0xc09c => CipherSuite::TLS_RSA_WITH_AES_128_CCM,
      0xc09d => CipherSuite::TLS_RSA_WITH_AES_256_CCM,
      0xc09e => CipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM,
      0xc09f => CipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM,
      0xc0a0 => CipherSuite::TLS_RSA_WITH_AES_128_CCM_8,
      0xc0a1 => CipherSuite::TLS_RSA_WITH_AES_256_CCM_8,
      0xc0a2 => CipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM_8,
      0xc0a3 => CipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM_8,
      0xc0a4 => CipherSuite::TLS_PSK_WITH_AES_128_CCM,
      0xc0a5 => CipherSuite::TLS_PSK_WITH_AES_256_CCM,
      0xc0a6 => CipherSuite::TLS_DHE_PSK_WITH_AES_128_CCM,
      0xc0a7 => CipherSuite::TLS_DHE_PSK_WITH_AES_256_CCM,
      0xc0a8 => CipherSuite::TLS_PSK_WITH_AES_128_CCM_8,
      0xc0a9 => CipherSuite::TLS_PSK_WITH_AES_256_CCM_8,
      0xc0aa => CipherSuite::TLS_PSK_DHE_WITH_AES_128_CCM_8,
      0xc0ab => CipherSuite::TLS_PSK_DHE_WITH_AES_256_CCM_8,
      0xcca8 => CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
      0xcca9 => CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
      0xccaa => CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
      0xccab => CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
      0xccac => CipherSuite::TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
      0xccad => CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
      0xccae => CipherSuite::TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
      0xfefe => CipherSuite::SSL_RSA_FIPS_WITH_DES_CBC_SHA,
      0xfeff => CipherSuite::SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA,
      x => CipherSuite::Unknown(x)
    })
  }
}

impl CipherSuite {
  pub fn get_u16(&self) -> u16 {
    match *self {
      CipherSuite::TLS_NULL_WITH_NULL_NULL => 0x0000,
      CipherSuite::TLS_RSA_WITH_NULL_MD5 => 0x0001,
      CipherSuite::TLS_RSA_WITH_NULL_SHA => 0x0002,
      CipherSuite::TLS_RSA_EXPORT_WITH_RC4_40_MD5 => 0x0003,
      CipherSuite::TLS_RSA_WITH_RC4_128_MD5 => 0x0004,
      CipherSuite::TLS_RSA_WITH_RC4_128_SHA => 0x0005,
      CipherSuite::TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 => 0x0006,
      CipherSuite::TLS_RSA_WITH_IDEA_CBC_SHA => 0x0007,
      CipherSuite::TLS_RSA_EXPORT_WITH_DES40_CBC_SHA => 0x0008,
      CipherSuite::TLS_RSA_WITH_DES_CBC_SHA => 0x0009,
      CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA => 0x000a,
      CipherSuite::TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA => 0x000b,
      CipherSuite::TLS_DH_DSS_WITH_DES_CBC_SHA => 0x000c,
      CipherSuite::TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA => 0x000d,
      CipherSuite::TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA => 0x000e,
      CipherSuite::TLS_DH_RSA_WITH_DES_CBC_SHA => 0x000f,
      CipherSuite::TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA => 0x0010,
      CipherSuite::TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA => 0x0011,
      CipherSuite::TLS_DHE_DSS_WITH_DES_CBC_SHA => 0x0012,
      CipherSuite::TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA => 0x0013,
      CipherSuite::TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA => 0x0014,
      CipherSuite::TLS_DHE_RSA_WITH_DES_CBC_SHA => 0x0015,
      CipherSuite::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA => 0x0016,
      CipherSuite::TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 => 0x0017,
      CipherSuite::TLS_DH_anon_WITH_RC4_128_MD5 => 0x0018,
      CipherSuite::TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA => 0x0019,
      CipherSuite::TLS_DH_anon_WITH_DES_CBC_SHA => 0x001a,
      CipherSuite::TLS_DH_anon_WITH_3DES_EDE_CBC_SHA => 0x001b,
      CipherSuite::SSL_FORTEZZA_KEA_WITH_NULL_SHA => 0x001c,
      CipherSuite::SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA => 0x001d,
      CipherSuite::TLS_KRB5_WITH_DES_CBC_SHA_or_SSL_FORTEZZA_KEA_WITH_RC4_128_SHA => 0x001e,
      CipherSuite::TLS_KRB5_WITH_3DES_EDE_CBC_SHA => 0x001f,
      CipherSuite::TLS_KRB5_WITH_RC4_128_SHA => 0x0020,
      CipherSuite::TLS_KRB5_WITH_IDEA_CBC_SHA => 0x0021,
      CipherSuite::TLS_KRB5_WITH_DES_CBC_MD5 => 0x0022,
      CipherSuite::TLS_KRB5_WITH_3DES_EDE_CBC_MD5 => 0x0023,
      CipherSuite::TLS_KRB5_WITH_RC4_128_MD5 => 0x0024,
      CipherSuite::TLS_KRB5_WITH_IDEA_CBC_MD5 => 0x0025,
      CipherSuite::TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA => 0x0026,
      CipherSuite::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA => 0x0027,
      CipherSuite::TLS_KRB5_EXPORT_WITH_RC4_40_SHA => 0x0028,
      CipherSuite::TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 => 0x0029,
      CipherSuite::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 => 0x002a,
      CipherSuite::TLS_KRB5_EXPORT_WITH_RC4_40_MD5 => 0x002b,
      CipherSuite::TLS_PSK_WITH_NULL_SHA => 0x002c,
      CipherSuite::TLS_DHE_PSK_WITH_NULL_SHA => 0x002d,
      CipherSuite::TLS_RSA_PSK_WITH_NULL_SHA => 0x002e,
      CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA => 0x002f,
      CipherSuite::TLS_DH_DSS_WITH_AES_128_CBC_SHA => 0x0030,
      CipherSuite::TLS_DH_RSA_WITH_AES_128_CBC_SHA => 0x0031,
      CipherSuite::TLS_DHE_DSS_WITH_AES_128_CBC_SHA => 0x0032,
      CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA => 0x0033,
      CipherSuite::TLS_DH_anon_WITH_AES_128_CBC_SHA => 0x0034,
      CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA => 0x0035,
      CipherSuite::TLS_DH_DSS_WITH_AES_256_CBC_SHA => 0x0036,
      CipherSuite::TLS_DH_RSA_WITH_AES_256_CBC_SHA => 0x0037,
      CipherSuite::TLS_DHE_DSS_WITH_AES_256_CBC_SHA => 0x0038,
      CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA => 0x0039,
      CipherSuite::TLS_DH_anon_WITH_AES_256_CBC_SHA => 0x003a,
      CipherSuite::TLS_RSA_WITH_NULL_SHA256 => 0x003b,
      CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256 => 0x003c,
      CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256 => 0x003d,
      CipherSuite::TLS_DH_DSS_WITH_AES_128_CBC_SHA256 => 0x003e,
      CipherSuite::TLS_DH_RSA_WITH_AES_128_CBC_SHA256 => 0x003f,
      CipherSuite::TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 => 0x0040,
      CipherSuite::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA => 0x0041,
      CipherSuite::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA => 0x0042,
      CipherSuite::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA => 0x0043,
      CipherSuite::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA => 0x0044,
      CipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA => 0x0045,
      CipherSuite::TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA => 0x0046,
      CipherSuite::TLS_ECDH_ECDSA_WITH_NULL_SHA_draft => 0x0047,
      CipherSuite::TLS_ECDH_ECDSA_WITH_RC4_128_SHA_draft => 0x0048,
      CipherSuite::TLS_ECDH_ECDSA_WITH_DES_CBC_SHA_draft => 0x0049,
      CipherSuite::TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA_draft => 0x004a,
      CipherSuite::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA_draft => 0x004b,
      CipherSuite::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA_draft => 0x004c,
      CipherSuite::TLS_ECDH_ECNRA_WITH_DES_CBC_SHA_draft => 0x004d,
      CipherSuite::TLS_ECDH_ECNRA_WITH_3DES_EDE_CBC_SHA_draft => 0x004e,
      CipherSuite::TLS_ECMQV_ECDSA_NULL_SHA_draft => 0x004f,
      CipherSuite::TLS_ECMQV_ECDSA_WITH_RC4_128_SHA_draft => 0x0050,
      CipherSuite::TLS_ECMQV_ECDSA_WITH_DES_CBC_SHA_draft => 0x0051,
      CipherSuite::TLS_ECMQV_ECDSA_WITH_3DES_EDE_CBC_SHA_draft => 0x0052,
      CipherSuite::TLS_ECMQV_ECNRA_NULL_SHA_draft => 0x0053,
      CipherSuite::TLS_ECMQV_ECNRA_WITH_RC4_128_SHA_draft => 0x0054,
      CipherSuite::TLS_ECMQV_ECNRA_WITH_DES_CBC_SHA_draft => 0x0055,
      CipherSuite::TLS_ECMQV_ECNRA_WITH_3DES_EDE_CBC_SHA_draft => 0x0056,
      CipherSuite::TLS_ECDH_anon_NULL_WITH_SHA_draft => 0x0057,
      CipherSuite::TLS_ECDH_anon_WITH_RC4_128_SHA_draft => 0x0058,
      CipherSuite::TLS_ECDH_anon_WITH_DES_CBC_SHA_draft => 0x0059,
      CipherSuite::TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA_draft => 0x005a,
      CipherSuite::TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA_draft => 0x005b,
      CipherSuite::TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA_draft => 0x005c,
      CipherSuite::TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 => 0x0060,
      CipherSuite::TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 => 0x0061,
      CipherSuite::TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA => 0x0062,
      CipherSuite::TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA => 0x0063,
      CipherSuite::TLS_RSA_EXPORT1024_WITH_RC4_56_SHA => 0x0064,
      CipherSuite::TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA => 0x0065,
      CipherSuite::TLS_DHE_DSS_WITH_RC4_128_SHA => 0x0066,
      CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 => 0x0067,
      CipherSuite::TLS_DH_DSS_WITH_AES_256_CBC_SHA256 => 0x0068,
      CipherSuite::TLS_DH_RSA_WITH_AES_256_CBC_SHA256 => 0x0069,
      CipherSuite::TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 => 0x006a,
      CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 => 0x006b,
      CipherSuite::TLS_DH_anon_WITH_AES_128_CBC_SHA256 => 0x006c,
      CipherSuite::TLS_DH_anon_WITH_AES_256_CBC_SHA256 => 0x006d,
      CipherSuite::TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD => 0x0072,
      CipherSuite::TLS_DHE_DSS_WITH_AES_128_CBC_RMD => 0x0073,
      CipherSuite::TLS_DHE_DSS_WITH_AES_256_CBC_RMD => 0x0074,
      CipherSuite::TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD => 0x0077,
      CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_RMD => 0x0078,
      CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_RMD => 0x0079,
      CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_RMD => 0x007c,
      CipherSuite::TLS_RSA_WITH_AES_128_CBC_RMD => 0x007d,
      CipherSuite::TLS_RSA_WITH_AES_256_CBC_RMD => 0x007e,
      CipherSuite::TLS_GOSTR341094_WITH_28147_CNT_IMIT => 0x0080,
      CipherSuite::TLS_GOSTR341001_WITH_28147_CNT_IMIT => 0x0081,
      CipherSuite::TLS_GOSTR341094_WITH_NULL_GOSTR3411 => 0x0082,
      CipherSuite::TLS_GOSTR341001_WITH_NULL_GOSTR3411 => 0x0083,
      CipherSuite::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA => 0x0084,
      CipherSuite::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA => 0x0085,
      CipherSuite::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA => 0x0086,
      CipherSuite::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA => 0x0087,
      CipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA => 0x0088,
      CipherSuite::TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA => 0x0089,
      CipherSuite::TLS_PSK_WITH_RC4_128_SHA => 0x008a,
      CipherSuite::TLS_PSK_WITH_3DES_EDE_CBC_SHA => 0x008b,
      CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA => 0x008c,
      CipherSuite::TLS_PSK_WITH_AES_256_CBC_SHA => 0x008d,
      CipherSuite::TLS_DHE_PSK_WITH_RC4_128_SHA => 0x008e,
      CipherSuite::TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA => 0x008f,
      CipherSuite::TLS_DHE_PSK_WITH_AES_128_CBC_SHA => 0x0090,
      CipherSuite::TLS_DHE_PSK_WITH_AES_256_CBC_SHA => 0x0091,
      CipherSuite::TLS_RSA_PSK_WITH_RC4_128_SHA => 0x0092,
      CipherSuite::TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA => 0x0093,
      CipherSuite::TLS_RSA_PSK_WITH_AES_128_CBC_SHA => 0x0094,
      CipherSuite::TLS_RSA_PSK_WITH_AES_256_CBC_SHA => 0x0095,
      CipherSuite::TLS_RSA_WITH_SEED_CBC_SHA => 0x0096,
      CipherSuite::TLS_DH_DSS_WITH_SEED_CBC_SHA => 0x0097,
      CipherSuite::TLS_DH_RSA_WITH_SEED_CBC_SHA => 0x0098,
      CipherSuite::TLS_DHE_DSS_WITH_SEED_CBC_SHA => 0x0099,
      CipherSuite::TLS_DHE_RSA_WITH_SEED_CBC_SHA => 0x009a,
      CipherSuite::TLS_DH_anon_WITH_SEED_CBC_SHA => 0x009b,
      CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256 => 0x009c,
      CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384 => 0x009d,
      CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 => 0x009e,
      CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 => 0x009f,
      CipherSuite::TLS_DH_RSA_WITH_AES_128_GCM_SHA256 => 0x00a0,
      CipherSuite::TLS_DH_RSA_WITH_AES_256_GCM_SHA384 => 0x00a1,
      CipherSuite::TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 => 0x00a2,
      CipherSuite::TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 => 0x00a3,
      CipherSuite::TLS_DH_DSS_WITH_AES_128_GCM_SHA256 => 0x00a4,
      CipherSuite::TLS_DH_DSS_WITH_AES_256_GCM_SHA384 => 0x00a5,
      CipherSuite::TLS_DH_anon_WITH_AES_128_GCM_SHA256 => 0x00a6,
      CipherSuite::TLS_DH_anon_WITH_AES_256_GCM_SHA384 => 0x00a7,
      CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256 => 0x00a8,
      CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384 => 0x00a9,
      CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 => 0x00aa,
      CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 => 0x00ab,
      CipherSuite::TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 => 0x00ac,
      CipherSuite::TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 => 0x00ad,
      CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA256 => 0x00ae,
      CipherSuite::TLS_PSK_WITH_AES_256_CBC_SHA384 => 0x00af,
      CipherSuite::TLS_PSK_WITH_NULL_SHA256 => 0x00b0,
      CipherSuite::TLS_PSK_WITH_NULL_SHA384 => 0x00b1,
      CipherSuite::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 => 0x00b2,
      CipherSuite::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 => 0x00b3,
      CipherSuite::TLS_DHE_PSK_WITH_NULL_SHA256 => 0x00b4,
      CipherSuite::TLS_DHE_PSK_WITH_NULL_SHA384 => 0x00b5,
      CipherSuite::TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 => 0x00b6,
      CipherSuite::TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 => 0x00b7,
      CipherSuite::TLS_RSA_PSK_WITH_NULL_SHA256 => 0x00b8,
      CipherSuite::TLS_RSA_PSK_WITH_NULL_SHA384 => 0x00b9,
      CipherSuite::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 => 0x00ba,
      CipherSuite::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 => 0x00bb,
      CipherSuite::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 => 0x00bc,
      CipherSuite::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 => 0x00bd,
      CipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 => 0x00be,
      CipherSuite::TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 => 0x00bf,
      CipherSuite::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 => 0x00c0,
      CipherSuite::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 => 0x00c1,
      CipherSuite::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 => 0x00c2,
      CipherSuite::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 => 0x00c3,
      CipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 => 0x00c4,
      CipherSuite::TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 => 0x00c5,
      CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV => 0x00ff,
      CipherSuite::TLS_ECDH_ECDSA_WITH_NULL_SHA => 0xc001,
      CipherSuite::TLS_ECDH_ECDSA_WITH_RC4_128_SHA => 0xc002,
      CipherSuite::TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA => 0xc003,
      CipherSuite::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA => 0xc004,
      CipherSuite::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA => 0xc005,
      CipherSuite::TLS_ECDHE_ECDSA_WITH_NULL_SHA => 0xc006,
      CipherSuite::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA => 0xc007,
      CipherSuite::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA => 0xc008,
      CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => 0xc009,
      CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => 0xc00a,
      CipherSuite::TLS_ECDH_RSA_WITH_NULL_SHA => 0xc00b,
      CipherSuite::TLS_ECDH_RSA_WITH_RC4_128_SHA => 0xc00c,
      CipherSuite::TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA => 0xc00d,
      CipherSuite::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA => 0xc00e,
      CipherSuite::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA => 0xc00f,
      CipherSuite::TLS_ECDHE_RSA_WITH_NULL_SHA => 0xc010,
      CipherSuite::TLS_ECDHE_RSA_WITH_RC4_128_SHA => 0xc011,
      CipherSuite::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA => 0xc012,
      CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => 0xc013,
      CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => 0xc014,
      CipherSuite::TLS_ECDH_anon_WITH_NULL_SHA => 0xc015,
      CipherSuite::TLS_ECDH_anon_WITH_RC4_128_SHA => 0xc016,
      CipherSuite::TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA => 0xc017,
      CipherSuite::TLS_ECDH_anon_WITH_AES_128_CBC_SHA => 0xc018,
      CipherSuite::TLS_ECDH_anon_WITH_AES_256_CBC_SHA => 0xc019,
      CipherSuite::TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA => 0xc01a,
      CipherSuite::TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA => 0xc01b,
      CipherSuite::TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA => 0xc01c,
      CipherSuite::TLS_SRP_SHA_WITH_AES_128_CBC_SHA => 0xc01d,
      CipherSuite::TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA => 0xc01e,
      CipherSuite::TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA => 0xc01f,
      CipherSuite::TLS_SRP_SHA_WITH_AES_256_CBC_SHA => 0xc020,
      CipherSuite::TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA => 0xc021,
      CipherSuite::TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA => 0xc022,
      CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 => 0xc023,
      CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 => 0xc024,
      CipherSuite::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 => 0xc025,
      CipherSuite::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 => 0xc026,
      CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 => 0xc027,
      CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => 0xc028,
      CipherSuite::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 => 0xc029,
      CipherSuite::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 => 0xc02a,
      CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => 0xc02b,
      CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => 0xc02c,
      CipherSuite::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 => 0xc02d,
      CipherSuite::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 => 0xc02e,
      CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => 0xc02f,
      CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => 0xc030,
      CipherSuite::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 => 0xc031,
      CipherSuite::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 => 0xc032,
      CipherSuite::TLS_ECDHE_PSK_WITH_RC4_128_SHA => 0xc033,
      CipherSuite::TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA => 0xc034,
      CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA => 0xc035,
      CipherSuite::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA => 0xc036,
      CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 => 0xc037,
      CipherSuite::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 => 0xc038,
      CipherSuite::TLS_ECDHE_PSK_WITH_NULL_SHA => 0xc039,
      CipherSuite::TLS_ECDHE_PSK_WITH_NULL_SHA256 => 0xc03a,
      CipherSuite::TLS_ECDHE_PSK_WITH_NULL_SHA384 => 0xc03b,
      CipherSuite::TLS_RSA_WITH_ARIA_128_CBC_SHA256 => 0xc03c,
      CipherSuite::TLS_RSA_WITH_ARIA_256_CBC_SHA384 => 0xc03d,
      CipherSuite::TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 => 0xc03e,
      CipherSuite::TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 => 0xc03f,
      CipherSuite::TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 => 0xc040,
      CipherSuite::TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 => 0xc041,
      CipherSuite::TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 => 0xc042,
      CipherSuite::TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 => 0xc043,
      CipherSuite::TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 => 0xc044,
      CipherSuite::TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 => 0xc045,
      CipherSuite::TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 => 0xc046,
      CipherSuite::TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 => 0xc047,
      CipherSuite::TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 => 0xc048,
      CipherSuite::TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 => 0xc049,
      CipherSuite::TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 => 0xc04a,
      CipherSuite::TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 => 0xc04b,
      CipherSuite::TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 => 0xc04c,
      CipherSuite::TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 => 0xc04d,
      CipherSuite::TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 => 0xc04e,
      CipherSuite::TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 => 0xc04f,
      CipherSuite::TLS_RSA_WITH_ARIA_128_GCM_SHA256 => 0xc050,
      CipherSuite::TLS_RSA_WITH_ARIA_256_GCM_SHA384 => 0xc051,
      CipherSuite::TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 => 0xc052,
      CipherSuite::TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 => 0xc053,
      CipherSuite::TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 => 0xc054,
      CipherSuite::TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 => 0xc055,
      CipherSuite::TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 => 0xc056,
      CipherSuite::TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 => 0xc057,
      CipherSuite::TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 => 0xc058,
      CipherSuite::TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 => 0xc059,
      CipherSuite::TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 => 0xc05a,
      CipherSuite::TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 => 0xc05b,
      CipherSuite::TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 => 0xc05c,
      CipherSuite::TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 => 0xc05d,
      CipherSuite::TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 => 0xc05e,
      CipherSuite::TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 => 0xc05f,
      CipherSuite::TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 => 0xc060,
      CipherSuite::TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 => 0xc061,
      CipherSuite::TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 => 0xc062,
      CipherSuite::TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 => 0xc063,
      CipherSuite::TLS_PSK_WITH_ARIA_128_CBC_SHA256 => 0xc064,
      CipherSuite::TLS_PSK_WITH_ARIA_256_CBC_SHA384 => 0xc065,
      CipherSuite::TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 => 0xc066,
      CipherSuite::TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 => 0xc067,
      CipherSuite::TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 => 0xc068,
      CipherSuite::TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 => 0xc069,
      CipherSuite::TLS_PSK_WITH_ARIA_128_GCM_SHA256 => 0xc06a,
      CipherSuite::TLS_PSK_WITH_ARIA_256_GCM_SHA384 => 0xc06b,
      CipherSuite::TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 => 0xc06c,
      CipherSuite::TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 => 0xc06d,
      CipherSuite::TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 => 0xc06e,
      CipherSuite::TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 => 0xc06f,
      CipherSuite::TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 => 0xc070,
      CipherSuite::TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 => 0xc071,
      CipherSuite::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 => 0xc072,
      CipherSuite::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 => 0xc073,
      CipherSuite::TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 => 0xc074,
      CipherSuite::TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 => 0xc075,
      CipherSuite::TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 => 0xc076,
      CipherSuite::TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 => 0xc077,
      CipherSuite::TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 => 0xc078,
      CipherSuite::TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 => 0xc079,
      CipherSuite::TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc07a,
      CipherSuite::TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc07b,
      CipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc07c,
      CipherSuite::TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc07d,
      CipherSuite::TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc07e,
      CipherSuite::TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc07f,
      CipherSuite::TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 => 0xc080,
      CipherSuite::TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 => 0xc081,
      CipherSuite::TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 => 0xc082,
      CipherSuite::TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 => 0xc083,
      CipherSuite::TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 => 0xc084,
      CipherSuite::TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 => 0xc085,
      CipherSuite::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc086,
      CipherSuite::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc087,
      CipherSuite::TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc088,
      CipherSuite::TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc089,
      CipherSuite::TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc08a,
      CipherSuite::TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc08b,
      CipherSuite::TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc08c,
      CipherSuite::TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc08d,
      CipherSuite::TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 => 0xc08e,
      CipherSuite::TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 => 0xc08f,
      CipherSuite::TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 => 0xc090,
      CipherSuite::TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 => 0xc091,
      CipherSuite::TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 => 0xc092,
      CipherSuite::TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 => 0xc093,
      CipherSuite::TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 => 0xc094,
      CipherSuite::TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 => 0xc095,
      CipherSuite::TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 => 0xc096,
      CipherSuite::TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 => 0xc097,
      CipherSuite::TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 => 0xc098,
      CipherSuite::TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 => 0xc099,
      CipherSuite::TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 => 0xc09a,
      CipherSuite::TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 => 0xc09b,
      CipherSuite::TLS_RSA_WITH_AES_128_CCM => 0xc09c,
      CipherSuite::TLS_RSA_WITH_AES_256_CCM => 0xc09d,
      CipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM => 0xc09e,
      CipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM => 0xc09f,
      CipherSuite::TLS_RSA_WITH_AES_128_CCM_8 => 0xc0a0,
      CipherSuite::TLS_RSA_WITH_AES_256_CCM_8 => 0xc0a1,
      CipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM_8 => 0xc0a2,
      CipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM_8 => 0xc0a3,
      CipherSuite::TLS_PSK_WITH_AES_128_CCM => 0xc0a4,
      CipherSuite::TLS_PSK_WITH_AES_256_CCM => 0xc0a5,
      CipherSuite::TLS_DHE_PSK_WITH_AES_128_CCM => 0xc0a6,
      CipherSuite::TLS_DHE_PSK_WITH_AES_256_CCM => 0xc0a7,
      CipherSuite::TLS_PSK_WITH_AES_128_CCM_8 => 0xc0a8,
      CipherSuite::TLS_PSK_WITH_AES_256_CCM_8 => 0xc0a9,
      CipherSuite::TLS_PSK_DHE_WITH_AES_128_CCM_8 => 0xc0aa,
      CipherSuite::TLS_PSK_DHE_WITH_AES_256_CCM_8 => 0xc0ab,
      CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 0xcca8,
      CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => 0xcca9,
      CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 0xccaa,
      CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 => 0xccab,
      CipherSuite::TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => 0xccac,
      CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => 0xccad,
      CipherSuite::TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 => 0xccae,
      CipherSuite::SSL_RSA_FIPS_WITH_DES_CBC_SHA => 0xfefe,
      CipherSuite::SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA => 0xfeff,
      CipherSuite::Unknown(v) => v
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ECPointFormat {
  Uncompressed,
  ANSIX962CompressedPrime,
  ANSIX962CompressedChar2,
  Unknown(u8)
}

impl Codec for ECPointFormat {
  fn encode(&self, bytes: &mut Vec<u8>) {
    encode_u8(self.get_u8(), bytes);
  }

  fn read(r: &mut Reader) -> Option<ECPointFormat> {
    let u = read_u8(r);

    if u.is_none() {
      return None
    }

    Some(match u.unwrap() {
      0x00 => ECPointFormat::Uncompressed,
      0x01 => ECPointFormat::ANSIX962CompressedPrime,
      0x02 => ECPointFormat::ANSIX962CompressedChar2,
      x => ECPointFormat::Unknown(x)
    })
  }
}

impl ECPointFormat {
  pub fn get_u8(&self) -> u8 {
    match *self {
      ECPointFormat::Uncompressed => 0x00,
      ECPointFormat::ANSIX962CompressedPrime => 0x01,
      ECPointFormat::ANSIX962CompressedChar2 => 0x02,
      ECPointFormat::Unknown(v) => v
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum HeartbeatMode {
  PeerAllowedToSend,
  PeerNotAllowedToSend,
  Unknown(u8)
}

impl Codec for HeartbeatMode {
  fn encode(&self, bytes: &mut Vec<u8>) {
    encode_u8(self.get_u8(), bytes);
  }

  fn read(r: &mut Reader) -> Option<HeartbeatMode> {
    let u = read_u8(r);

    if u.is_none() {
      return None
    }

    Some(match u.unwrap() {
      0x01 => HeartbeatMode::PeerAllowedToSend,
      0x02 => HeartbeatMode::PeerNotAllowedToSend,
      x => HeartbeatMode::Unknown(x)
    })
  }
}

impl HeartbeatMode {
  pub fn get_u8(&self) -> u8 {
    match *self {
      HeartbeatMode::PeerAllowedToSend => 0x01,
      HeartbeatMode::PeerNotAllowedToSend => 0x02,
      HeartbeatMode::Unknown(v) => v
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ECCurveType {
  ExplicitPrime,
  ExplicitChar2,
  NamedCurve,
  Unknown(u8)
}

impl Codec for ECCurveType {
  fn encode(&self, bytes: &mut Vec<u8>) {
    encode_u8(self.get_u8(), bytes);
  }

  fn read(r: &mut Reader) -> Option<ECCurveType> {
    let u = read_u8(r);

    if u.is_none() {
      return None
    }

    Some(match u.unwrap() {
      0x01 => ECCurveType::ExplicitPrime,
      0x02 => ECCurveType::ExplicitChar2,
      0x03 => ECCurveType::NamedCurve,
      x => ECCurveType::Unknown(x)
    })
  }
}

impl ECCurveType {
  pub fn get_u8(&self) -> u8 {
    match *self {
      ECCurveType::ExplicitPrime => 0x01,
      ECCurveType::ExplicitChar2 => 0x02,
      ECCurveType::NamedCurve => 0x03,
      ECCurveType::Unknown(v) => v
    }
  }
}
