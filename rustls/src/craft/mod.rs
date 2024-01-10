mod fingerprints;
pub use fingerprints::*;

use crate::client::ClientConnectionData;
use crate::common_state::Context;
use crate::crypto::{ActiveKeyExchange, SupportedKxGroup};
use crate::msgs::base::{Payload, PayloadU16};
use crate::msgs::codec::{Codec, LengthPrefixedBuffer};
use crate::msgs::enums::{ECPointFormat, ExtensionType, PSKKeyExchangeMode};
use crate::msgs::handshake::{
    CertificateStatusRequest, ClientExtension, KeyShareEntry, OcspCertificateStatusRequest,
};
use crate::msgs::handshake::{HelloRetryRequest, UnknownExtension};
use crate::version::{TLS12, TLS13};
use crate::versions::EnabledVersions;
use crate::{
    CipherSuite, ClientConfig, NamedGroup, ProtocolVersion, SignatureScheme, ALL_VERSIONS,
};
use alloc::sync::Arc;
use core::fmt::Debug;
use std::boxed::Box;
use std::vec;
use std::{collections::HashMap, vec::Vec};

use static_init::dynamic;

#[derive(Clone, Debug, Default)]
pub(crate) struct CraftOptions(Option<CraftOptionsImpl>);

#[derive(Clone, Debug)]
struct CraftOptionsImpl {
    fingerprint: Fingerprint,
    strict_mode: bool,
    override_keyshare: bool,
}

impl CraftOptions {
    fn get(&self) -> &CraftOptionsImpl {
        assert!(self.0.is_some(), "The tls client config doesn't contain a fingerprint, please consider calling ClientConfig::with_fingerprint(...)");
        self.0.as_ref().unwrap()
    }

    pub(crate) fn patch_extension(
        &self,
        cx: &mut Context<'_, ClientConnectionData>,
        config: &ClientConfig,
        hrr: Option<&HelloRetryRequest>,
        extension: &mut Vec<ClientExtension>,
    ) {
        self.get()
            .fingerprint
            .patch_extension(cx, config, hrr, extension)
    }

    pub(crate) fn patch_cipher(
        &self,
        cx: &mut Context<'_, ClientConnectionData>,
        extension: &mut Vec<CipherSuite>,
    ) {
        self.get()
            .fingerprint
            .patch_cipher(cx, extension)
    }
}

#[allow(dead_code)]
#[repr(usize)]
enum BoringSslGreaseIndex {
    Cipher,
    Group,
    Extension1,
    Extension2,
    Version,
    TicketExtension,
    EchConfigId,
    NumOfGrease,
}

#[derive(Debug)]
struct GreaseSeed([u16; BoringSslGreaseIndex::NumOfGrease as usize]);

impl GreaseSeed {
    fn get(&self, idx: BoringSslGreaseIndex) -> u16 {
        self.0[idx as usize]
    }
}

pub(crate) struct CraftConnectionData {
    grease_seed: GreaseSeed,
    pub(crate) our_key_share_alt: Vec<Box<dyn ActiveKeyExchange>>,
    pub(crate) extension_order: Vec<usize>,
}

impl Debug for CraftConnectionData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CraftConnectionData")
            .field("grease_seed", &self.grease_seed)
            .field("our_key_share_alt", &"hidden")
            .finish()
    }
}

impl CraftConnectionData {
    pub(crate) fn new(config: &ClientConfig) -> Self {
        use BoringSslGreaseIndex::*;
        let mut grease_seed_u8 = [0u8; NumOfGrease as usize];
        let mut grease_seed = [0u16; NumOfGrease as usize];
        config
            .provider
            .secure_random
            .fill(&mut grease_seed_u8)
            .unwrap();
        for i in 0..NumOfGrease as usize {
            let unit = ((grease_seed_u8[i] & 0xf0) | 0x0a) as u16;
            grease_seed[i] = unit << 8 | unit;
        }
        if grease_seed[Extension1 as usize] == grease_seed[Extension2 as usize] {
            grease_seed[Extension2 as usize] ^= 0x1010;
        }
        Self {
            grease_seed: GreaseSeed(grease_seed),
            our_key_share_alt: Vec::new(),
            extension_order: Vec::new(),
        }
    }

    pub(crate) fn find_key_share(
        &mut self,
        target_group: NamedGroup,
    ) -> Option<Box<dyn ActiveKeyExchange>> {
        for i in 0..self.our_key_share_alt.len() {
            if self.our_key_share_alt[i].group() == target_group {
                return Some(self.our_key_share_alt.swap_remove(i));
            }
        }

        None
    }
}

/// An enum representing either a valid value of type `T` or a GREASE (Generate Random Extensions And Sustain Extensibility) placeholder.
#[derive(Debug)]
pub enum GreaseOr<T> {
    /// A GREASE placeholder value, which will be generated randomly per session.
    Grease,
    /// A valid value of the generic type `T`.
    T(T),
}

impl<T: Clone> GreaseOr<T> {
    pub(crate) fn is_grease(&self) -> bool {
        matches!(self, Grease)
    }

    pub(crate) fn val(&self) -> T {
        match self {
            Grease => unimplemented!(),
            GreaseOr::T(t) => t.clone(),
        }
    }
}

use GreaseOr::Grease;

pub(crate) trait CreateUnknown: Clone + Debug {
    fn create_unknown(grease: u16) -> Self;
}

impl<T> GreaseOr<T> {
    fn val_or(&self, grease: u16) -> T
    where
        T: CreateUnknown,
    {
        match self {
            Grease => T::create_unknown(grease),
            GreaseOr::T(t) => t.clone(),
        }
    }
}

impl<T> From<T> for GreaseOr<T> {
    fn from(value: T) -> Self {
        GreaseOr::T(value)
    }
}

/// A type that can either hold a valid `NamedGroup` or serve as a GREASE placeholder.
pub type GreaseOrCurve = GreaseOr<NamedGroup>;

/// A type that can either hold a valid `ProtocolVersion` or serve as a GREASE placeholder.
pub type GreaseOrVersion = GreaseOr<ProtocolVersion>;

/// A type that can either hold a valid `CipherSuite` or serve as a GREASE placeholder.
pub type GreaseOrCipher = GreaseOr<CipherSuite>;

impl CreateUnknown for NamedGroup {
    fn create_unknown(grease: u16) -> Self {
        Self::Unknown(grease)
    }
}

impl CreateUnknown for ProtocolVersion {
    fn create_unknown(grease: u16) -> Self {
        Self::Unknown(grease)
    }
}

impl CreateUnknown for CipherSuite {
    fn create_unknown(grease: u16) -> Self {
        Self::Unknown(grease)
    }
}

#[derive(Debug)]
struct CraftFakeKxGroup {
    name: NamedGroup,
}

impl SupportedKxGroup for CraftFakeKxGroup {
    fn name(&self) -> NamedGroup {
        self.name
    }

    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, crate::Error> {
        todo!()
    }
}

pub(crate) static FAKE_SECP256R1: &'static dyn SupportedKxGroup = &CraftFakeKxGroup {
    name: NamedGroup::secp256r1,
};

pub(crate) static FAKE_SECP384R1: &'static dyn SupportedKxGroup = &CraftFakeKxGroup {
    name: NamedGroup::secp384r1,
};

pub(crate) static FAKE_SECP521R1: &'static dyn SupportedKxGroup = &CraftFakeKxGroup {
    name: NamedGroup::secp521r1,
};

pub(crate) static FAKE_FFDHE2048: &'static dyn SupportedKxGroup = &CraftFakeKxGroup {
    name: NamedGroup::FFDHE2048,
};

pub(crate) static FAKE_FFDHE3072: &'static dyn SupportedKxGroup = &CraftFakeKxGroup {
    name: NamedGroup::FFDHE3072,
};

fn to_fake_curves(group: &NamedGroup) -> &'static dyn SupportedKxGroup {
    match group {
        NamedGroup::secp256r1 => FAKE_SECP256R1,
        NamedGroup::secp384r1 => FAKE_SECP384R1,
        NamedGroup::secp521r1 => FAKE_SECP521R1,
        NamedGroup::FFDHE2048 => FAKE_FFDHE2048,
        NamedGroup::FFDHE3072 => FAKE_FFDHE3072,
        _ => unimplemented!(),
    }
}

/// Craft client extension provides customization to rustls client extensions, or offers some unavailable extensions in rustls.
#[derive(Debug, Clone)]
pub enum CraftExtension {
    /// The first grease extension in the list
    Grease1,

    /// The second grease extension in the list
    Grease2,

    /// RenegotiationInfo extension that hard coded with `RenegotiationNever`
    RenegotiationInfo,

    /// SupportedCurves that supports grease or NamedCurve
    SupportedCurves(&'static [GreaseOrCurve]),

    /// SupportedVersions that supports grease or tls versions
    SupportedVersions(&'static [GreaseOrVersion]),

    /// Hardcoded SignedCertificateTimestamp
    SignedCertificateTimestamp,

    /// KeyShare that supports grease or NamedCurve
    KeyShare(&'static [GreaseOrCurve]),

    /// Hardcoded fake BoringSSL ApplicationSettings.
    FakeApplicationSettings,

    /// Hardcoded fake CompressCert extension that provides no compression algorithm
    #[cfg(not(cert_compress))]
    FakeCompressCert,
    /// CompressCert extension
    #[cfg(cert_compress)]
    CompressCert(&'static [crate::CertificateCompressionAlgorithm]),

    /// Client Hello Padding extension that mimics the BoringSSL padding style
    Padding,

    /// ALPN extension
    Protocols(&'static [&'static [u8]]),

    /// Fake DelegatedCredentials extension
    FakeDelegatedCredentials(&'static [SignatureScheme]),

    /// Fake RecordSizeLimit extension
    FakeRecordSizeLimit(u16),
}

macro_rules! get_origin_ext {
    ($extract:expr, $ext:path, $strict_mode:expr) => {
        match $extract {
            Some($ext(v)) => v,
            _ => {
                assert!(!$strict_mode);
                return Err(());
            }
        }
    };
}

impl CraftExtension {
    fn make_ext(typ: ExtensionType, payload: Vec<u8>) -> ClientExtension {
        ClientExtension::Unknown(UnknownExtension {
            typ,
            payload: Payload(payload),
        })
    }

    fn to_rustls_extension(
        &self,
        cx: &mut Context<'_, ClientConnectionData>,
        config: &ClientConfig,
        ext_store: &mut HashMap<u16, ClientExtension>,
        hrr: Option<&HelloRetryRequest>,
    ) -> Result<ClientExtension, ()> {
        let craft_config = config.craft.get();
        Ok(match self {
            CraftExtension::Grease1 => Self::make_ext(
                cx.data
                    .craft_connection_data
                    .grease_seed
                    .get(BoringSslGreaseIndex::Extension1)
                    .into(),
                Vec::new(),
            ),
            CraftExtension::Grease2 => Self::make_ext(
                cx.data
                    .craft_connection_data
                    .grease_seed
                    .get(BoringSslGreaseIndex::Extension2)
                    .into(),
                vec![0],
            ),
            CraftExtension::RenegotiationInfo => {
                Self::make_ext(ExtensionType::RenegotiationInfo, vec![0])
            }
            CraftExtension::SupportedCurves(curves) => {
                let origin_curves = get_origin_ext!(
                    ext_store.remove(&ExtensionType::EllipticCurves.get_u16()),
                    ClientExtension::NamedGroups,
                    craft_config.strict_mode
                );

                ClientExtension::NamedGroups(
                    curves
                        .iter()
                        .map(|v| {
                            v.val_or(
                                cx.data
                                    .craft_connection_data
                                    .grease_seed
                                    .get(BoringSslGreaseIndex::Group),
                            )
                        })
                        .filter(|group| {
                            if !group.craft_is_unknown() && !origin_curves.contains(&group) {
                                assert!(!craft_config.strict_mode);
                                false
                            } else {
                                true
                            }
                        })
                        .collect(),
                )
            }
            CraftExtension::SupportedVersions(versions) => {
                let origin_versions = get_origin_ext!(
                    ext_store.remove(&ExtensionType::SupportedVersions.get_u16()),
                    ClientExtension::SupportedVersions,
                    craft_config.strict_mode
                );
                ClientExtension::SupportedVersions(
                    versions
                        .iter()
                        .map(|v| {
                            v.val_or(
                                cx.data
                                    .craft_connection_data
                                    .grease_seed
                                    .get(BoringSslGreaseIndex::Version),
                            )
                        })
                        .filter(|v| {
                            if !v.craft_is_unknown() && !origin_versions.contains(v) {
                                assert!(!craft_config.strict_mode);
                                false
                            } else {
                                true
                            }
                        })
                        .collect(),
                )
            }
            CraftExtension::SignedCertificateTimestamp => {
                Self::make_ext(ExtensionType::SCT, vec![])
            }
            CraftExtension::KeyShare(key_share_spec) => {
                if hrr.is_some()
                    && hrr
                        .unwrap()
                        .get_requested_key_share_group()
                        .is_some()
                    || !craft_config.override_keyshare
                {
                    return ext_store
                        .remove(&ExtensionType::KeyShare.get_u16())
                        .ok_or(());
                }
                let mut origin_ks = get_origin_ext!(
                    ext_store.remove(&ExtensionType::KeyShare.get_u16()),
                    ClientExtension::KeyShare,
                    craft_config.strict_mode
                )
                .into_iter()
                .next();

                let origin_ks_group = origin_ks.as_ref().unwrap().group;

                let mut key_shares = vec![];

                for group_spec in key_share_spec.iter() {
                    key_shares.push(match group_spec {
                        Grease => KeyShareEntry {
                            group: group_spec
                                .val_or(
                                    cx.data
                                        .craft_connection_data
                                        .grease_seed
                                        .get(BoringSslGreaseIndex::Group),
                                )
                                .into(),
                            payload: PayloadU16(vec![0]),
                        },
                        GreaseOr::T(group) => {
                            if (origin_ks_group != config.provider.kx_groups[0].name()
                                || *group == origin_ks_group)
                                && origin_ks.is_some()
                            {
                                origin_ks.take().unwrap()
                            } else if !key_shares
                                .iter()
                                .any(|ks: &KeyShareEntry| ks.group == *group)
                            {
                                let ks_data = match config
                                    .find_kx_group(*group)
                                    .and_then(|v| v.start().ok())
                                {
                                    Some(ks_data) => ks_data,
                                    None => {
                                        assert!(
                                            !craft_config.strict_mode,
                                            "unsupported group specified for psk"
                                        );
                                        continue;
                                    }
                                };
                                let ks_ext = KeyShareEntry::new(*group, ks_data.pub_key());

                                cx.data
                                    .craft_connection_data
                                    .our_key_share_alt
                                    .push(ks_data);
                                ks_ext
                            } else {
                                continue;
                            }
                        }
                    });
                }

                ClientExtension::KeyShare(key_shares)
            }
            CraftExtension::FakeApplicationSettings => {
                Self::make_ext(17513.into(), vec![0, 3, 2, b'h', b'2'])
            }
            CraftExtension::Padding => {
                ClientExtension::CraftPadding(CraftPadding {
                    psk_len: if let Some(ClientExtension::PresharedKey(psk)) =
                        ext_store.get(&ExtensionType::PreSharedKey.get_u16())
                    {
                        2 /* ext_type */ + 2 /* len */ + 2 /* ident_len */ + psk.identities.iter().map(|v| 2 /* len */ + v.identity.0.len() + 4 /* obfs ticket age */).sum::<usize>() + 2 /* binders len */ + psk.binders.iter().map(|b| 1 + b.0.0.len()).sum::<usize>()
                    } else {
                        0
                    },
                })
            }
            #[cfg(not(cert_compress))]
            CraftExtension::FakeCompressCert => Self::make_ext(0x001b.into(), vec![2, 0, 0]),
            #[cfg(cert_compress)]
            CraftExtension::CompressCert(algorithms) => {
                if craft_config.strict_mode {
                    config
                        .certificate_compression_algorithms
                        .iter()
                        .zip(algorithms.iter())
                        .for_each(|(a, b)| {
                            assert_eq!(a.alg, *b);
                        });
                }
                ext_store
                    .remove(&ExtensionType::CompressCertificate.get_u16())
                    .ok_or(())?
            }
            CraftExtension::Protocols(protocols) => {
                if craft_config.strict_mode {
                    if protocols.len() != config.alpn_protocols.len()
                        || protocols
                            .iter()
                            .zip(config.alpn_protocols.iter())
                            .any(|(p1, p2)| p1 != &p2.as_slice())
                    {
                        panic!()
                    }
                }
                ext_store
                    .remove(&ExtensionType::ALProtocolNegotiation.get_u16())
                    .ok_or(())?
            }
            CraftExtension::FakeDelegatedCredentials(delegated) => {
                let mut buf = vec![];
                {
                    let length_padded =
                        LengthPrefixedBuffer::new(crate::msgs::codec::ListLength::U16, &mut buf);
                    for sig in delegated.iter() {
                        sig.encode(length_padded.buf);
                    }
                };
                Self::make_ext(34.into(), buf)
            }
            CraftExtension::FakeRecordSizeLimit(limit) => {
                Self::make_ext(28.into(), limit.to_be_bytes().to_vec())
            }
        })
    }
}

/// A boringssl-style client padding presented by Craftls.
#[derive(Clone, Debug)]
pub struct CraftPadding {
    psk_len: usize,
}

impl Codec for CraftPadding {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let unpadded = self.psk_len + bytes.len() - 4;
        if unpadded > 0xff && unpadded < 0x200 {
            let mut padding_len = 0x200 - unpadded;
            if padding_len >= 4 + 1 {
                padding_len -= 4;
            } else {
                padding_len = 1
            }
            bytes.resize(bytes.len() + padding_len, 0);
        } else {
            // A dirty trick to delete the already written ext type and size.
            bytes.resize(bytes.len() - 4, 0);
        }
    }

    fn read(_: &mut crate::msgs::codec::Reader) -> Result<Self, crate::InvalidMessage> {
        todo!()
    }
}

/// `KeepExtension` gives fine-grained control over the inclusion of extensions originally generated by Rustls.
/// It dictates whether to keep certain Rustls extensions, use them optionally, or provide a default if unavailable.
#[derive(Debug, Clone)]
pub enum KeepExtension {
    /// Specifies that the `ExtensionType` must be provided by Rustls. If the extension is not present, there might be a configuration or implementation error.
    Must(ExtensionType),
    /// Specifies that the `ExtensionType` may be provided by Rustls. Its absence will not be considered
    /// an error.
    Optional(ExtensionType),
    /// Specifies that the `ExtensionType` should be provided by Rustls; if it is not available,
    /// the specified `ClientExtension` will be used as a fallback.
    OrDefault(ExtensionType, ClientExtension),
}

/// `ExtensionSpec` outlines the types of client extensions that can be used in a fingerprint specification
#[derive(Debug, Clone)]
pub enum ExtensionSpec {
    /// A `CraftExtension` represents an extension not inherently supported by Rustls or a customization not available in Rustls.
    /// These extensions will be eventually be converted into Rustls `ClientExtension`s.
    Craft(CraftExtension),

    /// A `ClientExtension` native to Rustls. Extensions specified here are directly included in the client hello message.
    Rustls(ClientExtension),

    /// A `KeepExtension` dictates the retention policy for extensions that are generated by Rustls by default.
    /// It allows for specifying whether certain Rustls-generated extensions should be kept as-is, used conditionally,
    /// or replaced with a default if not present.
    Keep(KeepExtension),
}

fn shuffle_extensions(extensions: &[ExtensionSpec], config: &ClientConfig) -> Vec<usize> {
    use ExtensionSpec::*;

    let mut to_shuffle = Vec::with_capacity(extensions.len());
    let mut do_not_shuffle = Vec::with_capacity(extensions.len());
    for (i, ext) in extensions.iter().enumerate() {
        match ext {
            Craft(CraftExtension::Grease1 | CraftExtension::Grease2)
            | Craft(CraftExtension::Padding)
            | Keep(KeepExtension::Optional(ExtensionType::PreSharedKey)) => {
                do_not_shuffle.push(i);
            }
            _ => to_shuffle.push(i),
        }
    }

    let mut random_buf = [0u8, 0, 0, 0];
    let rand_gen = config.provider.secure_random;
    for i in (1..to_shuffle.len()).rev() {
        rand_gen.fill(&mut random_buf).unwrap();
        let swap_idx = (u32::from_be_bytes(random_buf) as usize) % (i + 1);
        to_shuffle.swap(i, swap_idx);
    }

    for i in do_not_shuffle {
        to_shuffle.insert(i, i);
    }

    to_shuffle
}

/// Represents a TLS fingerprint
///
/// # Available Fingerprints:
/// * [`CHROME_108`]
/// * [`CHROME_112`]
/// * [`SAFARI_17_1`]
/// * [`FIREFOX_105`]
#[derive(Debug, Clone, Default)]
pub struct Fingerprint {
    /// The TLS ClientHello extensions included in the fingerprint. Each `ExtensionSpec` determines the nature and handling
    /// of an extension, whether it's a Craft extension, a native Rustls extension, or subject
    /// to conditional inclusion based on Rustls' defaults.
    pub extensions: &'static [ExtensionSpec],
    /// Indicates whether the list of extensions should be randomly reordered
    /// before being sent in the ClientHello message. This shuffling process is introduced to mimic BoringSSL.
    pub shuffle_extensions: bool,
    /// Specifies the list of ciphers included in the ClientHello.
    pub cipher: &'static [GreaseOrCipher],
}

impl Fingerprint {
    /// Creates a fingerprint builder that allow you to tweak the fingerprint and patch the client config. See also [`crate::ClientConfig::with_fingerprint`]
    pub fn builder(&self) -> FingerprintBuilder {
        FingerprintBuilder {
            fingerprint: self.clone(),
            override_alpn: true,
            strict_mode: true,
            override_supported_curves: true,
            override_version: true,
            override_keyshare: true,
            override_cert_compress: true,
        }
    }

    fn patch_extension(
        &self,
        cx: &mut Context<'_, ClientConnectionData>,
        config: &ClientConfig,
        hrr: Option<&HelloRetryRequest>,
        extension: &mut Vec<ClientExtension>,
    ) {
        let craft_config = config.craft.get();
        if extension
            .iter()
            .any(|v| matches!(v, ClientExtension::EarlyData))
        {
            assert!(!craft_config.strict_mode);
            return;
        }

        let mut ext_store = HashMap::new();
        for ext in extension.drain(..) {
            match ext {
                ClientExtension::ServerName(_)
                | ClientExtension::SessionTicket(_)
                | ClientExtension::KeyShare(_)
                | ClientExtension::PresharedKey(_)
                | ClientExtension::Protocols(_)
                | ClientExtension::NamedGroups(_)
                | ClientExtension::SupportedVersions(_)
                | ClientExtension::Cookie(_) => {
                    ext_store.insert(ext.get_type().get_u16(), ext);
                }
                #[cfg(cert_compress)]
                ClientExtension::CompressCertificate(_) => {
                    ext_store.insert(ext.get_type().get_u16(), ext);
                }
                _ => (),
            }
        }

        use ExtensionSpec::*;
        use KeepExtension::*;

        if hrr.is_none()
            && craft_config
                .fingerprint
                .shuffle_extensions
        {
            cx.data
                .craft_connection_data
                .extension_order = shuffle_extensions(self.extensions, config);
        }

        let order = {
            let mut iter_a = None;
            let mut iter_b = None;

            let order = &cx
                .data
                .craft_connection_data
                .extension_order;
            if order.len() == 0 {
                iter_a = Some(0..self.extensions.len())
            } else {
                iter_b = Some(order.clone().into_iter())
            }
            iter_a
                .into_iter()
                .flatten()
                .chain(iter_b.into_iter().flatten())
        };

        for idx in order {
            let spec = &self.extensions[idx];
            extension.push(match spec {
                Craft(ext) => match ext.to_rustls_extension(cx, &config, &mut ext_store, hrr) {
                    Ok(ext) => ext,
                    Err(_) => continue,
                },
                Rustls(ext) => ext.clone(),
                Keep(Must(ext_type)) => match ext_store.remove(&ext_type.get_u16()) {
                    Some(ext) => ext,
                    None => {
                        if matches!(ext_type, ExtensionType::ServerName) && config.enable_sni {
                            continue;
                        }
                        assert!(
                            !craft_config.strict_mode,
                            "expecting {:?}, but got nothing",
                            ext_type
                        );
                        continue;
                    }
                },
                Keep(Optional(ext)) => match ext_store.remove(&ext.get_u16()) {
                    Some(ext) => ext,
                    None => {
                        continue;
                    }
                },
                Keep(OrDefault(ext, default_ext)) => ext_store
                    .remove(&ext.get_u16())
                    .unwrap_or_else(|| default_ext.clone()),
            })
        }
    }

    pub(crate) fn patch_cipher(
        &self,
        cx: &mut Context<'_, ClientConnectionData>,
        extension: &mut Vec<CipherSuite>,
    ) {
        *extension = self
            .cipher
            .iter()
            .map(|c| {
                c.val_or(
                    cx.data
                        .craft_connection_data
                        .grease_seed
                        .get(BoringSslGreaseIndex::Cipher),
                )
            })
            .collect();
    }
}

#[derive(Debug, Clone)]
/// A builder for constructing a [`Fingerprint`] with customizable configurations.
/// The builder allows specific aspects of the TLS fingerprint to be overridden,
/// ensuring that the final [`crate::ClientConfig`] and ClientHello align with desired specifications or
/// testing conditions.
pub struct FingerprintBuilder {
    fingerprint: Fingerprint,
    override_alpn: bool,
    override_version: bool,
    override_supported_curves: bool,
    strict_mode: bool,
    override_keyshare: bool,
    override_cert_compress: bool,
}

impl FingerprintBuilder {
    /// Disables the overriding of the ALPN settings.
    /// Use this option when working with HTTP clients, such as `hyper`, that internally manage
    /// ALPN settings; they may raise issues if ALPN is set externally. While this option skips
    /// setting ALPN, it still validates the ALPN during TLS handshakes against expected values.
    /// Non-compliance will lead to a panic, ensuring adherence to the specified ALPN requirements.
    pub fn do_not_override_alpn(mut self) -> Self {
        self.override_alpn = false;
        self
    }

    /// Disables the override of key share configurations. Intended only for testing purposes,
    /// this option allows the default key share behavior to be used, bypassing the key share settings
    /// specified in the `Fingerprint`. This can help in testing scenarios where non-standard key
    /// share configurations are to be evaluated or default behavior is required.
    pub fn dangerous_disable_override_keyshare(mut self) -> Self {
        self.override_keyshare = false;
        self
    }

    /// Enters a craftls test mode that disables various overrides and strict checking against the [`Fingerprint`].
    /// This mode is intended for testing and should be used with caution as it relaxes the
    /// constraints normally enforced by the builder, potentially allowing configurations that
    /// deviate from the specified `Fingerprint`. This can be useful for testing how the system
    /// behaves under non-standard or unexpected configurations.
    pub fn dangerous_craft_test_mode(mut self) -> Self {
        self.strict_mode = false;
        self.override_alpn = false;
        self.override_version = false;
        self.override_supported_curves = false;
        self.override_cert_compress = false;
        self
    }

    fn build(self) -> CraftOptions {
        CraftOptions(Some(CraftOptionsImpl {
            fingerprint: self.fingerprint,
            strict_mode: self.strict_mode,
            override_keyshare: self.override_keyshare,
        }))
    }

    pub(crate) fn patch_config(self, mut config: ClientConfig) -> ClientConfig {
        if self.override_version {
            assert_eq!(ALL_VERSIONS, &[&TLS13, &TLS12]);
            config.versions = EnabledVersions::new(ALL_VERSIONS); // enable both tls 1.2 and 1.3
        }
        for ext in self.fingerprint.extensions.iter() {
            match ext {
                ExtensionSpec::Craft(CraftExtension::SupportedCurves(curves)) => {
                    if !self.override_supported_curves {
                        continue;
                    }

                    let curves_need_modification = curves
                        .iter()
                        .filter(|c| !c.is_grease())
                        .zip(config.provider.kx_groups.iter())
                        .all(|(c1, c2)| c1.val() == c2.name());

                    if !curves_need_modification {
                        continue;
                    }

                    let mut provider = config.provider.as_ref().clone();

                    let mut grease_offset = 0;
                    for (idx, curve) in curves.iter().enumerate() {
                        match curve {
                            Grease => {
                                grease_offset += 1;
                                continue;
                            }
                            GreaseOr::T(curve) => {
                                if let Some(old_idx) = provider
                                    .kx_groups
                                    .iter()
                                    .position(|v| v.name() == *curve)
                                {
                                    if idx - grease_offset == old_idx {
                                        continue;
                                    }
                                    assert!(
                                        idx - grease_offset < old_idx,
                                        "idx {idx}, old_idx {old_idx}"
                                    );
                                    provider.kx_groups.swap(idx, old_idx);
                                } else {
                                    provider
                                        .kx_groups
                                        .insert(idx - grease_offset, to_fake_curves(curve))
                                }
                            }
                        }
                    }
                    config.provider = Arc::new(provider);
                }
                ExtensionSpec::Craft(CraftExtension::Protocols(protocols)) => {
                    if !self.override_alpn {
                        continue;
                    }
                    config.alpn_protocols = protocols
                        .iter()
                        .map(|p| p.to_vec())
                        .collect();
                }
                #[cfg(cert_compress)]
                ExtensionSpec::Craft(CraftExtension::CompressCert(algos)) => {
                    if !self.override_cert_compress {
                        continue;
                    }
                    config.certificate_compression_algorithms = algos
                        .iter()
                        .map(|algo| match algo {
                            crate::CertificateCompressionAlgorithm::Zlib => crate::ZLIB_DEFAULT,
                            crate::CertificateCompressionAlgorithm::Brotli => crate::BROTLI_DEFAULT,
                            crate::CertificateCompressionAlgorithm::Zstd => crate::ZSTD_DEFAULT,
                            crate::CertificateCompressionAlgorithm::Unknown(_) => unimplemented!(),
                        })
                        .collect();
                }
                _ => (),
            }
        }
        config.craft = self.build();
        config
    }
}

/// Constructs a `CertCompression` extension suitable for use with [`ExtensionSpec`].
///
/// This macro is necessary because, as of the last update, Rustls does not natively support a
/// certificate compression extension. An implementation is under review (for more than 2 years) for inclusion
/// in Rustls. In the interim, this macro facilitates our own `CompressCertExt`
/// implementation. The intent is for configurations using this macro to seamlessly transition to the official Rustls implementation when it
/// becomes available.
///
/// The macro allows specifying one or more compression algorithms that should be included
/// in the `CertCompression` extension.
///
/// # Examples
/// ```
/// cert_compress_ext!(crate::CertificateCompressionAlgorithm::Zlib, crate::CertificateCompressionAlgorithm::Brotli);
/// ```
#[macro_export]
macro_rules! cert_compress_ext {
    ($($algo:expr),+) => {{
        #[cfg(cert_compress)]
        {
            Craft(CraftExtension::CompressCert(&[
                $($algo),+
            ]))
        }
        // Only available with internal branches
        #[cfg(not(cert_compress))]
        {
            Craft(CraftExtension::FakeCompressCert)
        }
    }};
}

/// Represents a collection of [`Fingerprint`] instances, each configured with different ALPN extensions.
pub struct FingerprintSet {
    /// The default `Fingerprint` variant configured for HTTP/2 (h2) clients.
    /// This is the primary variant used for most scenarios and is designed to be consistent with browsers.
    pub main: Fingerprint,
    /// A `Fingerprint` variant specifically tailored for clients that use HTTP/1.1 (http1).
    /// This variant is useful for testing or scenarios where HTTP/2 support is unavailable.
    pub test_alpn_http1: Fingerprint,
    /// A `Fingerprint` variant without any specific ALPN settings, suitable for use with both HTTP/1.1 and non-HTTP clients.
    /// This variant provides a craftible option for testing or supporting clients where ALPN may not be applicable.
    pub test_no_alpn: Fingerprint,
}

impl std::ops::Deref for FingerprintSet {
    type Target = Fingerprint;

    /// Provides implicit access to the [`FingerprintSet::main`] variant when a [`FingerprintSet`] is dereferenced.
    /// This allows the `main` variant to be used as the default when no explicit selection is made from the set.
    fn deref(&self) -> &Self::Target {
        &self.main
    }
}
