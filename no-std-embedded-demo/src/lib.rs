#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use core::ops::Range;

use alloc::sync::Arc;

use embassy_net::{
    dns::DnsQueryType,
    udp::{PacketMetadata, UdpSocket},
    IpAddress, IpEndpoint, Ipv4Address, Stack,
};
use embassy_stm32::eth::{generic_smi::GenericSMI, Ethernet};
use embassy_stm32::peripherals::ETH;
use embassy_sync::{blocking_mutex::raw::ThreadModeRawMutex, mutex::Mutex};
use embassy_time::Instant;
use pki_types::PrivateKeyDer;

mod aead;
mod hash;
mod hmac;
#[cfg(feature = "std")]
mod hpke;
mod kx;
mod sign;
mod verify;
const UNIX_TIME: u64 = 1702453769; // `date +%s`

#[cfg(feature = "std")]
pub use hpke::HPKE_PROVIDER;
pub static NTP_TIME: Mutex<ThreadModeRawMutex, Option<u64>> = Mutex::new(None);
pub static TIME_FROM_START: Mutex<ThreadModeRawMutex, Option<Instant>> = Mutex::new(None);

pub static PROVIDER: &'static dyn rustls::crypto::CryptoProvider = &Provider;

#[derive(Debug)]
struct Provider;

impl rustls::crypto::CryptoProvider for Provider {
    fn fill_random(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| rustls::crypto::GetRandomFailed)
    }

    fn default_cipher_suites(&self) -> &'static [rustls::SupportedCipherSuite] {
        ALL_CIPHER_SUITES
    }

    fn default_kx_groups(&self) -> &'static [&'static dyn rustls::crypto::SupportedKxGroup] {
        kx::ALL_KX_GROUPS
    }

    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        let key = sign::EcdsaSigningKeyP256::try_from(key_der).map_err(|err| {
            #[cfg(feature = "std")]
            let err = rustls::OtherError(Arc::new(err));
            #[cfg(not(feature = "std"))]
            let err = rustls::Error::General(alloc::format!("{}", err));
            err
        })?;
        Ok(Arc::new(key))
    }

    fn signature_verification_algorithms(&self) -> rustls::WebPkiSupportedAlgorithms {
        verify::ALGORITHMS
    }
}

static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

pub static TLS13_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::Sha256,
            confidentiality_limit: u64::MAX,
            integrity_limit: 1 << 36,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Chacha20Poly1305,
        quic: None,
    });

pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::Sha256,
            confidentiality_limit: u64::MAX,
            integrity_limit: 1 << 36,
        },
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: &[
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ],
        prf_provider: &rustls::crypto::tls12::PrfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Chacha20Poly1305,
    });

pub async fn init_call_to_ntp_server(stack: &'static Stack<Ethernet<'static, ETH, GenericSMI>>) {
    // TODO: SPIN once
    let ntp_time = get_time_from_ntp_server(stack).await;
    NTP_TIME.lock().await.replace(ntp_time);
}

pub async fn get_time_from_ntp_server(
    stack: &'static Stack<Ethernet<'static, ETH, GenericSMI>>,
) -> u64 {
    const NTP_PACKET_SIZE: usize = 48;
    const TX_SECONDS: Range<usize> = 40..44;

    let ntp_server_addr = stack
        .dns_query("time.cloudflare.com", DnsQueryType::A)
        .await;

    let ntp_sever = if let Ok(net_server_addr) = ntp_server_addr {
        let adr = net_server_addr.first().unwrap().clone();
        IpAddress::from(adr)
    } else {
        // Cloudflare server we know works!
        IpAddress::from(Ipv4Address::new(162, 159, 200, 1))
    };

    let ntp_server = IpEndpoint {
        addr: ntp_sever,
        port: 123,
    };
    let mut rx_meta = [PacketMetadata::EMPTY; 16];
    let mut rx_buffer = [0; 6400];
    let mut tx_meta = [PacketMetadata::EMPTY; 16];
    let mut tx_buffer = [0; 6400];
    let mut buf = [0u8; NTP_PACKET_SIZE];

    let mut sock = UdpSocket::new(
        stack,
        &mut rx_meta,
        &mut rx_buffer,
        &mut tx_meta,
        &mut tx_buffer,
    );

    sock.bind(45698).unwrap();

    // this magic number means
    // - use NTPv3
    // - we are a client
    buf[0] = 0x1b;
    sock.send_to(&buf, ntp_server)
        .await
        .unwrap();

    let mut response = buf;

    let (_read, _ntc_peer) = sock
        .recv_from(&mut response)
        .await
        .unwrap();

    let transmit_seconds = u32::from_be_bytes(response[TX_SECONDS].try_into().unwrap());
    transmit_seconds.into()
}
pub mod time_provider {
    use core::time::Duration;
    use pki_types::UnixTime;
    use rustls::time_provider::{GetCurrentTime, TimeProvider};

    use crate::{NTP_TIME, TIME_FROM_START};
    const TIME_BETWEEN_1900_1970: u64 = 2_208_988_800;

    pub fn stub() -> TimeProvider {
        TimeProvider::new(StubTimeProvider)
    }

    #[derive(Debug)]
    struct StubTimeProvider;

    impl GetCurrentTime for StubTimeProvider {
        fn get_current_time(&self) -> Option<UnixTime> {
            let ntp_time = embassy_futures::block_on(async {
                let provisory = NTP_TIME.lock().await;
                provisory.as_ref().map(|v| *v)
            });

            let time_from_start =
                embassy_futures::block_on(async { *TIME_FROM_START.lock().await });

            let now_from_start = if let Some(now) = time_from_start {
                now
            } else {
                unreachable!();
            };

            // Either the call to NTP server was successful and we can use NTP time ...
            if let Some(now) = ntp_time {
                let now_in_unix = now - TIME_BETWEEN_1900_1970;

                Some(UnixTime::since_unix_epoch(Duration::from_secs(
                    now_in_unix + now_from_start.elapsed().as_secs(),
                )))
            } else {
                // .. or we can use the hardcoded UNIX time
                Some(UnixTime::since_unix_epoch(Duration::from_secs(
                    super::UNIX_TIME,
                )))
            }
        }
    }
}
