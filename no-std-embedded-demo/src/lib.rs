#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use core::ops::Range;
use alloc::sync::Arc;
use defmt::{dbg, Debug2Format};
use rustls::pki_types::UnixTime;

use embassy_net::{
    dns::DnsQueryType,
    udp::{PacketMetadata, UdpSocket},
    IpAddress, IpEndpoint, Ipv4Address, Stack,
};
use embassy_stm32::eth::{generic_smi::GenericSMI, Ethernet};
use embassy_stm32::peripherals::ETH;
use embassy_sync::{blocking_mutex::raw::ThreadModeRawMutex, mutex::Mutex};
use embassy_time::Instant;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::PrivateKeyDer;
use rustls::crypto::SecureRandom;
use rustls::crypto::KeyProvider;
use rustls::time_provider::TimeProvider;

mod aead;
mod hash;
mod hmac;

use core::time::Duration;

const TIME_BETWEEN_1900_1970: u64 = 2_208_988_800;
#[cfg(feature = "std")]
mod hpke;
mod kx;
mod sign;
mod verify;
const UNIX_TIME: u64 = 1705398728; // `date +%s`

#[cfg(feature = "std")]
pub use hpke::HPKE_PROVIDER;
pub static NTP_TIME: Mutex<ThreadModeRawMutex, Option<u64>> = Mutex::new(None);
pub static TIME_FROM_START: Mutex<ThreadModeRawMutex, Option<Instant>> = Mutex::new(None);


pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: kx::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &Provider,
        key_provider: &Provider,
    }
}
#[derive(Debug)]
struct Provider;

impl SecureRandom for Provider {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| rustls::crypto::GetRandomFailed)
    }
}

impl KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        Ok(Arc::new(
            sign::EcdsaSigningKeyP256::try_from(key_der).map_err(|err| {
                let err = rustls::Error::General(alloc::format!("{}", err));
                err
            })?,
        ))
    }
}


#[derive(Debug)]
struct StubTimeProvider;

pub fn stub() -> Arc<dyn TimeProvider> {
    Arc::new(StubTimeProvider)
}


impl TimeProvider for StubTimeProvider {
    fn current_time(&self) -> Option<UnixTime> {
        // let ntp_time = embassy_futures::block_on(async {
        //     let provisory = NTP_TIME.lock().await;
        //     provisory.as_ref().map(|v| *v)
        // });

        // dbg!(ntp_time);

        // let time_from_start =
        //     embassy_futures::block_on(async { *TIME_FROM_START.lock().await });

        // dbg!(time_from_start);

        // let now_from_start = if let Some(now) = time_from_start {
        //     now
        // } else {
        //     unreachable!();
        // };

        // // Either the call to NTP server was successful and we can use NTP time ...
        // if let Some(now) = ntp_time {
        //     let now_in_unix = now - TIME_BETWEEN_1900_1970;
        // dbg!(now_in_unix + now_from_start.elapsed().as_secs());
        //     Some(UnixTime::since_unix_epoch(Duration::from_secs(
        //         now_in_unix + now_from_start.elapsed().as_secs(),
        //     )))
        // } else {
        //     dbg!(Debug2Format(&UnixTime::since_unix_epoch(Duration::from_secs(
        //         UNIX_TIME))));
        //     // .. or we can use the hardcoded UNIX time
        //     Some(UnixTime::since_unix_epoch(Duration::from_secs(
        //         UNIX_TIME,
        //     )))
            Some(UnixTime::since_unix_epoch(Duration::from_secs(UNIX_TIME)))
        }
    }


static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

pub static TLS13_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
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
        common: rustls::crypto::CipherSuiteCommon {
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