#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::persist;
use rustls::internal::msgs::codec::{Reader, Codec};

fn try_type<T>(data: &[u8]) where T: Codec {
    let mut rdr = Reader::init(data);
    T::read(&mut rdr);
}

fn try_tls12clientsession(data: &[u8]) {
    let mut rdr = Reader::init(data);
    persist::ClientSessionValue::read(&mut rdr,
                                      rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                      &rustls::ALL_CIPHER_SUITES);
}

fn try_tls13clientsession(data: &[u8]) {
    let mut rdr = Reader::init(data);
    persist::ClientSessionValue::read(&mut rdr,
                                      rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                                      &rustls::ALL_CIPHER_SUITES);
}

fuzz_target!(|data: &[u8]| {
    try_tls12clientsession(data);
    try_tls13clientsession(data);
    try_type::<persist::ServerSessionValue>(data);
});
