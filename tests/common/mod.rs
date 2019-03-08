use std::fs::{self, File};
use std::io::Write;
use std::str;
use tempfile;

macro_rules! embed_files {
    (
        $(
            ($name:ident, $keytype:expr, $path:expr);
        )+
    ) => {
        $(
            const $name: &'static [u8] = include_bytes!(
                concat!("../../test-ca/", $keytype, "/", $path));
        )+

        pub fn bytes_for(keytype: &str, path: &str) -> &'static [u8] {
            match (keytype, path) {
                $(
                    ($keytype, $path) => $name,
                )+
                _ => panic!("unknown keytype {} with path {}", keytype, path),
            }
        }

        pub fn new_test_ca() -> tempfile::TempDir {
            let dir = tempfile::TempDir::new().unwrap();

            fs::create_dir(dir.path().join("ecdsa")).unwrap();
            fs::create_dir(dir.path().join("rsa")).unwrap();

            $(
                let mut f = File::create(dir.path().join($keytype).join($path)).unwrap();
                f.write($name).unwrap();
            )+

            dir
        }
    }
}

embed_files! {
    (ECDSA_CA_CERT, "ecdsa", "ca.cert");
    (ECDSA_CA_DER, "ecdsa", "ca.der");
    (ECDSA_CA_KEY, "ecdsa", "ca.key");
    (ECDSA_CLIENT_CERT, "ecdsa", "client.cert");
    (ECDSA_CLIENT_CHAIN, "ecdsa", "client.chain");
    (ECDSA_CLIENT_FULLCHAIN, "ecdsa", "client.fullchain");
    (ECDSA_CLIENT_KEY, "ecdsa", "client.key");
    (ECDSA_CLIENT_REQ, "ecdsa", "client.req");
    (ECDSA_END_CERT, "ecdsa", "end.cert");
    (ECDSA_END_CHAIN, "ecdsa", "end.chain");
    (ECDSA_END_FULLCHAIN, "ecdsa", "end.fullchain");
    (ECDSA_END_KEY, "ecdsa", "end.key");
    (ECDSA_END_REQ, "ecdsa", "end.req");
    (ECDSA_INTER_CERT, "ecdsa", "inter.cert");
    (ECDSA_INTER_KEY, "ecdsa", "inter.key");
    (ECDSA_INTER_REQ, "ecdsa", "inter.req");
    (ECDSA_NISTP256_PEM, "ecdsa", "nistp256.pem");
    (ECDSA_NISTP384_PEM, "ecdsa", "nistp384.pem");

    (RSA_CA_CERT, "rsa", "ca.cert");
    (RSA_CA_DER, "rsa", "ca.der");
    (RSA_CA_KEY, "rsa", "ca.key");
    (RSA_CLIENT_CERT, "rsa", "client.cert");
    (RSA_CLIENT_CHAIN, "rsa", "client.chain");
    (RSA_CLIENT_FULLCHAIN, "rsa", "client.fullchain");
    (RSA_CLIENT_KEY, "rsa", "client.key");
    (RSA_CLIENT_REQ, "rsa", "client.req");
    (RSA_CLIENT_RSA, "rsa", "client.rsa");
    (RSA_END_CERT, "rsa", "end.cert");
    (RSA_END_CHAIN, "rsa", "end.chain");
    (RSA_END_FULLCHAIN, "rsa", "end.fullchain");
    (RSA_END_KEY, "rsa", "end.key");
    (RSA_END_REQ, "rsa", "end.req");
    (RSA_END_RSA, "rsa", "end.rsa");
    (RSA_INTER_CERT, "rsa", "inter.cert");
    (RSA_INTER_KEY, "rsa", "inter.key");
    (RSA_INTER_REQ, "rsa", "inter.req");
}
