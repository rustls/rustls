#![warn(clippy::assertions_on_result_states)]

#[path = "."]
mod tests_with_ring {
    rustls_test::provider_ring!();

    #[path = "api/client_cert_verifier.rs"]
    mod client_cert_verifier;
    #[path = "api/compress.rs"]
    mod compress;
    #[path = "api/crypto.rs"]
    mod crypto;
    #[path = "api/ffdhe.rs"]
    mod ffdhe;
    #[path = "api/io.rs"]
    mod io;
    #[path = "api/kernel.rs"]
    mod kernel;
    #[path = "api/kx.rs"]
    mod kx;
    #[path = "api/quic.rs"]
    mod quic;
    #[path = "api/raw_keys.rs"]
    mod raw_keys;
    #[path = "api/resolve.rs"]
    mod resolve;
    #[path = "api/resume.rs"]
    mod resume;
    #[path = "api/server_cert_verifier.rs"]
    mod server_cert_verifier;
    #[path = "api/split.rs"]
    mod split;
    #[path = "api/api.rs"]
    mod tests;
}

#[path = "."]
mod tests_with_aws_lc_rs {
    rustls_test::provider_aws_lc_rs!();

    #[path = "api/client_cert_verifier.rs"]
    mod client_cert_verifier;
    #[path = "api/compress.rs"]
    mod compress;
    #[path = "api/crypto.rs"]
    mod crypto;
    #[path = "api/ffdhe.rs"]
    mod ffdhe;
    #[path = "api/io.rs"]
    mod io;
    #[path = "api/kernel.rs"]
    mod kernel;
    #[path = "api/kx.rs"]
    mod kx;
    #[path = "api/quic.rs"]
    mod quic;
    #[path = "api/raw_keys.rs"]
    mod raw_keys;
    #[path = "api/resolve.rs"]
    mod resolve;
    #[path = "api/resume.rs"]
    mod resume;
    #[path = "api/server_cert_verifier.rs"]
    mod server_cert_verifier;
    #[path = "api/split.rs"]
    mod split;
    #[path = "api/api.rs"]
    mod tests;
}
