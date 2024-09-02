#[macro_use]
mod macros;

#[cfg(feature = "ring")]
#[path = "."]
mod tests_with_ring {
    provider_ring!();

    #[path = "../client_cert_verifier.rs"]
    mod tests;
}

#[cfg(feature = "aws_lc_rs")]
#[path = "."]
mod tests_with_aws_lc_rs {
    provider_aws_lc_rs!();

    #[path = "../client_cert_verifier.rs"]
    mod tests;
}
