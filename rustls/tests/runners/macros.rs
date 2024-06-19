//! Macros that bring a provider into the current scope.
//!
//! The selected provider module is bound as `provider`; you can rely on this
//! having the union of the public items common to the `rustls::crypto::ring`
//! and `rustls::crypto::aws_lc_rs` modules.

#[allow(unused_macros)]
macro_rules! provider_ring {
    () => {
        #[allow(unused_imports)]
        use rustls::crypto::ring as provider;
        #[allow(dead_code)]
        const fn provider_is_aws_lc_rs() -> bool {
            false
        }
        #[allow(dead_code)]
        const fn provider_is_ring() -> bool {
            true
        }
        #[allow(dead_code)]
        const fn provider_is_fips() -> bool {
            false
        }
    };
}

#[allow(unused_macros)]
macro_rules! provider_aws_lc_rs {
    () => {
        #[allow(unused_imports)]
        use rustls::crypto::aws_lc_rs as provider;
        #[allow(dead_code)]
        const fn provider_is_aws_lc_rs() -> bool {
            true
        }
        #[allow(dead_code)]
        const fn provider_is_ring() -> bool {
            false
        }
        #[allow(dead_code)]
        const fn provider_is_fips() -> bool {
            cfg!(feature = "fips")
        }
    };
}
