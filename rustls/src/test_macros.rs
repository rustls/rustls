//! Macros used for unit testing.

/// Instantiate the given benchmark functions once for each built-in provider.
///
/// The selected provider module is bound as `provider`; you can rely on this
/// having the union of the items common to the `crypto::ring` and
/// `crypto::aws_lc_rs` modules.
#[cfg(bench)]
macro_rules! bench_for_each_provider {
    ($($tt:tt)+) => {
        #[cfg(feature = "ring")]
        mod bench_with_ring {
            use crate::crypto::ring as provider;
            #[allow(unused_imports)]
            use super::*;
            $($tt)+
        }

        #[cfg(feature = "aws-lc-rs")]
        mod bench_with_aws_lc_rs {
            use crate::crypto::aws_lc_rs as provider;
            #[allow(unused_imports)]
            use super::*;
            $($tt)+
        }
    };
}

#[cfg(all(test, bench))]
#[macro_rules_attribute::apply(bench_for_each_provider)]
mod benchmarks {
    #[bench]
    fn bench_each_provider(b: &mut test::Bencher) {
        b.iter(|| super::provider::DEFAULT_PROVIDER);
    }
}
