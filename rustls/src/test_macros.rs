//! Macros used for unit testing.

/// Instantiate the given test functions once for each built-in provider.
///
/// The selected provider module is bound as `provider`; you can rely on this
/// having the union of the items common to the `crypto::ring` and
/// `crypto::aws_lc_rs` modules.
macro_rules! test_for_each_provider {
    ($($tt:tt)+) => {
        #[cfg(all(test, feature = "ring"))]
        mod test_with_ring {
            use crate::crypto::ring as provider;
            $($tt)+
        }

        #[cfg(all(test, feature = "aws_lc_rs"))]
        mod test_with_aws_lc_rs {
            use crate::crypto::aws_lc_rs as provider;
            $($tt)+
        }
    };
}

/// Instantiate the given benchmark functions once for each built-in provider.
///
/// The selected provider module is bound as `provider`; you can rely on this
/// having the union of the items common to the `crypto::ring` and
/// `crypto::aws_lc_rs` modules.
macro_rules! bench_for_each_provider {
    ($($tt:tt)+) => {
        #[cfg(all(bench, feature = "ring"))]
        mod bench_with_ring {
            use crate::crypto::ring as provider;
            $($tt)+
        }

        #[cfg(all(bench, feature = "aws_lc_rs"))]
        mod bench_with_aws_lc_rs {
            use crate::crypto::aws_lc_rs as provider;
            $($tt)+
        }
    };
}

test_for_each_provider! {
    #[test]
    fn test_each_provider() {
        std::println!("provider is {:?}", provider::default_provider());
    }
}

bench_for_each_provider! {
    #[bench]
    fn bench_each_provider(b: &mut test::Bencher) {
        b.iter(|| provider::default_provider());
    }
}
