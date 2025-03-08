#![allow(clippy::duplicate_mod)]

#[macro_use]
mod macros;

#[cfg(feature = "ring")]
#[path = "."]
mod tests_with_ring {
    provider_ring!();

    #[path = "../kernel.rs"]
    mod kernel;
}

#[cfg(feature = "aws_lc_rs")]
#[path = "."]
mod tests_with_aws_lc_rs {
    provider_aws_lc_rs!();

    #[path = "../kernel.rs"]
    mod tests;
}
