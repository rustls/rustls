//! This module contains parameters for FFDHE named groups as defined
//! in [RFC 7919 Appendix A](https://datatracker.ietf.org/doc/html/rfc7919#appendix-A).

use crate::NamedGroup;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Parameters of an FFDHE group, with Big-endian byte order
pub struct FfdheGroup<'a> {
    pub p: &'a [u8],
    pub g: &'a [u8],
}

impl FfdheGroup<'static> {
    /// Return the `FfdheGroup` corresponding to the provided `NamedGroup`
    /// if it is indeed an FFDHE group
    pub fn from_named_group(named_group: NamedGroup) -> Option<Self> {
        match named_group {
            NamedGroup::FFDHE2048 => Some(FFDHE2048),
            NamedGroup::FFDHE3072 => Some(FFDHE3072),
            NamedGroup::FFDHE4096 => Some(FFDHE4096),
            NamedGroup::FFDHE6144 => Some(FFDHE6144),
            NamedGroup::FFDHE8192 => Some(FFDHE8192),
            _ => None,
        }
    }
}

impl<'a> FfdheGroup<'a> {
    /// Return the `NamedGroup` for the `FfdheGroup` if it represents one.
    pub fn named_group(&self) -> Option<NamedGroup> {
        match *self {
            FFDHE2048 => Some(NamedGroup::FFDHE2048),
            FFDHE3072 => Some(NamedGroup::FFDHE3072),
            FFDHE4096 => Some(NamedGroup::FFDHE4096),
            FFDHE6144 => Some(NamedGroup::FFDHE6144),
            FFDHE8192 => Some(NamedGroup::FFDHE8192),
            _ => None,
        }
    }

    /// Construct an `FfdheGroup` from the given `p` and `g`, trimming any potential leading zeros.
    pub fn from_params_trimming_leading_zeros(p: &'a [u8], g: &'a [u8]) -> Self {
        fn trim_leading_zeros(buf: &[u8]) -> &[u8] {
            for start in 0..buf.len() {
                if buf[start] != 0 {
                    return &buf[start..];
                }
            }
            &[]
        }

        FfdheGroup {
            p: trim_leading_zeros(p),
            g: trim_leading_zeros(g),
        }
    }
}

/// FFDHE2048 group defined in [RFC 7919 Appendix A.1]
///
/// [RFC 7919 Appendix A.1]: https://datatracker.ietf.org/doc/html/rfc7919#appendix-A.1
pub const FFDHE2048: FfdheGroup = FfdheGroup {
    p: include_bytes!("ffdhe_groups/ffdhe2048-modulus.bin"),
    g: &[2],
};

/// FFDHE3072 group defined in [RFC 7919 Appendix A.2]
///
/// [RFC 7919 Appendix A.2]: https://datatracker.ietf.org/doc/html/rfc7919#appendix-A.2
pub const FFDHE3072: FfdheGroup = FfdheGroup {
    p: include_bytes!("ffdhe_groups/ffdhe3072-modulus.bin"),
    g: &[2],
};

/// FFDHE4096 group defined in [RFC 7919 Appendix A.3]
///
/// [RFC 7919 Appendix A.3]: https://datatracker.ietf.org/doc/html/rfc7919#appendix-A.3
pub const FFDHE4096: FfdheGroup = FfdheGroup {
    p: include_bytes!("ffdhe_groups/ffdhe4096-modulus.bin"),
    g: &[2],
};

/// FFDHE6144 group defined in [RFC 7919 Appendix A.4]
///
/// [RFC 7919 Appendix A.4]: https://datatracker.ietf.org/doc/html/rfc7919#appendix-A.4
pub const FFDHE6144: FfdheGroup = FfdheGroup {
    p: include_bytes!("ffdhe_groups/ffdhe6144-modulus.bin"),
    g: &[2],
};

/// FFDHE8192 group defined in [RFC 7919 Appendix A.5]
///
/// [RFC 7919 Appendix A.5]: https://datatracker.ietf.org/doc/html/rfc7919#appendix-A.5
pub const FFDHE8192: FfdheGroup = FfdheGroup {
    p: include_bytes!("ffdhe_groups/ffdhe8192-modulus.bin"),
    g: &[2],
};

#[test]
fn named_group_ffdhe_group_roudtrip() {
    use NamedGroup::*;
    let ffdhe_groups = [FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192];
    for g in ffdhe_groups {
        assert_eq!(
            FfdheGroup::from_named_group(g)
                .unwrap()
                .named_group(),
            Some(g)
        );
    }
}
