use base64::prelude::*;
use rustls::ffdhe_groups::FfdheGroup;
use rustls::NamedGroup;

use crate::utils::verify_openssl3_available;

#[test]
fn ffdhe_params_correct() {
    use NamedGroup::*;

    verify_openssl3_available();

    let groups = [FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192];
    for group in groups {
        println!("testing {group:?}");
        test_ffdhe_params_correct(group);
    }
}

fn test_ffdhe_params_correct(group: NamedGroup) {
    let (p, g) = get_ffdhe_params_from_openssl(group);
    let openssl_params = FfdheGroup::from_params_trimming_leading_zeros(&p, &g);
    let rustls_params = FfdheGroup::from_named_group(group).unwrap();
    assert_eq!(rustls_params.named_group(), Some(group));

    assert_eq!(rustls_params, openssl_params);
}

/// Get FFDHE parameters `(p, g)` for the given `ffdhe_group` from OpenSSL
fn get_ffdhe_params_from_openssl(ffdhe_group: NamedGroup) -> (Vec<u8>, Vec<u8>) {
    let group = match ffdhe_group {
        NamedGroup::FFDHE2048 => "group:ffdhe2048",
        NamedGroup::FFDHE3072 => "group:ffdhe3072",
        NamedGroup::FFDHE4096 => "group:ffdhe4096",
        NamedGroup::FFDHE6144 => "group:ffdhe6144",
        NamedGroup::FFDHE8192 => "group:ffdhe8192",
        _ => panic!("not an ffdhe group: {ffdhe_group:?}"),
    };

    let openssl_output = std::process::Command::new("openssl")
        .args([
            "genpkey",
            "-genparam",
            "-algorithm",
            "DH",
            "-text",
            "-pkeyopt",
            group,
        ])
        .output()
        .unwrap();

    parse_dh_params_pem(&openssl_output.stdout)
}

/// Parse PEM-encoded DH parameters, returning `(p, g)`
fn parse_dh_params_pem(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let output_str = std::str::from_utf8(data).unwrap();
    let output_str_lines = output_str.lines().collect::<Vec<_>>();
    assert_eq!(output_str_lines[0], "-----BEGIN DH PARAMETERS-----");

    let last_line = output_str_lines
        .iter()
        .enumerate()
        .find(|(_i, l)| **l == "-----END DH PARAMETERS-----")
        .unwrap()
        .0;

    let stripped = &output_str_lines[1..last_line];

    let base64_encoded = stripped
        .iter()
        .fold(String::new(), |acc, l| acc + l);

    let base64_decoded = BASE64_STANDARD
        .decode(base64_encoded)
        .unwrap();

    let res: asn1::ParseResult<_> = asn1::parse(&base64_decoded, |d| {
        d.read_element::<asn1::Sequence>()?
            .parse(|d| {
                let p = d.read_element::<asn1::BigUint>()?;
                let g = d.read_element::<asn1::BigUint>()?;
                Ok((p, g))
            })
    });
    let res = res.unwrap();
    (res.0.as_bytes().to_vec(), res.1.as_bytes().to_vec())
}
