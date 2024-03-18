use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyIdMethod, KeyPair,
    KeyUsagePurpose, RevocationReason, RevokedCertParams, RsaKeySize, SanType, SerialNumber,
    SignatureAlgorithm, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ECDSA_P521_SHA512,
    PKCS_ED25519, PKCS_RSA_SHA256, PKCS_RSA_SHA384, PKCS_RSA_SHA512,
};
use time::OffsetDateTime;

fn main() {
    // Note: these are ordered such that the data dependencies for issuance are satisfied.
    let roles = [
        Role::TrustAnchor,
        Role::Intermediate,
        Role::EndEntity,
        Role::Client,
    ];

    let sig_algs = [
        // Note: for convenience we use the RSA sigalg digest algorithm to inform the RSA modulus
        //   size, mapping SHA256 to RSA 2048, SHA384 to RSA 3072, and SHA512 to RSA 4096.
        &PKCS_RSA_SHA256,
        &PKCS_RSA_SHA384,
        &PKCS_RSA_SHA512,
        &PKCS_ECDSA_P256_SHA256,
        &PKCS_ECDSA_P384_SHA384,
        &PKCS_ECDSA_P521_SHA512,
        &PKCS_ED25519,
    ];

    let mut certified_keys = HashMap::with_capacity(roles.len() * sig_algs.len());
    for role in roles {
        for alg in sig_algs {
            // Generate a key pair and serialize it to a PEM encoded file.
            let key_pair = keypair_for_alg(alg);
            let mut key_pair_file = File::create(role.key_file_path(alg)).unwrap();
            key_pair_file
                .write_all(key_pair.serialize_pem().as_bytes())
                .unwrap();

            // Issue a certificate for the key pair. For trust anchors, this will be self-signed.
            // Otherwise we dig out the issuer and issuer_key for the issuer, which should have
            // been produced in earlier iterations based on the careful ordering of roles.
            let cert = match role {
                Role::TrustAnchor => role
                    .params(alg)
                    .self_signed(&key_pair)
                    .unwrap(),
                Role::Intermediate => {
                    let CertifiedKey {
                        cert: issuer,
                        key_pair: issuer_key,
                    } = certified_keys
                        .get(&(Role::TrustAnchor, alg))
                        .unwrap();
                    role.params(alg)
                        .signed_by(&key_pair, issuer, issuer_key)
                        .unwrap()
                }
                Role::EndEntity | Role::Client => {
                    let CertifiedKey {
                        cert: issuer,
                        key_pair: issuer_key,
                    } = certified_keys
                        .get(&(Role::Intermediate, alg))
                        .unwrap();
                    role.params(alg)
                        .signed_by(&key_pair, issuer, issuer_key)
                        .unwrap()
                }
            };
            // Serialize the issued certificate to a PEM encoded file.
            let mut cert_file = File::create(role.cert_pem_file_path(alg)).unwrap();
            cert_file
                .write_all(cert.pem().as_bytes())
                .unwrap();
            // And to a DER encoded file.
            let mut cert_file = File::create(role.cert_der_file_path(alg)).unwrap();
            cert_file.write_all(cert.der()).unwrap();

            certified_keys.insert((role, alg), CertifiedKey { cert, key_pair });
        }
    }

    // Write the PEM chain and full chain files for the end entity and client certs.
    // Chain files include the intermediate and root certs, while full chain files include
    // the end entity or client cert as well.
    for role in [Role::EndEntity, Role::Client] {
        for alg in sig_algs {
            let CertifiedKey { cert: root, .. } = certified_keys
                .get(&(Role::TrustAnchor, alg))
                .unwrap();
            let CertifiedKey {
                cert: intermediate, ..
            } = certified_keys
                .get(&(Role::Intermediate, alg))
                .unwrap();
            let CertifiedKey {
                cert: end_entity, ..
            } = certified_keys
                .get(&(role, alg))
                .unwrap();
            fn write_chain_file(
                role: Role,
                alg: &'static SignatureAlgorithm,
                name: &str,
                chain_certs: &[&Certificate],
            ) {
                let mut chain_file =
                    File::create(output_directory(alg).join(format!("{}.{}", role.label(), name)))
                        .unwrap();
                for cert in chain_certs {
                    chain_file
                        .write_all(cert.pem().as_bytes())
                        .unwrap();
                }
            }

            write_chain_file(role, alg, "chain", &[intermediate, root]);
            write_chain_file(role, alg, "fullchain", &[end_entity, intermediate, root]);
        }
    }

    // Write PEM CRLs revoking the client, end entity and intermediate certs.
    for role in [Role::Intermediate, Role::EndEntity, Role::Client] {
        for alg in sig_algs {
            let CertifiedKey { cert, .. } = certified_keys
                .get(&(role, alg))
                .unwrap();

            // The CRL will be signed by the issuer of the certificate being revoked. For
            // intermediates this will be the trust anchor, and for client/EE certs this will
            // be the intermediate.
            let (issuer, issuer_key) = match role {
                Role::Intermediate => {
                    let CertifiedKey {
                        cert: issuer,
                        key_pair: issuer_key,
                    } = certified_keys
                        .get(&(Role::TrustAnchor, alg))
                        .unwrap();
                    (issuer, issuer_key)
                }
                Role::EndEntity | Role::Client => {
                    let CertifiedKey {
                        cert: issuer,
                        key_pair: issuer_key,
                    } = certified_keys
                        .get(&(Role::Intermediate, alg))
                        .unwrap();
                    (issuer, issuer_key)
                }
                _ => panic!("unexpected role for CRL generation: {role:?}"),
            };
            let crl = crl_for_serial(
                cert.params()
                    .serial_number
                    .as_ref()
                    .unwrap(),
            )
            .signed_by(issuer, issuer_key)
            .unwrap();
            let mut crl_file = File::create(
                output_directory(alg).join(format!("{}.revoked.crl.pem", role.label())),
            )
            .unwrap();
            crl_file
                .write_all(crl.pem().unwrap().as_bytes())
                .unwrap();
        }
    }
}

struct CertifiedKey {
    cert: Certificate,
    key_pair: KeyPair,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
enum Role {
    Client,
    EndEntity,
    Intermediate,
    TrustAnchor,
}

impl Role {
    fn key_file_path(&self, alg: &'static SignatureAlgorithm) -> PathBuf {
        output_directory(alg).join(format!("{}.key", self.label()))
    }

    fn cert_pem_file_path(&self, alg: &'static SignatureAlgorithm) -> PathBuf {
        output_directory(alg).join(format!("{}.cert", self.label()))
    }

    fn cert_der_file_path(&self, alg: &'static SignatureAlgorithm) -> PathBuf {
        output_directory(alg).join(format!("{}.der", self.label()))
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::EndEntity => "end",
            Self::Intermediate => "inter",
            Self::TrustAnchor => "ca",
        }
    }

    fn params(&self, alg: &'static SignatureAlgorithm) -> CertificateParams {
        let mut params = CertificateParams::default();
        params.distinguished_name = self.common_name(alg);
        params.use_authority_key_identifier_extension = true;
        let serial = SERIAL_NUMBER.fetch_add(1, Ordering::SeqCst);
        params.serial_number = Some(SerialNumber::from_slice(&serial.to_be_bytes()[..]));

        match self {
            Self::TrustAnchor | Self::Intermediate => {
                params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                params.key_usages = vec![
                    KeyUsagePurpose::CrlSign,
                    KeyUsagePurpose::KeyCertSign,
                    KeyUsagePurpose::DigitalSignature,
                    KeyUsagePurpose::ContentCommitment,
                    KeyUsagePurpose::KeyEncipherment,
                    KeyUsagePurpose::DataEncipherment,
                    KeyUsagePurpose::KeyAgreement,
                ];
                params.extended_key_usages = vec![
                    ExtendedKeyUsagePurpose::ServerAuth,
                    ExtendedKeyUsagePurpose::ClientAuth,
                ];
            }
            Self::EndEntity | Self::Client => {
                params.is_ca = IsCa::NoCa;
                params.key_usages = vec![
                    KeyUsagePurpose::DigitalSignature,
                    KeyUsagePurpose::ContentCommitment,
                ];
                params.subject_alt_names = vec![
                    SanType::DnsName(Ia5String::try_from("testserver.com".to_string()).unwrap()),
                    SanType::DnsName(
                        Ia5String::try_from("second.testserver.com".to_string()).unwrap(),
                    ),
                    SanType::DnsName(Ia5String::try_from("localhost".to_string()).unwrap()),
                    SanType::IpAddress(IpAddr::from_str("198.51.100.1").unwrap()),
                    SanType::IpAddress(IpAddr::from_str("2001:db8::1").unwrap()),
                ];
            }
        }

        // Client certificates additionally get the client auth EKU.
        if matches!(self, Self::Client) {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        }

        params
    }

    fn common_name(&self, alg: &'static SignatureAlgorithm) -> DistinguishedName {
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(
            DnType::CommonName,
            match self {
                Self::Client => "ponytown client".to_string(),
                Self::EndEntity => "testserver.com".to_string(),
                Self::Intermediate => {
                    format!("ponytown {} level 2 intermediate", issuer_cn(alg))
                }
                Self::TrustAnchor => format!("ponytown {} CA", issuer_cn(alg)),
            },
        );
        distinguished_name
    }
}

fn crl_for_serial(serial_number: &SerialNumber) -> CertificateRevocationListParams {
    let now = OffsetDateTime::now_utc();
    CertificateRevocationListParams {
        this_update: now,
        next_update: now + Duration::from_secs(60 * 60 * 24 * 5),
        crl_number: SerialNumber::from(1234),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number: serial_number.clone(),
            revocation_time: now,
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: KeyIdMethod::Sha256,
    }
}

fn output_directory(alg: &'static SignatureAlgorithm) -> PathBuf {
    let output_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../")
        .join("test-ca")
        .join(sig_alg_label(alg));
    fs::create_dir_all(&output_dir).unwrap();
    output_dir
}

fn sig_alg_label(alg: &'static SignatureAlgorithm) -> &'static str {
    if *alg == PKCS_RSA_SHA256 {
        "rsa-2048"
    } else if *alg == PKCS_RSA_SHA384 {
        "rsa-3072"
    } else if *alg == PKCS_RSA_SHA512 {
        "rsa-4096"
    } else if *alg == PKCS_ECDSA_P256_SHA256 {
        "ecdsa-p256"
    } else if *alg == PKCS_ECDSA_P384_SHA384 {
        "ecdsa-p384"
    } else if *alg == PKCS_ECDSA_P521_SHA512 {
        "ecdsa-p521"
    } else if *alg == PKCS_ED25519 {
        "eddsa"
    } else {
        panic!("Unknown algorithm: {:?}", alg);
    }
}

fn issuer_cn(alg: &'static SignatureAlgorithm) -> &'static str {
    if *alg == PKCS_RSA_SHA256 {
        "RSA 2048"
    } else if *alg == PKCS_RSA_SHA384 {
        "RSA 3072"
    } else if *alg == PKCS_RSA_SHA512 {
        "RSA 4096"
    } else if *alg == PKCS_ECDSA_P256_SHA256 {
        "ECDSA p256"
    } else if *alg == PKCS_ECDSA_P384_SHA384 {
        "ECDSA p384"
    } else if *alg == PKCS_ECDSA_P521_SHA512 {
        "ECDSA p521"
    } else if *alg == PKCS_ED25519 {
        "EdDSA"
    } else {
        panic!("Unknown algorithm: {:?}", alg);
    }
}

fn keypair_for_alg(alg: &'static SignatureAlgorithm) -> KeyPair {
    let key_pair = if *alg == PKCS_RSA_SHA256 {
        KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)
    } else if *alg == PKCS_RSA_SHA384 {
        KeyPair::generate_rsa_for(&PKCS_RSA_SHA384, RsaKeySize::_3072)
    } else if *alg == PKCS_RSA_SHA512 {
        KeyPair::generate_rsa_for(&PKCS_RSA_SHA512, RsaKeySize::_4096)
    } else {
        KeyPair::generate_for(alg)
    };
    key_pair.unwrap()
}

static SERIAL_NUMBER: AtomicU64 = AtomicU64::new(1);
