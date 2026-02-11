//! A TLS server that accepts connections using a custom `Acceptor`, demonstrating how fresh
//! CRL information can be retrieved per-client connection to use for revocation checking of
//! client certificates.
//!
//! For a more complete server demonstration, see `tlsserver-mio.rs`.

use core::ops::Add;
use core::time::Duration;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::{fs, thread};

use clap::Parser;
use rcgen::{Issuer, KeyPair, SerialNumber};
use rustls::crypto::{CryptoProvider, Identity};
use rustls::pki_types::{CertificateRevocationListDer, PrivatePkcs8KeyDer};
use rustls::server::{Acceptor, ClientHello, ServerConfig, WebPkiClientVerifier};
use rustls::{RootCertStore, TlsInputBuffer};
use rustls_aws_lc_rs::DEFAULT_PROVIDER;
use rustls_util::{KeyLogFile, complete_io};

fn main() {
    let args = Args::parse();

    if args.verbose {
        env_logger::Builder::new()
            .parse_filters("trace")
            .init();
    }

    let write_pem = |path: &str, pem: &str| {
        let mut file = File::create(path).unwrap();
        file.write_all(pem.as_bytes()).unwrap();
    };

    // Create a test PKI with:
    // * An issuing CA certificate.
    // * A server certificate issued by the CA.
    // * A client certificate issued by the CA.
    let test_pki = Arc::new(TestPki::new());

    // Write out the parts of the test PKI a client will need to connect:
    // * The CA certificate for validating the server certificate.
    // * The client certificate and key for its presented mTLS identity.
    write_pem(&args.ca_path, &test_pki.ca_cert.1.pem());
    write_pem(&args.client_cert_path, &test_pki.client_cert.0.cert.pem());
    write_pem(
        &args.client_key_path,
        &test_pki
            .client_cert
            .0
            .signing_key
            .serialize_pem(),
    );

    // Write out an initial DER CRL that has no revoked certificates.
    let mut crl_der = File::create(args.crl_path.clone()).unwrap();
    crl_der
        .write_all(&test_pki.crl(Vec::default(), args.crl_update_seconds))
        .unwrap();

    // Spawn a thread that will periodically update the CRL. In a real server you would
    // fetch fresh CRLs from a distribution point, or somehow update the CRLs on disk.
    //
    // For this demo we spawn a thread that flips between writing a CRL that lists the client
    // certificate as revoked and a CRL that has no revoked certificates.
    let crl_updater = CrlUpdater {
        sleep_duration: Duration::from_secs(args.crl_update_seconds),
        crl_path: PathBuf::from(args.crl_path.clone()),
        pki: test_pki.clone(),
    };
    thread::spawn(move || crl_updater.run());

    // Start a TLS server accepting connections as they arrive.
    let listener = std::net::TcpListener::bind(format!("[::]:{}", args.port)).unwrap();
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut acceptor = Acceptor::default();
        let mut buf = TlsInputBuffer::default();

        // Read TLS packets until we've consumed a full client hello and are ready to accept a
        // connection.
        let accepted = loop {
            buf.read(&mut stream, true).unwrap();
            match acceptor.accept(&mut buf) {
                Ok(Some(accepted)) => break accepted,
                Ok(None) => continue,
                Err((e, mut alert)) => {
                    alert.write_all(&mut stream).unwrap();
                    panic!("error accepting connection: {e}");
                }
            }
        };

        // Generate a server config for the accepted connection, optionally customizing the
        // configuration based on the client hello.
        let config = test_pki.server_config(&args.crl_path, accepted.client_hello());
        let mut conn = match accepted.into_connection(config) {
            Ok(conn) => conn,
            Err((e, mut alert)) => {
                alert.write_all(&mut stream).unwrap();
                panic!("error completing accepting connection: {e}");
            }
        };

        // Proceed with handling the ServerConnection
        // Important: We do no error handling here, but you should!
        _ = complete_io(&mut stream, &mut buf, &mut conn);
    }
}

/// A test PKI with a CA certificate, server certificate, and client certificate.
struct TestPki {
    provider: Arc<CryptoProvider>,
    roots: Arc<RootCertStore>,
    ca_cert: (Issuer<'static, KeyPair>, rcgen::Certificate),
    client_cert: (rcgen::CertifiedKey<KeyPair>, SerialNumber),
    server_cert: rcgen::CertifiedKey<KeyPair>,
}

impl TestPki {
    /// Create a new test PKI using `rcgen`.
    fn new() -> Self {
        // Create an issuer CA cert.
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Rustls Server Acceptor");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate_for(alg).unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca = Issuer::new(ca_params, ca_key);

        // Create a server end entity cert issued by the CA.
        let mut server_ee_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_ee_params.is_ca = rcgen::IsCa::NoCa;
        server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let ee_key = KeyPair::generate_for(alg).unwrap();
        let server_cert = server_ee_params
            .signed_by(&ee_key, &ca)
            .unwrap();

        // Create a client end entity cert issued by the CA.
        let mut client_ee_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        client_ee_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example Client");
        client_ee_params.is_ca = rcgen::IsCa::NoCa;
        client_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let client_serial = SerialNumber::from(vec![0xC0, 0xFF, 0xEE]);
        client_ee_params.serial_number = Some(client_serial);
        let client_key = KeyPair::generate_for(alg).unwrap();
        let client_cert = client_ee_params
            .signed_by(&client_key, &ca)
            .unwrap();

        // Create a root cert store that includes the CA certificate.
        let mut roots = RootCertStore::empty();
        roots
            .add(ca_cert.der().clone())
            .unwrap();
        Self {
            provider: Arc::new(DEFAULT_PROVIDER),
            roots: roots.into(),
            ca_cert: (ca, ca_cert),
            client_cert: (
                rcgen::CertifiedKey {
                    cert: client_cert,
                    signing_key: client_key,
                },
                client_ee_params.serial_number.unwrap(),
            ),
            server_cert: rcgen::CertifiedKey {
                cert: server_cert,
                signing_key: ee_key,
            },
        }
    }

    /// Generate a server configuration for the client using the test PKI.
    ///
    /// Importantly this creates a new client certificate verifier per-connection so that the server
    /// can read in the latest CRL content from disk.
    ///
    /// Since the presented client certificate is not available in the `ClientHello` the server
    /// must know ahead of time which CRLs it cares about.
    fn server_config(&self, crl_path: &str, _hello: ClientHello<'_>) -> Arc<ServerConfig> {
        // Read the latest CRL from disk. The CRL is being periodically updated by the crl_updater
        // thread.
        let mut crl_file = File::open(crl_path).unwrap();
        let mut crl = Vec::default();
        crl_file.read_to_end(&mut crl).unwrap();

        // Construct a fresh verifier using the test PKI roots, and the updated CRL.
        let verifier = Arc::new(
            WebPkiClientVerifier::builder(self.roots.clone(), &self.provider)
                .with_crls([CertificateRevocationListDer::from(crl)])
                .build()
                .unwrap(),
        );

        // Build a server config using the fresh verifier. If necessary, this could be customized
        // based on the ClientHello (e.g. selecting a different certificate, or customizing
        // supported algorithms/protocol versions).
        let mut server_config = ServerConfig::builder(self.provider.clone())
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                Arc::from(
                    Identity::from_cert_chain(vec![self.server_cert.cert.der().clone()]).unwrap(),
                ),
                PrivatePkcs8KeyDer::from(
                    self.server_cert
                        .signing_key
                        .serialize_der(),
                )
                .into(),
            )
            .unwrap();

        // Allow using SSLKEYLOGFILE.
        server_config.key_log = Arc::new(KeyLogFile::new());

        Arc::new(server_config)
    }

    /// Issue a certificate revocation list (CRL) for the revoked `serials` provided (may be empty).
    /// The CRL will be signed by the test PKI CA and returned in DER serialized form.
    fn crl(
        &self,
        serials: Vec<SerialNumber>,
        next_update_seconds: u64,
    ) -> CertificateRevocationListDer<'static> {
        // In a real use-case you would want to set this to the current date/time.
        let now = rcgen::date_time_ymd(2023, 1, 1);

        // For each serial, create a revoked certificate entry.
        let revoked_certs = serials
            .into_iter()
            .map(|serial| rcgen::RevokedCertParams {
                serial_number: serial,
                revocation_time: now,
                reason_code: Some(rcgen::RevocationReason::KeyCompromise),
                invalidity_date: None,
            })
            .collect();

        // Create a new CRL signed by the CA cert.
        let crl_params = rcgen::CertificateRevocationListParams {
            this_update: now,
            next_update: now.add(Duration::from_secs(next_update_seconds)),
            crl_number: SerialNumber::from(1234),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        crl_params
            .signed_by(&self.ca_cert.0)
            .unwrap()
            .into()
    }
}

/// CRL updater that runs in a separate thread. This periodically updates the CRL file on disk,
/// flipping between writing a CRL that describes the client certificate as revoked, and a CRL that
/// describes the client certificate as not revoked.
///
/// In a real use case, the CRL would be updated by fetching fresh CRL data from an authoritative
/// distribution point.
struct CrlUpdater {
    sleep_duration: Duration,
    crl_path: PathBuf,
    pki: Arc<TestPki>,
}

impl CrlUpdater {
    fn run(self) {
        let mut revoked = true;

        loop {
            thread::sleep(self.sleep_duration);

            let revoked_certs = if revoked {
                vec![self.pki.client_cert.1.clone()]
            } else {
                Vec::default()
            };
            revoked = !revoked;

            // Write the new CRL content to a temp file, this avoids a race condition where the server
            // reads the configured CRL path while we're in the process of writing it.
            let mut tmp_path = self.crl_path.clone();
            tmp_path.set_extension("tmp");
            let mut crl_der = File::create(&tmp_path).unwrap();
            crl_der
                .write_all(
                    &self
                        .pki
                        .crl(revoked_certs, self.sleep_duration.as_secs()),
                )
                .unwrap();

            // Once the new CRL content is available, atomically rename.
            fs::rename(&tmp_path, &self.crl_path).unwrap();
        }
    }
}

/// Runs a TLS server on :PORT.  The default PORT is 4443.
///
/// This example generates its own keys, certificates, and revocation
/// lists.  These are written into the current working directory.
/// Periodically the revocation lists are updated to flip between
/// the client identity being included or excluded in the revocation
/// list.
#[derive(Debug, Parser)]
#[clap(version)]
struct Args {
    /// Listen on this port
    #[clap(long, default_value = "4443")]
    port: u16,

    /// Emit log output
    #[clap(long)]
    verbose: bool,

    /// Update the CRL after this many seconds
    #[clap(long, default_value = "5")]
    crl_update_seconds: u64,

    /// Write the CA cert PEM to this path
    #[clap(long, default_value = "ca-cert.pem")]
    ca_path: String,

    /// Write the client cert PEM to this path
    #[clap(long, default_value = "client-cert.pem")]
    client_cert_path: String,

    /// Write the client key PEM to this path
    #[clap(long, default_value = "client-key.pem")]
    client_key_path: String,

    /// Write the DER CRL content to this path
    #[clap(long, default_value = "crl.der")]
    crl_path: String,
}
