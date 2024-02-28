//! A TLS server that accepts connections using a custom `Acceptor`, demonstrating how fresh
//! CRL information can be retrieved per-client connection to use for revocation checking of
//! client certificates.
//!
//! For a more complete server demonstration, see `tlsserver-mio.rs`.

use std::fs::File;
use std::io::{Read, Write};
use std::ops::Add;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::{fs, thread};

use docopt::Docopt;
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, PrivatePkcs8KeyDer,
};
use rustls::server::{Acceptor, ClientHello, ServerConfig, WebPkiClientVerifier};
use rustls::RootCertStore;
use serde_derive::Deserialize;

fn main() {
    let version = concat!(
        env!("CARGO_PKG_NAME"),
        ", version: ",
        env!("CARGO_PKG_VERSION")
    )
    .to_string();

    let args: Args = Docopt::new(USAGE)
        .map(|d| d.help(true))
        .map(|d| d.version(Some(version)))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_verbose {
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
    write_pem(
        &args
            .flag_ca_path
            .unwrap_or("ca-cert.pem".to_string()),
        &test_pki
            .ca_cert
            .serialize_pem()
            .unwrap(),
    );
    write_pem(
        &args
            .flag_client_cert_path
            .unwrap_or("client-cert.pem".to_string()),
        &test_pki
            .client_cert
            .serialize_pem_with_signer(&test_pki.ca_cert)
            .unwrap(),
    );
    write_pem(
        &args
            .flag_client_key_path
            .unwrap_or("client-key.pem".to_string()),
        &test_pki
            .client_cert
            .serialize_private_key_pem(),
    );

    // Write out an initial DER CRL that has no revoked certificates.
    let update_seconds = args
        .flag_crl_update_seconds
        .unwrap_or(5);
    let crl_path = args
        .flag_crl_path
        .unwrap_or("crl.der".to_string());
    let mut crl_der = File::create(crl_path.clone()).unwrap();
    crl_der
        .write_all(&test_pki.crl(Vec::default(), update_seconds))
        .unwrap();

    // Spawn a thread that will periodically update the CRL. In a real server you would
    // fetch fresh CRLs from a distribution point, or somehow update the CRLs on disk.
    //
    // For this demo we spawn a thread that flips between writing a CRL that lists the client
    // certificate as revoked and a CRL that has no revoked certificates.
    let crl_updater = CrlUpdater {
        sleep_duration: Duration::from_secs(update_seconds),
        crl_path: PathBuf::from(crl_path.clone()),
        pki: test_pki.clone(),
    };
    thread::spawn(move || crl_updater.run());

    // Start a TLS server accepting connections as they arrive.
    let listener =
        std::net::TcpListener::bind(format!("[::]:{}", args.flag_port.unwrap_or(4443))).unwrap();
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut acceptor = Acceptor::default();

        // Read TLS packets until we've consumed a full client hello and are ready to accept a
        // connection.
        let accepted = loop {
            acceptor.read_tls(&mut stream).unwrap();

            match acceptor.accept() {
                Ok(Some(accepted)) => break accepted,
                Ok(None) => continue,
                Err((e, mut alert)) => {
                    alert.write(&mut stream).unwrap();
                    panic!("error accepting connection: {e}");
                }
            }
        };

        // Generate a server config for the accepted connection, optionally customizing the
        // configuration based on the client hello.
        let config = test_pki.server_config(&crl_path, accepted.client_hello());
        let mut conn = match accepted.into_connection(config) {
            Ok(conn) => conn,
            Err((e, mut alert)) => {
                alert.write(&mut stream).unwrap();
                panic!("error completing accepting connection: {e}");
            }
        };

        // Proceed with handling the ServerConnection
        // Important: We do no error handling here, but you should!
        _ = conn.complete_io(&mut stream);
    }
}

/// A test PKI with a CA certificate, server certificate, and client certificate.
struct TestPki {
    roots: Arc<RootCertStore>,
    ca_cert: rcgen::Certificate,
    client_cert: rcgen::Certificate,
    server_cert_der: CertificateDer<'static>,
    server_key_der: PrivateKeyDer<'static>,
}

impl TestPki {
    /// Create a new test PKI using `rcgen`.
    fn new() -> Self {
        // Create an issuer CA cert.
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let mut ca_params = rcgen::CertificateParams::new(Vec::new());
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
        ca_params.alg = alg;
        let ca_cert = rcgen::Certificate::from_params(ca_params).unwrap();

        // Create a server end entity cert issued by the CA.
        let mut server_ee_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
        server_ee_params.is_ca = rcgen::IsCa::NoCa;
        server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        server_ee_params.alg = alg;
        let server_cert = rcgen::Certificate::from_params(server_ee_params).unwrap();
        let server_cert_der = CertificateDer::from(
            server_cert
                .serialize_der_with_signer(&ca_cert)
                .unwrap(),
        );
        let server_key_der = PrivatePkcs8KeyDer::from(server_cert.serialize_private_key_der());

        // Create a client end entity cert issued by the CA.
        let mut client_ee_params = rcgen::CertificateParams::new(Vec::new());
        client_ee_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example Client");
        client_ee_params.is_ca = rcgen::IsCa::NoCa;
        client_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        client_ee_params.alg = alg;
        client_ee_params.serial_number = Some(rcgen::SerialNumber::from(vec![0xC0, 0xFF, 0xEE]));
        let client_cert = rcgen::Certificate::from_params(client_ee_params).unwrap();

        // Create a root cert store that includes the CA certificate.
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_cert.serialize_der().unwrap()))
            .unwrap();
        Self {
            roots: roots.into(),
            ca_cert,
            client_cert,
            server_cert_der,
            server_key_der: server_key_der.into(),
        }
    }

    /// Generate a server configuration for the client using the test PKI.
    ///
    /// Importantly this creates a new client certificate verifier per-connection so that the server
    /// can read in the latest CRL content from disk.
    ///
    /// Since the presented client certificate is not available in the `ClientHello` the server
    /// must know ahead of time which CRLs it cares about.
    fn server_config(&self, crl_path: &str, _hello: ClientHello) -> Arc<ServerConfig> {
        // Read the latest CRL from disk. The CRL is being periodically updated by the crl_updater
        // thread.
        let mut crl_file = File::open(crl_path).unwrap();
        let mut crl = Vec::default();
        crl_file.read_to_end(&mut crl).unwrap();

        // Construct a fresh verifier using the test PKI roots, and the updated CRL.
        let verifier = WebPkiClientVerifier::builder(self.roots.clone())
            .with_crls([CertificateRevocationListDer::from(crl)])
            .build()
            .unwrap();

        // Build a server config using the fresh verifier. If necessary, this could be customized
        // based on the ClientHello (e.g. selecting a different certificate, or customizing
        // supported algorithms/protocol versions).
        let mut server_config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![self.server_cert_der.clone()],
                PrivatePkcs8KeyDer::from(
                    self.server_key_der
                        .secret_der()
                        .to_owned(),
                )
                .into(),
            )
            .unwrap();

        // Allow using SSLKEYLOGFILE.
        server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        Arc::new(server_config)
    }

    /// Issue a certificate revocation list (CRL) for the revoked `serials` provided (may be empty).
    /// The CRL will be signed by the test PKI CA and returned in DER serialized form.
    fn crl(&self, serials: Vec<rcgen::SerialNumber>, next_update_seconds: u64) -> Vec<u8> {
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
        let crl = rcgen::CertificateRevocationListParams {
            this_update: now,
            next_update: now.add(Duration::from_secs(next_update_seconds)),
            crl_number: rcgen::SerialNumber::from(1234),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
            alg: &rcgen::PKCS_ECDSA_P256_SHA256,
        };
        rcgen::CertificateRevocationList::from_params(crl)
            .unwrap()
            .serialize_der_with_signer(&self.ca_cert)
            .unwrap()
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
                vec![self
                    .pki
                    .client_cert
                    .get_params()
                    .serial_number
                    .clone()
                    .unwrap()]
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

const USAGE: &str = "
Runs a TLS server on :PORT.  The default PORT is 4443.

Usage:
  server_acceptor [options]
  server_acceptor  (--version | -v)
  server_acceptor  (--help | -h)

Options:
    -p, --port PORT                 Listen on PORT [default: 4443].
    --verbose                       Emit log output.
    --crl-update-seconds SECONDS    Update the CRL after SECONDS [default: 5].
    --ca-path PATH                  Write the CA cert PEM to PATH [default: ca-cert.pem].
    --client-cert-path PATH         Write the client cert PEM to PATH [default: client-cert.pem].
    --client-key-path PATH          Write the client key PEM to PATH [default: client-key.pem].
    --crl-path PATH                 Write the DER CRL content to PATH [default: crl.der].
    --version, -v                   Show tool version.
    --help, -h                      Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_port: Option<u16>,
    flag_verbose: bool,
    flag_crl_update_seconds: Option<u64>,
    flag_ca_path: Option<String>,
    flag_client_cert_path: Option<String>,
    flag_client_key_path: Option<String>,
    flag_crl_path: Option<String>,
}
