use std::sync::Arc;
use std::{env, process};

use base64::prelude::{BASE64_STANDARD, Engine};
use rustls::crypto::kx::NamedGroup;
use rustls::crypto::{CryptoProvider, SignatureScheme};
use rustls::enums::ProtocolVersion;
use rustls::pki_types::{EchConfigListBytes, ServerName};
use rustls::{DistinguishedName, HandshakeKind};

use super::client::OcspValidation;
use super::{
    BOGO_NACK, CompressionAlgs, Credential, CredentialSet, SelectedProvider, Side, align_time,
    lookup_scheme,
};

#[derive(Debug)]
pub(crate) struct Options {
    pub(crate) port: u16,
    pub(crate) shim_id: u64,
    pub(crate) side: Side,
    pub(crate) max_fragment: Option<usize>,
    pub(crate) resumes: usize,
    pub(crate) verify_peer: bool,
    pub(crate) require_any_client_cert: bool,
    pub(crate) server_preference: bool,
    pub(crate) root_hint_subjects: Vec<DistinguishedName>,
    pub(crate) offer_no_client_cas: bool,
    pub(crate) tickets: bool,
    pub(crate) resume_with_tickets_disabled: bool,
    pub(crate) queue_data: bool,
    pub(crate) queue_data_on_resume: bool,
    pub(crate) initial_write_on_resume: Option<Vec<u8>>,
    pub(crate) repeat_initial_write_on_resume: usize,
    pub(crate) only_write_one_byte_after_handshake: bool,
    pub(crate) only_write_one_byte_after_handshake_on_resume: bool,
    pub(crate) shut_down_after_handshake: bool,
    pub(crate) check_close_notify: bool,
    pub(crate) host_name: String,
    pub(crate) use_sni: bool,
    pub(crate) trusted_cert_file: String,
    pub(crate) credentials: CredentialSet,
    pub(crate) protocols: Vec<String>,
    pub(crate) reject_alpn: bool,
    pub(crate) support_tls13: bool,
    pub(crate) support_tls12: bool,
    pub(crate) min_version: Option<ProtocolVersion>,
    pub(crate) max_version: Option<ProtocolVersion>,
    pub(crate) server_ocsp_response: Arc<[u8]>,
    pub(crate) groups: Option<Vec<NamedGroup>>,
    pub(crate) server_supported_group_hint: Option<NamedGroup>,
    pub(crate) export_keying_material: usize,
    pub(crate) export_keying_material_label: String,
    pub(crate) export_keying_material_context: String,
    pub(crate) export_keying_material_context_used: bool,
    pub(crate) export_traffic_secrets: bool,
    pub(crate) read_size: usize,
    pub(crate) quic_transport_params: Vec<u8>,
    pub(crate) expect_quic_transport_params: Vec<u8>,
    pub(crate) enable_early_data: bool,
    pub(crate) expect_ticket_supports_early_data: bool,
    pub(crate) expect_accept_early_data: bool,
    pub(crate) expect_reject_early_data: bool,
    pub(crate) expect_version: u16,
    pub(crate) resumption_delay: u32,
    pub(crate) queue_early_data_after_received_messages: Vec<usize>,
    pub(crate) require_ems: bool,
    pub(crate) expect_handshake_kind: Option<Vec<HandshakeKind>>,
    pub(crate) expect_handshake_kind_resumed: Option<Vec<HandshakeKind>>,
    pub(crate) install_cert_compression_algs: CompressionAlgs,
    pub(crate) selected_provider: SelectedProvider,
    pub(crate) provider: CryptoProvider,
    pub(crate) ech_config_list: Option<EchConfigListBytes<'static>>,
    pub(crate) expect_ech_accept: bool,
    pub(crate) expect_ech_retry_configs: Option<EchConfigListBytes<'static>>,
    pub(crate) expect_no_ech_retry_configs: bool,
    pub(crate) on_resume_ech_config_list: Option<EchConfigListBytes<'static>>,
    pub(crate) on_resume_expect_ech_accept: bool,
    pub(crate) on_initial_expect_ech_accept: bool,
    pub(crate) enable_ech_grease: bool,
    pub(crate) reject_unusable_ech_config: bool,
    pub(crate) expect_ech_name_override: Option<String>,
    pub(crate) expect_no_ech_name_override: bool,
    pub(crate) on_retry_expect_ech_name_override: Option<String>,
    pub(crate) send_key_update: bool,
    pub(crate) expect_curve_id: Option<NamedGroup>,
    pub(crate) on_initial_expect_curve_id: Option<NamedGroup>,
    pub(crate) on_resume_expect_curve_id: Option<NamedGroup>,
    pub(crate) wait_for_debugger: bool,
    pub(crate) ocsp: OcspValidation,
    pub(crate) verify_prefs: Option<SignatureScheme>,
}

impl Options {
    pub(crate) fn new() -> Self {
        let selected_provider = match env::var("BOGO_SHIM_PROVIDER")
            .ok()
            .as_deref()
        {
            None | Some("aws-lc-rs") => SelectedProvider::AwsLcRs,
            #[cfg(feature = "fips")]
            Some("aws-lc-rs-fips") => SelectedProvider::AwsLcRsFips,
            Some("ring") => SelectedProvider::Ring,
            Some(other) => panic!("unrecognized value for BOGO_SHIM_PROVIDER: {other:?}"),
        };

        Self {
            port: 0,
            shim_id: 0,
            side: Side::Client,
            max_fragment: None,
            resumes: 0,
            verify_peer: false,
            tickets: true,
            resume_with_tickets_disabled: false,
            host_name: "example.com".to_string(),
            use_sni: false,
            queue_data: false,
            queue_data_on_resume: false,
            initial_write_on_resume: None,
            repeat_initial_write_on_resume: 1,
            only_write_one_byte_after_handshake: false,
            only_write_one_byte_after_handshake_on_resume: false,
            shut_down_after_handshake: false,
            check_close_notify: false,
            require_any_client_cert: false,
            server_preference: false,
            root_hint_subjects: vec![],
            offer_no_client_cas: false,
            trusted_cert_file: "".to_string(),
            credentials: CredentialSet::default(),
            protocols: vec![],
            reject_alpn: false,
            support_tls13: true,
            support_tls12: true,
            min_version: None,
            max_version: None,
            server_ocsp_response: Arc::from([]),
            groups: None,
            server_supported_group_hint: None,
            export_keying_material: 0,
            export_keying_material_label: "".to_string(),
            export_keying_material_context: "".to_string(),
            export_keying_material_context_used: false,
            export_traffic_secrets: false,
            read_size: 512,
            quic_transport_params: vec![],
            expect_quic_transport_params: vec![],
            enable_early_data: false,
            expect_ticket_supports_early_data: false,
            expect_accept_early_data: false,
            expect_reject_early_data: false,
            expect_version: 0,
            resumption_delay: 0,
            queue_early_data_after_received_messages: vec![],
            require_ems: false,
            expect_handshake_kind: None,
            expect_handshake_kind_resumed: Some(vec![HandshakeKind::Resumed]),
            install_cert_compression_algs: CompressionAlgs::None,
            selected_provider,
            provider: selected_provider.provider(),
            ech_config_list: None,
            expect_ech_accept: false,
            expect_ech_retry_configs: None,
            expect_no_ech_retry_configs: false,
            on_resume_ech_config_list: None,
            on_resume_expect_ech_accept: false,
            on_initial_expect_ech_accept: false,
            enable_ech_grease: false,
            reject_unusable_ech_config: false,
            expect_ech_name_override: None,
            expect_no_ech_name_override: false,
            on_retry_expect_ech_name_override: None,
            send_key_update: false,
            expect_curve_id: None,
            on_initial_expect_curve_id: None,
            on_resume_expect_curve_id: None,
            wait_for_debugger: false,
            ocsp: OcspValidation::default(),
            verify_prefs: None,
        }
    }

    /// The message the shim writes first, and how many times it writes it.
    pub(crate) fn initial_write(&self, count: usize) -> (&[u8], usize) {
        match (count > 0, &self.initial_write_on_resume) {
            (true, Some(message)) => (message, self.repeat_initial_write_on_resume),
            _ => (b"hello", 1),
        }
    }

    fn version_allowed(&self, vers: ProtocolVersion) -> bool {
        (self.min_version.is_none() || u16::from(vers) >= u16::from(self.min_version.unwrap()))
            && (self.max_version.is_none()
                || u16::from(vers) <= u16::from(self.max_version.unwrap()))
    }

    fn tls13_supported(&self) -> bool {
        self.support_tls13 && self.version_allowed(ProtocolVersion::TLSv1_3)
    }

    fn tls12_supported(&self) -> bool {
        self.support_tls12 && self.version_allowed(ProtocolVersion::TLSv1_2)
    }

    pub(crate) fn expected_server_names(&self) -> Vec<ServerName<'static>> {
        let mut names = vec![];

        let name = match (
            &self.expect_ech_name_override,
            self.expect_no_ech_name_override,
        ) {
            (Some(override_name), _) => override_name,
            (None, true) => &self.host_name,
            (None, false) => return names,
        };

        names.push(
            ServerName::try_from(name.as_str())
                .expect("invalid expected server name")
                .to_owned(),
        );

        if let Some(on_retry) = &self.on_retry_expect_ech_name_override {
            names.push(
                ServerName::try_from(on_retry.as_str())
                    .expect("invalid expected server name")
                    .to_owned(),
            );
        }

        names
    }

    pub(crate) fn provider(&self) -> CryptoProvider {
        let mut provider = self.provider.clone();

        if !matches!(self.selected_provider, SelectedProvider::Ring)
            && let Some(
                SignatureScheme::ML_DSA_44
                | SignatureScheme::ML_DSA_65
                | SignatureScheme::ML_DSA_87,
            ) = self.verify_prefs
        {
            // ML-DSA is disabled by default, enable for preferred verification scheme
            provider.signature_verification_algorithms = rustls_aws_lc_rs::SUPPORTED_SIG_ALGS;
        }

        if let Some(groups) = &self.groups {
            provider
                .kx_groups
                .to_mut()
                .retain(|kxg| groups.contains(&kxg.name()));
        }

        match (self.tls12_supported(), self.tls13_supported()) {
            (true, true) => provider,
            (true, false) => CryptoProvider {
                tls13_cipher_suites: Default::default(),
                ..provider
            },
            (false, true) => CryptoProvider {
                tls12_cipher_suites: Default::default(),
                ..provider
            },
            _ => panic!("nonsense version constraint"),
        }
    }

    pub(crate) fn parse_one(&mut self, args: &mut Vec<String>) {
        let arg = args.remove(0);
        match arg.as_ref() {
            "-port" => {
                self.port = args.remove(0).parse::<u16>().unwrap();
            }
            "-shim-id" => {
                self.shim_id = args.remove(0).parse::<u64>().unwrap();
            }
            "-server" => {
                self.side = Side::Server;
            }
            "-key-file" => {
                self.credentials.last_mut().key_file = args.remove(0);
            }
            "-new-x509-credential" => {
                self.credentials
                    .additional
                    .push(Credential::default());
            }
            "-expect-selected-credential" => {
                self.credentials.expect_selected = args.remove(0).parse::<isize>().ok();
            }
            "-cert-file" => {
                self.credentials.last_mut().cert_file = args.remove(0);
            }
            "-trust-cert" => {
                self.trusted_cert_file = args.remove(0);
            }
            "-resume-count" => {
                self.resumes = args.remove(0).parse::<usize>().unwrap();
            }
            "-no-tls13" => {
                self.support_tls13 = false;
            }
            "-no-tls12" => {
                self.support_tls12 = false;
            }
            "-min-version" => {
                let min = args.remove(0).parse::<u16>().unwrap();
                self.min_version = Some(ProtocolVersion(min));
            }
            "-max-version" => {
                let max = args.remove(0).parse::<u16>().unwrap();
                self.max_version = Some(ProtocolVersion(max));
            }
            "-max-send-fragment" => {
                let max_fragment = args.remove(0).parse::<usize>().unwrap();
                // ours includes header and overhead, OpenSSL includes neither.
                self.max_fragment = Some(max_fragment + 5);
            }
            "-read-size" => {
                let rdsz = args.remove(0).parse::<usize>().unwrap();
                self.read_size = rdsz;
            }
            "-tls13-variant" => {
                let variant = args.remove(0).parse::<u16>().unwrap();
                if variant != 1 {
                    println!("NYI TLS1.3 variant selection: {arg:?} {variant:?}");
                    process::exit(BOGO_NACK);
                }
            }
            "-no-ticket" => {
                self.tickets = false;
            }
            "-on-resume-no-ticket" => {
                self.resume_with_tickets_disabled = true;
            }
            "-signing-prefs" => {
                let alg = args.remove(0).parse::<u16>().unwrap();
                self.credentials
                    .last_mut()
                    .use_signing_scheme = Some(alg);
            }
            "-must-match-issuer" => {
                self.credentials
                    .last_mut()
                    .must_match_issuer = true;
            }
            "-use-client-ca-list" => match args.remove(0).as_ref() {
                "<EMPTY>" | "<NULL>" => {
                    self.root_hint_subjects = vec![];
                }
                list => {
                    self.root_hint_subjects = list
                        .split(',')
                        .map(|entry| DistinguishedName::from(decode_hex(entry)))
                        .collect();
                }
            },
            "-verify-prefs" => {
                self.verify_prefs = Some(lookup_scheme(args.remove(0).parse::<u16>().unwrap()));
            }
            "-expect-curve-id" => {
                self.expect_curve_id =
                    Some(NamedGroup::from(args.remove(0).parse::<u16>().unwrap()));
            }
            "-on-initial-expect-curve-id" => {
                self.on_initial_expect_curve_id =
                    Some(NamedGroup::from(args.remove(0).parse::<u16>().unwrap()));
            }
            "-on-resume-expect-curve-id" => {
                self.on_resume_expect_curve_id =
                    Some(NamedGroup::from(args.remove(0).parse::<u16>().unwrap()));
            }
            "-max-cert-list"
            | "-expect-peer-signature-algorithm"
            | "-expect-peer-verify-pref"
            | "-expect-advertised-alpn"
            | "-expect-alpn"
            | "-on-initial-expect-alpn"
            | "-on-resume-expect-alpn"
            | "-on-retry-expect-alpn"
            | "-expect-server-name"
            | "-expect-ocsp-response"
            | "-expect-signed-cert-timestamps"
            | "-expect-certificate-types"
            | "-expect-client-ca-list"
            | "-on-initial-expect-early-data-reason"
            | "-on-initial-expect-cipher"
            | "-on-resume-expect-cipher"
            | "-on-retry-expect-cipher"
            | "-expect-ticket-age-skew"
            | "-handshaker-path"
            | "-application-settings"
            | "-expect-msg-callback" => {
                println!("not checking {} {}; NYI", arg, args.remove(0));
            }

            "-expect-secure-renegotiation"
            | "-expect-no-session-id"
            | "-enable-ed25519"
            | "-on-resume-expect-no-offer-early-data"
            | "-expect-tls13-downgrade"
            | "-enable-signed-cert-timestamps"
            | "-expect-session-id" => {
                println!("not checking {arg}; NYI");
            }

            "-key-update" => {
                self.send_key_update = true;
            }
            "-expect-hrr" => {
                self.expect_handshake_kind = Some(vec![HandshakeKind::FullWithHelloRetryRequest]);
                self.expect_handshake_kind_resumed =
                    Some(vec![HandshakeKind::ResumedWithHelloRetryRequest]);
            }
            "-expect-no-hrr" => {
                self.expect_handshake_kind = Some(vec![HandshakeKind::Full]);
            }
            "-on-retry-expect-early-data-reason" | "-on-resume-expect-early-data-reason" => {
                if args.remove(0) == "hello_retry_request" {
                    self.expect_handshake_kind_resumed =
                        Some(vec![HandshakeKind::ResumedWithHelloRetryRequest]);
                }
            }
            "-expect-session-miss" => {
                self.expect_handshake_kind_resumed = Some(vec![
                    HandshakeKind::Full,
                    HandshakeKind::FullWithHelloRetryRequest,
                ]);
            }
            "-export-keying-material" => {
                self.export_keying_material = args.remove(0).parse::<usize>().unwrap();
            }
            "-export-label" => {
                self.export_keying_material_label = args.remove(0);
            }
            "-export-context" => {
                self.export_keying_material_context = args.remove(0);
            }
            "-use-export-context" => {
                self.export_keying_material_context_used = true;
            }
            "-export-traffic-secrets" => {
                self.export_traffic_secrets = true;
            }
            "-quic-transport-params" => {
                self.quic_transport_params = BASE64_STANDARD
                    .decode(args.remove(0).as_bytes())
                    .expect("invalid base64");
            }
            "-expect-quic-transport-params" => {
                self.expect_quic_transport_params = BASE64_STANDARD
                    .decode(args.remove(0).as_bytes())
                    .expect("invalid base64");
            }

            "-ocsp-response" => {
                self.server_ocsp_response = Arc::from(
                    BASE64_STANDARD
                        .decode(args.remove(0).as_bytes())
                        .expect("invalid base64"),
                );
            }
            "-select-alpn" => {
                self.protocols.push(args.remove(0));
            }
            "-require-any-client-certificate" => {
                self.require_any_client_cert = true;
            }
            "-verify-peer" => {
                self.verify_peer = true;
            }
            "-shim-writes-first" => {
                self.queue_data = true;
            }
            "-read-with-unfinished-write" => {
                self.queue_data = true;
                self.only_write_one_byte_after_handshake = true;
            }
            "-shim-shuts-down" => {
                self.shut_down_after_handshake = true;
            }
            "-check-close-notify" => {
                self.check_close_notify = true;
            }
            "-host-name" => {
                self.host_name = args.remove(0);
                self.use_sni = true;
            }
            "-advertise-alpn" => {
                self.protocols = split_protocols(&args.remove(0));
            }
            "-reject-alpn" => {
                self.reject_alpn = true;
            }
            "-use-null-client-ca-list" => {
                self.offer_no_client_cas = true;
            }
            "-enable-early-data" => {
                self.tickets = false;
                self.enable_early_data = true;
            }
            "-on-resume-shim-writes-first" => {
                self.queue_data_on_resume = true;
            }
            "-on-resume-shim-initial-write" => {
                self.initial_write_on_resume = Some(args.remove(0).into_bytes());
            }
            "-on-resume-repeat-shim-initial-write" => {
                self.repeat_initial_write_on_resume = args.remove(0).parse().unwrap();
            }
            "-on-resume-read-with-unfinished-write" => {
                self.queue_data_on_resume = true;
                self.only_write_one_byte_after_handshake_on_resume = true;
            }
            "-on-resume-early-write-after-message" => {
                self.queue_early_data_after_received_messages =
                    match args.remove(0).parse::<u8>().unwrap() {
                        // estimate where these messages appear in the server's first flight.
                        2 => vec![5 + 112 + 5 + 32],
                        8 => vec![5 + 112 + 5 + 32, 5 + 64],
                        _ => {
                            panic!("unhandled -on-resume-early-write-after-message");
                        }
                    };
                self.queue_data_on_resume = true;
            }
            "-expect-ticket-supports-early-data" => {
                self.expect_ticket_supports_early_data = true;
            }
            "-expect-accept-early-data" | "-on-resume-expect-accept-early-data" => {
                self.expect_accept_early_data = true;
            }
            "-expect-early-data-reason" | "-on-resume-expect-reject-early-data-reason" => {
                let reason = args.remove(0);
                match reason.as_str() {
                    "disabled" | "protocol_version" => {
                        self.expect_reject_early_data = true;
                    }
                    _ => {
                        println!("NYI early data reason: {reason}");
                        process::exit(1);
                    }
                }
            }
            "-expect-reject-early-data" | "-on-resume-expect-reject-early-data" => {
                self.expect_reject_early_data = true;
            }
            "-expect-version" => {
                self.expect_version = args.remove(0).parse::<u16>().unwrap();
            }
            "-curves" => {
                let group = NamedGroup::from(args.remove(0).parse::<u16>().unwrap());
                self.groups
                    .get_or_insert(Vec::new())
                    .push(group);
            }
            "-server-supported-groups-hint" => {
                let group = NamedGroup::from(args.remove(0).parse::<u16>().unwrap());
                self.server_supported_group_hint = Some(group);
            }
            "-resumption-delay" => {
                self.resumption_delay = args.remove(0).parse::<u32>().unwrap();
                align_time();
            }
            "-expect-extended-master-secret" => {
                self.require_ems = true;
            }
            "-install-cert-compression-algs" => {
                self.install_cert_compression_algs = CompressionAlgs::All;
            }
            "-install-one-cert-compression-alg" => {
                self.install_cert_compression_algs =
                    CompressionAlgs::One(args.remove(0).parse::<u16>().unwrap());
            }
            #[cfg(feature = "fips")]
            "-fips-202205" if self.selected_provider == SelectedProvider::AwsLcRsFips => {
                self.provider = rustls_aws_lc_rs::DEFAULT_FIPS_PROVIDER.clone();
            }
            "-fips-202205" => {
                println!("Not a FIPS build");
                process::exit(BOGO_NACK);
            }
            "-ech-config-list" => {
                self.ech_config_list = Some(
                    BASE64_STANDARD
                        .decode(args.remove(0).as_bytes())
                        .expect("invalid ECH config base64")
                        .into(),
                );
            }
            "-expect-ech-accept" => {
                self.expect_ech_accept = true;
            }
            "-expect-ech-retry-configs" => {
                self.expect_ech_retry_configs = Some(
                    BASE64_STANDARD
                        .decode(args.remove(0).as_bytes())
                        .expect("invalid ECH config base64")
                        .into(),
                );
            }
            "-on-resume-ech-config-list" => {
                self.on_resume_ech_config_list = Some(
                    BASE64_STANDARD
                        .decode(args.remove(0).as_bytes())
                        .expect("invalid on resume ECH config base64")
                        .into(),
                );
            }
            "-on-resume-expect-ech-accept" => {
                self.on_resume_expect_ech_accept = true;
            }
            "-expect-no-ech-retry-configs" => {
                self.expect_ech_retry_configs = None;
                self.expect_no_ech_retry_configs = true;
            }
            "-on-initial-expect-ech-accept" => {
                self.on_initial_expect_ech_accept = true;
            }
            "-on-retry-expect-ech-retry-configs" => {
                // Note: we treat this the same as -expect-ech-retry-configs
                self.expect_ech_retry_configs = Some(
                    BASE64_STANDARD
                        .decode(args.remove(0).as_bytes())
                        .expect("invalid retry ECH config base64")
                        .into(),
                );
            }
            "-expect-ech-name-override" => {
                self.expect_ech_name_override = Some(args.remove(0));
            }
            "-expect-no-ech-name-override" => {
                self.expect_no_ech_name_override = true;
            }
            "-on-retry-expect-ech-name-override" => {
                self.on_retry_expect_ech_name_override = Some(args.remove(0));
            }
            "-enable-ech-grease" => {
                self.enable_ech_grease = true;
            }
            "-reject-unusable-ech-config" => {
                self.reject_unusable_ech_config = true;
            }
            "-server-preference" => {
                self.server_preference = true;
            }
            "-fail-ocsp-callback" => {
                self.ocsp = OcspValidation::Reject;
            }
            "-wait-for-debugger" => {
                #[cfg(windows)]
                {
                    panic!("-wait-for-debugger not supported on Windows");
                }
                #[cfg(unix)]
                {
                    self.wait_for_debugger = true;
                }
            }

            // defaults:
            "-decline-alpn"
            | "-enable-all-curves"
            | "-enable-ocsp-stapling"
            | "-expect-no-session"
            | "-expect-ticket-renewal"
            | "-forbid-renegotiation-after-handshake"
            | "-handoff"
            | "-ipv6"
            | "-no-legacy-server-connect"
            | "-no-ssl3"
            | "-no-tls1"
            | "-no-tls11"
            | "-on-resume-expect-no-ech-name-override"
            | "-on-retry-expect-no-session"
            | "-permute-extensions"
            | "-renegotiate-ignore"
            | "-use-ocsp-callback"
            | "-async"
            | "-implicit-handshake"
            | "-use-old-client-cert-callback"
            | "-use-early-callback"
            | "-use-custom-verify-callback"
            | "-reverify-on-resume" => {}

            // Not implemented things
            "-advertise-empty-npn"
            | "-advertise-npn"
            | "-allow-hint-mismatch"
            | "-allow-unknown-alpn-protos"
            | "-cipher"
            | "-cnsa-202407"
            | "-cnsa1-202603"
            | "-cnsa2-202603"
            | "-digest-prefs"
            | "-dtls"
            | "-enable-channel-id"
            | "-enable-client-custom-extension"
            | "-enable-grease"
            | "-enable-server-custom-extension"
            | "-expect-channel-id"
            | "-expect-cipher-aes"
            | "-expect-dhe-group-size"
            | "-expect-draft-downgrade"
            | "-expect-early-data-info"
            | "-expect-not-resumable-across-names"
            | "-expect-peer-cert-file"
            | "-expect-resumable-across-names"
            | "-expect-verify-result"
            | "-export-early-keying-material"
            | "-fail-cert-callback"
            | "-fail-early-callback"
            | "-fallback-scsv"
            | "-false-start"
            | "-handshake-twice"
            | "-ignore-tls13-downgrade"
            | "-install-ddos-callback"
            | "-key-shares"
            | "-no-op-extra-handshake"
            | "-no-key-shares"
            | "-no-server-name-ack"
            | "-no-rsa-pss-rsae-certs"
            | "-on-initial-expect-peer-cert-file"
            | "-on-initial-tls13-variant"
            | "-on-resume-enable-early-data"
            | "-on-resume-export-early-keying-material"
            | "-on-resume-verify-fail"
            | "-on-retry-verify-fail"
            | "-psk"
            | "-renegotiate-freely"
            | "-resumption-across-names-enabled"
            | "-retain-only-sha256-client-cert-initial"
            | "-select-empty-next-proto"
            | "-select-next-proto"
            | "-send-alert"
            | "-send-channel-id"
            | "-signed-cert-timestamps"
            | "-srtp-profiles"
            | "-ticket-key"
            | "-tls-unique"
            | "-use-exporter-between-reads"
            | "-use-ticket-aead-callback"
            | "-use-ticket-callback"
            | "-verify-fail"
            | "-wpa-202304" => {
                println!("NYI option {arg:?}");
                process::exit(BOGO_NACK);
            }

            "-print-rustls-provider" => {
                println!("{}", "*".repeat(66));
                println!("rustls provider is {:?}", self.selected_provider);
                println!("{}", "*".repeat(66));
                process::exit(0);
            }

            _ => {
                println!("unhandled option {arg:?}");
                process::exit(1);
            }
        }
    }
}

fn split_protocols(protos: &str) -> Vec<String> {
    let mut ret = Vec::new();

    let mut offs = 0;
    while offs < protos.len() {
        let len = protos.as_bytes()[offs] as usize;
        let item = protos[offs + 1..offs + 1 + len].to_string();
        ret.push(item);
        offs += 1 + len;
    }

    ret
}

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .inspect(|x| println!("item {x:?}"))
        .collect()
}
