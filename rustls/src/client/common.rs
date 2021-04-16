#[cfg(feature = "logging")]
use crate::log::trace;
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::CertificatePayload;
use crate::msgs::handshake::DigitallySignedStruct;
use crate::msgs::handshake::SCTList;
use crate::msgs::handshake::ServerExtension;
use crate::sign;

use std::sync::Arc;

pub struct ServerCertDetails {
    pub cert_chain: CertificatePayload,
    pub ocsp_response: Vec<u8>,
    pub scts: Option<SCTList>,
}

impl ServerCertDetails {
    pub fn new(
        cert_chain: CertificatePayload,
        ocsp_response: Vec<u8>,
        scts: Option<SCTList>,
    ) -> ServerCertDetails {
        ServerCertDetails {
            cert_chain,
            ocsp_response,
            scts,
        }
    }

    pub fn scts(&self) -> impl Iterator<Item = &[u8]> {
        self.scts
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|payload| payload.0.as_slice())
    }
}

pub struct ServerKxDetails {
    pub kx_params: Vec<u8>,
    pub kx_sig: DigitallySignedStruct,
}

impl ServerKxDetails {
    pub fn new(params: Vec<u8>, sig: DigitallySignedStruct) -> ServerKxDetails {
        ServerKxDetails {
            kx_params: params,
            kx_sig: sig,
        }
    }
}

pub struct ClientHelloDetails {
    pub sent_extensions: Vec<ExtensionType>,
}

impl ClientHelloDetails {
    pub fn new() -> ClientHelloDetails {
        ClientHelloDetails {
            sent_extensions: Vec::new(),
        }
    }

    pub fn server_may_send_sct_list(&self) -> bool {
        self.sent_extensions
            .contains(&ExtensionType::SCT)
    }

    pub fn server_sent_unsolicited_extensions(
        &self,
        received_exts: &[ServerExtension],
        allowed_unsolicited: &[ExtensionType],
    ) -> bool {
        for ext in received_exts {
            let ext_type = ext.get_type();
            if !self.sent_extensions.contains(&ext_type) && !allowed_unsolicited.contains(&ext_type)
            {
                trace!("Unsolicited extension {:?}", ext_type);
                return true;
            }
        }

        false
    }
}

pub struct ReceivedTicketDetails {
    pub new_ticket: Vec<u8>,
    pub new_ticket_lifetime: u32,
}

impl ReceivedTicketDetails {
    pub fn new() -> ReceivedTicketDetails {
        ReceivedTicketDetails::from(Vec::new(), 0)
    }

    pub fn from(ticket: Vec<u8>, lifetime: u32) -> ReceivedTicketDetails {
        ReceivedTicketDetails {
            new_ticket: ticket,
            new_ticket_lifetime: lifetime,
        }
    }
}

pub struct ClientAuthDetails {
    pub certkey: Option<Arc<sign::CertifiedKey>>,
    pub signer: Option<Box<dyn sign::Signer>>,
    pub auth_context: Option<Vec<u8>>,
}

impl ClientAuthDetails {
    pub fn new() -> ClientAuthDetails {
        ClientAuthDetails {
            certkey: None,
            signer: None,
            auth_context: None,
        }
    }
}
