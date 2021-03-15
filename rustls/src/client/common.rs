use crate::hash_hs;
#[cfg(feature = "logging")]
use crate::log::trace;
use crate::msgs::enums::ExtensionType;
use crate::msgs::enums::NamedGroup;
use crate::msgs::handshake::CertificatePayload;
use crate::msgs::handshake::DigitallySignedStruct;
use crate::msgs::handshake::SCTList;
use crate::msgs::handshake::ServerExtension;
use crate::msgs::handshake::SessionID;
use crate::msgs::persist;
use crate::sign;
use crate::kx;
use webpki;

use std::mem;

pub struct ServerCertDetails {
    pub cert_chain: CertificatePayload,
    pub ocsp_response: Vec<u8>,
    pub scts: Option<SCTList>,
}

impl ServerCertDetails {
    pub fn new(cert_chain: CertificatePayload,
               ocsp_response: Vec<u8>,
               scts: Option<SCTList>) -> ServerCertDetails {
        ServerCertDetails {
            cert_chain,
            ocsp_response,
            scts,
        }
    }

    pub fn take_chain(&mut self) -> CertificatePayload {
        mem::replace(&mut self.cert_chain, Vec::new())
    }

    pub fn scts(&self) -> impl Iterator<Item=&[u8]> {
        self.scts
            .as_ref()
            .map(|v| v.as_slice())
            .unwrap_or(&[])
            .iter()
            .map(|payload| payload.0.as_slice())
    }
}

pub struct ServerKXDetails {
    pub kx_params: Vec<u8>,
    pub kx_sig: DigitallySignedStruct,
}

impl ServerKXDetails {
    pub fn new(params: Vec<u8>, sig: DigitallySignedStruct) -> ServerKXDetails {
        ServerKXDetails {
            kx_params: params,
            kx_sig: sig,
        }
    }
}

pub struct HandshakeDetails {
    pub resuming_session: Option<persist::ClientSessionValue>,
    pub transcript: hash_hs::HandshakeHash,
    pub session_id: SessionID,
    pub dns_name: webpki::DNSName,
}

impl HandshakeDetails {
    pub fn new(host_name: webpki::DNSName) -> HandshakeDetails {
        HandshakeDetails {
            resuming_session: None,
            transcript: hash_hs::HandshakeHash::new(),
            session_id: SessionID::empty(),
            dns_name: host_name,
        }
    }
}

pub struct ClientHelloDetails {
    pub sent_extensions: Vec<ExtensionType>,
    pub offered_key_shares: Vec<kx::KeyExchange>,
}

impl ClientHelloDetails {
    pub fn new() -> ClientHelloDetails {
        ClientHelloDetails {
            sent_extensions: Vec::new(),
            offered_key_shares: Vec::new(),
        }
    }

    pub fn server_may_send_sct_list(&self) -> bool {
        self.sent_extensions.contains(&ExtensionType::SCT)
    }

    pub fn has_key_share(&self, group: NamedGroup) -> bool {
        self.offered_key_shares
            .iter()
            .any(|share| share.group() == group)
    }

    pub fn find_key_share(&mut self, group: NamedGroup) -> Option<kx::KeyExchange> {
        self.offered_key_shares
            .iter()
            .position(|s| s.group() == group)
            .map(|idx| self.offered_key_shares.remove(idx))
    }

    pub fn find_key_share_and_discard_others(
        &mut self,
        group: NamedGroup,
    ) -> Option<kx::KeyExchange> {
        match self.find_key_share(group) {
            Some(group) => {
                self.offered_key_shares.clear();
                Some(group)
            }
            None => None,
        }
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
    pub cert: Option<CertificatePayload>,
    pub signer: Option<Box<dyn sign::Signer>>,
    pub auth_context: Option<Vec<u8>>,
}

impl ClientAuthDetails {
    pub fn new() -> ClientAuthDetails {
        ClientAuthDetails {
            cert: None,
            signer: None,
            auth_context: None,
        }
    }
}
