use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{DataKind, SEQ_HARD_LIMIT, SEQ_SOFT_LIMIT};
use crate::crypto::cipher::{
    EncodableVersion, OutboundPlain, Record, RecordEncrypter, encode_record_header,
};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{AlertDescription, ApiMisuse, Error};
use crate::msgs::{AlertLevel, Fragmenter, HEADER_SIZE, Message, MessagePayload};
use crate::tls13::key_schedule::KeyScheduleTrafficSend;
use crate::tracing::{debug, error};

/// The data path from us to the peer.
#[derive(Default)]
pub(crate) struct SendPath {
    encrypt_state: EncryptionState,
    pub(crate) may_send_application_data: bool,
    may_send_half_rtt_data: bool,
    /// If we signaled end of stream.
    has_sent_close_notify: bool,
    fragmenter: Fragmenter,
    negotiated_version: Option<ProtocolVersion>,
}

impl SendPath {
    /// Encrypt application data from `payload` into TLS records, appended to `tls`.
    ///
    /// Unlike handshake messages, application data comes from the caller, may be arbitrarily
    /// large, and is always encrypted.
    pub(crate) fn send_appdata_encrypt(
        &mut self,
        payload: DataKind<OutboundPlain<'_>>,
        tls: &mut Vec<u8>,
    ) -> Result<usize, Error> {
        let (early, payload) = match payload {
            DataKind::Early(data) => (true, data),
            DataKind::Traffic(data) => (false, data),
        };

        if !early && !self.may_send_application_data {
            return Err(ApiMisuse::WriteBeforeHandshakeComplete.into());
        } else if self.has_sent_close_notify && !payload.is_empty() {
            return Err(ApiMisuse::WriteAfterSendPathClosed.into());
        }

        let encrypting = match &mut self.encrypt_state {
            EncryptionState::Encrypting(encrypting) => encrypting,
            EncryptionState::Handshake => {
                return Err(ApiMisuse::WriteBeforeHandshakeComplete.into());
            }
            EncryptionState::Retired => {
                return Err(ApiMisuse::WriteAfterSendPathClosed.into());
            }
        };

        let len = payload.len();
        encrypting.key_update_remote.write(tls);
        let limit_reached = encrypting.encrypt_records(
            self.fragmenter.fragment(
                ContentType::ApplicationData,
                EncodableVersion::Legacy(ProtocolVersion::TLSv1_2),
                payload,
                encrypting.encrypted_len(0),
            ),
            tls,
            self.negotiated_version,
        )?;

        if limit_reached {
            error!("traffic keys exhausted, closing connection to prevent security failure");
            self.send_close_notify(tls)?;
            return Err(Error::EncryptError);
        }

        if let KeyUpdateLocal::Requested = encrypting.key_update_local {
            let _ = self.send_key_update_request(tls);
        }

        Ok(len)
    }

    pub(crate) fn send_close_notify(&mut self, tls: &mut Vec<u8>) -> Result<(), Error> {
        if self.has_sent_close_notify {
            return Ok(());
        }
        debug!("Sending warning alert {:?}", AlertDescription::CloseNotify);
        self.has_sent_close_notify = true;
        self.send_alert(AlertLevel::Warning, AlertDescription::CloseNotify, tls)
    }

    pub(crate) fn set_max_fragment_size(&mut self, new: Option<usize>) -> Result<(), Error> {
        self.fragmenter
            .set_max_fragment_size(new)
    }

    pub(super) fn start_outgoing_traffic(&mut self) {
        self.may_send_application_data = true;
        debug_assert!(matches!(self.encrypt_state, EncryptionState::Encrypting(_)));
    }

    pub(super) fn refresh_traffic_keys(&mut self, tls: &mut Vec<u8>) -> Result<(), Error> {
        let encrypting = match &mut self.encrypt_state {
            EncryptionState::Encrypting(encrypting) => encrypting,
            EncryptionState::Retired if self.may_send_application_data => {
                return Err(Error::EncryptError);
            }
            _ => return Err(Error::HandshakeNotComplete),
        };

        if let KeyUpdateLocal::Outstanding = encrypting.key_update_local {
            return Ok(());
        }

        self.send_key_update_request(tls)
    }

    fn send_key_update_request(&mut self, tls: &mut Vec<u8>) -> Result<(), Error> {
        let EncryptionState::Encrypting(encrypting) = &mut self.encrypt_state else {
            return Err(Error::EncryptError);
        };

        if encrypting.tls13_key_schedule.is_none() {
            return Err(Error::HandshakeNotComplete);
        }

        send_short(Message::build_key_update_request(), tls, Some(encrypting))?;

        let Some(ks) = &mut encrypting.tls13_key_schedule else {
            return Err(Error::HandshakeNotComplete);
        };

        let encrypter = ks.update_encrypter();
        encrypting.key_update_local = KeyUpdateLocal::Outstanding;
        self.encrypt_state
            .set_encrypter(encrypter);

        Ok(())
    }

    pub(super) fn export(self) -> Result<(u64, Option<Box<KeyScheduleTrafficSend>>), Error> {
        match self.encrypt_state {
            EncryptionState::Encrypting(mut encrypting) => {
                Ok((encrypting.write_seq, encrypting.tls13_key_schedule.take()))
            }
            _ => Err(Error::EncryptError),
        }
    }

    pub(super) fn has_queued_key_update(&self) -> bool {
        match &self.encrypt_state {
            EncryptionState::Encrypting(encrypting) => {
                matches!(encrypting.key_update_remote, KeyUpdateRemote::Queued(_))
            }
            _ => false,
        }
    }
}

impl SendOutput for SendPath {
    fn negotiated_version(&mut self, version: ProtocolVersion) {
        self.negotiated_version = Some(version);
    }

    fn queue_requested_key_update(&mut self) -> Result<(), Error> {
        let EncryptionState::Encrypting(encrypting) = &mut self.encrypt_state else {
            return Err(Error::EncryptError);
        };

        if let KeyUpdateRemote::Queued(_) = &encrypting.key_update_remote {
            return Ok(());
        }

        let mut queued = Vec::new();
        send_short(
            Message::build_key_update_notify(),
            &mut queued,
            Some(encrypting),
        )?;
        encrypting.key_update_remote = KeyUpdateRemote::Queued(queued);

        let Some(ks) = &mut encrypting.tls13_key_schedule else {
            return Ok(());
        };

        let encrypter = ks.update_encrypter_for_key_update();
        self.encrypt_state
            .set_encrypter(encrypter);

        Ok(())
    }

    fn note_key_update_response(&mut self) {
        match &mut self.encrypt_state {
            EncryptionState::Encrypting(encrypting) => {
                if let KeyUpdateLocal::Outstanding = encrypting.key_update_local {
                    encrypting.key_update_local = KeyUpdateLocal::Idle;
                }
            }
            _ => {
                debug_assert!(
                    false,
                    "note_key_update_response() called in non-encrypting state"
                );
            }
        }
    }

    fn set_encrypter(&mut self, encrypter: Encrypter) {
        self.encrypt_state
            .set_encrypter(encrypter);
    }

    fn update_key_schedule(&mut self, schedule: Box<KeyScheduleTrafficSend>) {
        match &mut self.encrypt_state {
            EncryptionState::Encrypting(encrypting) => {
                encrypting.tls13_key_schedule = Some(schedule)
            }
            _ => {
                debug_assert!(
                    false,
                    "update_key_schedule() called in non-encrypting state"
                );
            }
        }
    }

    fn send_alert(
        &mut self,
        level: AlertLevel,
        desc: AlertDescription,
        tls: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let encrypting = match &mut self.encrypt_state {
            EncryptionState::Encrypting(encrypting) => Some(encrypting),
            EncryptionState::Handshake => None,
            EncryptionState::Retired => return Ok(()),
        };

        let result = send_short(Message::build_alert(level, desc), tls, encrypting);
        if level == AlertLevel::Fatal {
            self.encrypt_state = EncryptionState::Retired;
        }

        result
    }

    fn start_traffic(&mut self) {
        self.may_send_half_rtt_data = true;
        self.start_outgoing_traffic();
    }

    /// Send a raw TLS message, fragmenting it if needed.
    ///
    /// Alerts must be sent with [`Self::send_alert()`] instead.
    fn send_msg(
        &mut self,
        m: Message<'_>,
        must_encrypt: bool,
        tls: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let encrypting = match &mut self.encrypt_state {
            EncryptionState::Encrypting(encrypting) if must_encrypt => Some(encrypting),
            EncryptionState::Encrypting(_) => None,
            EncryptionState::Handshake if must_encrypt => {
                return Err(ApiMisuse::WriteBeforeHandshakeComplete.into());
            }
            EncryptionState::Handshake => None,
            EncryptionState::Retired => return Err(Error::EncryptError),
        };

        debug_assert!(!matches!(m.payload, MessagePayload::Alert(_)));
        let record = Record::from(m);
        if let Some(encrypting) = encrypting {
            let fragments = self.fragmenter.fragment(
                record.typ,
                record.version,
                record.payload.bytes().into(),
                encrypting.encrypted_len(0),
            );

            encrypting.key_update_remote.write(tls);
            if encrypting.encrypt_records(fragments, tls, self.negotiated_version)? {
                error!("traffic keys exhausted, closing connection to prevent security failure");
                self.send_close_notify(tls)?;
                return Err(Error::EncryptError);
            }
            return Ok(());
        }

        let fragments =
            self.fragmenter
                .fragment(record.typ, record.version, record.payload.bytes().into(), 0);

        let count = fragments.len();
        let mut iter = fragments.peekable();
        if let Some(first) = iter.peek() {
            tls.reserve(count * (HEADER_SIZE + first.payload.len()));
        }

        for record in iter {
            record.encode_unencrypted(tls);
        }

        Ok(())
    }
}

/// Record layer that tracks encryption keys.
#[derive(Default)]
enum EncryptionState {
    #[default]
    Handshake,
    Encrypting(Encrypting),
    Retired,
}

impl EncryptionState {
    fn set_encrypter(&mut self, encrypter: Encrypter) {
        let Encrypter {
            encrypter,
            limit: max_records,
        } = encrypter;

        match self {
            Self::Handshake => {
                *self = Self::Encrypting(Encrypting {
                    encrypter,
                    write_seq_max: Ord::min(SEQ_SOFT_LIMIT, max_records),
                    write_seq: 0,
                    key_update_local: KeyUpdateLocal::Idle,
                    key_update_remote: KeyUpdateRemote::Idle,
                    tls13_key_schedule: None,
                });
            }
            Self::Encrypting(encrypting) => {
                encrypting.encrypter = encrypter;
                encrypting.write_seq_max = Ord::min(SEQ_SOFT_LIMIT, max_records);
                encrypting.write_seq = 0;
            }
            // Retirement is permanent.
            Self::Retired => {}
        }
    }
}

struct Encrypting {
    encrypter: Box<dyn RecordEncrypter>,
    write_seq_max: u64,
    write_seq: u64,
    key_update_local: KeyUpdateLocal,
    key_update_remote: KeyUpdateRemote,
    tls13_key_schedule: Option<Box<KeyScheduleTrafficSend>>,
}

impl Encrypting {
    /// Encrypt each fragment in `iter`, appending the resulting records to `tls`.
    ///
    /// The return value indicates whether the confidentiality limit has been reached.
    /// When `true`, the caller should make sure to send a `CloseNotify` message.
    fn encrypt_records<'a>(
        &mut self,
        iter: impl ExactSizeIterator<Item = Record<OutboundPlain<'a>>>,
        tls: &mut Vec<u8>,
        version: Option<ProtocolVersion>,
    ) -> Result<bool, Error> {
        // Make sure we do the right thing when we're approaching the confidentiality limit
        // of the encryption keys. When we reach the hard limit, we must not encrypt any
        // more records with the current keys. If we reach the soft limit, we should either
        // request a key update (for 1.3) or send a close notify (for 1.2).
        let count = iter.len();
        if let Some(last) = (count as u64).checked_sub(1) {
            let last = self.write_seq.saturating_add(last);
            if last >= SEQ_HARD_LIMIT {
                return Err(Error::EncryptError);
            } else if last >= self.write_seq_max {
                match version {
                    // Keep going and signal to the caller that we need a key update
                    Some(ProtocolVersion::TLSv1_3) => {
                        self.key_update_local = KeyUpdateLocal::Requested
                    }
                    // Key updates aren't available, so we're going to stop immediately
                    _ => return Ok(true),
                }
            }
        }

        let mut iter = iter.peekable();
        if let Some(first) = iter.peek() {
            let record_len = HEADER_SIZE + self.encrypted_len(first.payload.len());
            tls.reserve(count * record_len);
        }

        for record in iter {
            self.encrypt_outgoing(record, tls)?;
        }

        Ok(false)
    }

    /// Encrypt a TLS record, returning the fully-encoded record.
    ///
    /// `plain` is a TLS record we'd like to send.
    ///
    /// The result including framing is appended to `output`.
    fn encrypt_outgoing(
        &mut self,
        plain: Record<OutboundPlain<'_>>,
        output: &mut Vec<u8>,
    ) -> Result<(), Error> {
        // Contents are fully overwritten below, so zeroing is pure cost.
        // A fresh buffer gets pre-zeroed memory straight from the allocator
        // while a reused one zeroes only what `resize` grows.
        let needed = HEADER_SIZE + self.encrypted_len(plain.payload.len());
        let start = output.len();
        output.resize(start + needed, 0);
        let written = self.encrypt_outgoing_into(plain, &mut output[start..])?;
        debug_assert_eq!(
            written, needed,
            "RecordEncrypter::encrypt() returned wrong length"
        );
        output.truncate(start + written);
        Ok(())
    }

    /// Encrypt a TLS record directly into `out`, returning the encoded
    /// record's length.
    ///
    /// The record, header included, is written to the front of `out`,
    /// which must be at least `HEADER_SIZE` plus
    /// [`Self::encrypted_len()`](Self::encrypted_len) bytes long.
    fn encrypt_outgoing_into(
        &mut self,
        plain: Record<OutboundPlain<'_>>,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        assert!(self.write_seq < SEQ_HARD_LIMIT);
        let seq = self.write_seq;
        self.write_seq += 1;

        #[cfg(debug_assertions)]
        let (out_ptr, out_len) = (out.as_ptr(), out.len());
        let encrypted = self
            .encrypter
            .encrypt(plain, seq, &mut out[HEADER_SIZE..])?;

        #[cfg(debug_assertions)]
        {
            // `RecordEncrypter::encrypt()` requires the returned payload to be
            // the written prefix of the passed-in buffer. Try to catch misbehaving
            // implementations in debug mode. In release builds a violation would corrupt
            // the sent stream.
            debug_assert_eq!(
                encrypted.payload.as_ptr(),
                out_ptr.wrapping_add(HEADER_SIZE)
            );
            debug_assert!(encrypted.payload.len() <= out_len - HEADER_SIZE);
        }

        let (typ, version, len) = (encrypted.typ, encrypted.version, encrypted.payload.len());
        debug_assert!(len <= usize::from(u16::MAX));
        out[..HEADER_SIZE].copy_from_slice(&encode_record_header(typ, version, len as u16));
        Ok(HEADER_SIZE + len)
    }

    fn encrypted_len(&self, payload_len: usize) -> usize {
        self.encrypter
            .encrypted_payload_len(payload_len)
    }
}

fn send_short(
    message: Message<'_>,
    tls: &mut Vec<u8>,
    encrypting: Option<&mut Encrypting>,
) -> Result<(), Error> {
    // Alerts always fit in a single record, and are never quashed by a `PreEncryptAction`.
    let record = Record::from(message);
    let record = record.borrow_outbound();
    match encrypting {
        Some(encrypting) => {
            encrypting.key_update_remote.write(tls);
            encrypting.encrypt_outgoing(record, tls)
        }
        None => {
            record.encode_unencrypted(tls);
            Ok(())
        }
    }
}

/// State machine for TLS1.3 key updates triggered by us.
///
/// This sits at [`Self::Idle`] for TLS1.2 connections.
enum KeyUpdateLocal {
    /// Nothing is happening.
    Idle,

    /// A key update request should be sent at the next sending opportunity.
    Requested,

    /// A key update request is outstanding; we await a response.
    Outstanding,
}

/// State machine for TLS1.3 key updates triggered by peer.
///
/// This sits at [`Self::Idle`] for TLS1.2 connections.
enum KeyUpdateRemote {
    /// Nothing is happening.
    Idle,

    /// A key update response is awaiting sending.
    Queued(Vec<u8>),
}

impl KeyUpdateRemote {
    fn write(&mut self, tls: &mut Vec<u8>) {
        let Self::Queued(message) = self else {
            return;
        };
        tls.append(message);
        *self = Self::Idle;
    }
}

pub(crate) trait SendOutput {
    fn negotiated_version(&mut self, version: ProtocolVersion);

    fn queue_requested_key_update(&mut self) -> Result<(), Error>;

    fn note_key_update_response(&mut self);

    fn set_encrypter(&mut self, encrypter: Encrypter);

    fn update_key_schedule(&mut self, schedule: Box<KeyScheduleTrafficSend>);

    fn send_alert(
        &mut self,
        level: AlertLevel,
        desc: AlertDescription,
        tls: &mut Vec<u8>,
    ) -> Result<(), Error>;

    fn start_traffic(&mut self);

    fn send_msg(
        &mut self,
        m: Message<'_>,
        must_encrypt: bool,
        tls: &mut Vec<u8>,
    ) -> Result<(), Error>;
}

pub(crate) struct Encrypter {
    pub(crate) encrypter: Box<dyn RecordEncrypter>,
    pub(crate) limit: u64,
}

#[cfg(test)]
mod tests {
    use core::iter;

    use super::*;
    use crate::crypto::test_provider::Tls13Cipher;

    #[test]
    fn encrypt_records_checks_limits_for_all_records() {
        let encrypt = |write_seq_max, write_seq, records| {
            let mut encrypting = Encrypting {
                encrypter: Box::new(Tls13Cipher),
                write_seq_max,
                write_seq,
                key_update_local: KeyUpdateLocal::Idle,
                key_update_remote: KeyUpdateRemote::Idle,
                tls13_key_schedule: None,
            };

            let record = Record::new(
                ContentType::ApplicationData,
                EncodableVersion::Legacy(ProtocolVersion::TLSv1_2),
                OutboundPlain::new_empty(),
            );
            let close = encrypting.encrypt_records(
                iter::repeat_n(record, records),
                &mut Vec::new(),
                Some(ProtocolVersion::TLSv1_2),
            )?;
            Ok::<_, Error>((close, encrypting.write_seq))
        };

        assert_eq!(encrypt(10, 8, 0), Ok((false, 8)));
        assert_eq!(encrypt(10, 8, 2), Ok((false, 10)));
        assert_eq!(encrypt(10, 8, 3), Ok((true, 8)));
        assert_eq!(encrypt(10, 11, 1), Ok((true, 11)));
        assert_eq!(
            encrypt(SEQ_SOFT_LIMIT, SEQ_HARD_LIMIT - 1, 1),
            Ok((true, SEQ_HARD_LIMIT - 1))
        );
        assert_eq!(
            encrypt(SEQ_SOFT_LIMIT, SEQ_HARD_LIMIT - 1, 2),
            Err(Error::EncryptError)
        );
    }
}
