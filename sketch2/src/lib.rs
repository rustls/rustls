#![cfg_attr(not(test), no_std)]

#[derive(Debug)]
pub enum TlsError {
    Fatal,
    // ..
}

pub type TlsResult<T> = Result<T, TlsError>;

pub struct LlConnectionCommon;

/// Handshake / connection state
pub enum State<'c, 'i> {
    /// An application data record is available
    // NOTE Alert records are implicitly handled by `process_tls_records` and not exposed through
    // this `enum`. Fatal alerts make `process_tls_records` return an `Err`or
    AppDataAvailable(AppDataAvailable<'c, 'i>),

    /// An early data record is available
    EarlyDataAvailable(EarlyDataAvailable<'c, 'i>),

    /// application data may be encrypted at this stage of the handshake
    MayEncryptAppData(MayEncryptAppData<'c>),

    /// early (0-RTT) data may be encrypted
    MayEncryptEarlyData(MayEncryptEarlyData<'c>),

    /// A Handshake record must be encrypted into the `outgoing_tls` buffer
    MustEncryptTlsData(MustEncryptTlsData<'c>),

    /// TLS records related to the handshake have been placed in the `outgoing_tls` buffer and must
    /// be transmitted to continue with the handshake process
    MustTransmitTlsData,

    /// More TLS data needs to be added to the `incoming_tls` buffer to continue with the handshake
    NeedsMoreTlsData,

    /// Handshake is complete.
    TrafficTransit(TrafficTransit<'c>),
    // NOTE omitting certificate verification variants for now
}

/// A single TLS record containing application data
pub struct AppDataAvailable<'c, 'i> {
    _conn: &'c mut LlConnectionCommon,
    _incoming_tls: &'i mut [u8],
}

impl<'c, 'i> AppDataAvailable<'c, 'i> {
    // decrypts the first record in `_incoming_tls` in-place and returns a slice into its payload
    // this advances `incoming_tls`'s cursor *fully* discarding the TLS record
    pub fn decrypt(self) -> TlsResult<&'i [u8]> {
        todo!()
    }
}

/// A single TLS record containing early data
pub struct EarlyDataAvailable<'c, 'i> {
    _conn: &'c mut LlConnectionCommon,
    _incoming_tls: &'i mut [u8],
}

impl<'c, 'i> EarlyDataAvailable<'c, 'i> {
    // decrypts the first record in `_incoming_tls` in-place and returns a slice into its payload
    // this advances `incoming_tls`'s cursor *fully* discarding the TLS record
    pub fn decrypt(self) -> TlsResult<&'i [u8]> {
        todo!()
    }

    // XXX consider adding a `discard` method to drop the entire early-data record (and advance
    // incoming_tls's cursor) without decrypting the record
}

/// provided `outgoing_tls` buffer is too small
#[derive(Debug)]
pub struct EncryptError {
    /// buffer must be at least this size
    pub required_size: usize,
}

pub struct MayEncryptAppData<'c> {
    _conn: &'c mut LlConnectionCommon,
}

impl<'c> MayEncryptAppData<'c> {
    /// Encrypts `outgoing_plaintext` into the `outgoing_tls` buffer
    ///
    /// returns the part of `outgoing_tls` that was not used, or an error if the provided buffer was
    /// too small
    // XXX can more than one application data record be sent during the same handshake round-trip?
    // if not, then this can take `self` by value
    pub fn encrypt(
        &mut self,
        _outgoing_plaintext: &[u8],
        _outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        todo!()
    }

    /// Continue with the handshake process
    pub fn done(self) {}
}

pub struct MayEncryptEarlyData<'c> {
    _conn: &'c mut LlConnectionCommon,
}

impl<'c> MayEncryptEarlyData<'c> {
    /// Encrypts `early_data` into the `outgoing_tls` buffer
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    pub fn encrypt(
        &mut self,
        _early_data: &[u8],
        _outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        todo!()
    }

    /// Continue with the handshake process
    pub fn done(self) {}
}

pub struct MustEncryptTlsData<'c> {
    _conn: &'c mut LlConnectionCommon,
}

impl<'c> MustEncryptTlsData<'c> {
    /// Encrypts a handshake record into the `outgoing_tls` buffer
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    // calling this again does nothing
    pub fn encrypt(&mut self, _outgoing_tls: &mut [u8]) -> Result<usize, EncryptError> {
        todo!()
    }

    // no `done` method because successfully encrypting advances the state machine
}

/// Handshake complete
pub struct TrafficTransit<'c> {
    _conn: &'c mut LlConnectionCommon,
}

impl<'c> TrafficTransit<'c> {
    /// Encrypts `outgoing_plaintext` into the `outgoing_tls` buffer
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    pub fn encrypt<'o>(
        &mut self,
        _outgoing_plaintext: &[u8],
        _outgoing_tls: &'o mut [u8],
    ) -> Result<&'o mut [u8], EncryptError> {
        todo!()
    }
}

impl LlConnectionCommon {
    pub fn process_tls_records<'c, 'i>(
        &'c mut self,
        // NOTE using `&mut [u8]` for simplicity / brevity but this still needs to be `IncomingTls`
        // or an `enum` to support the `read_buf` API (`std::io::BorrowedBuf`)
        _incoming_tls: &'i mut [u8],
    ) -> TlsResult<State<'c, 'i>> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // compile-pass test
    #[test]
    fn borrow_checker_is_happy() -> TlsResult<()> {
        let mut conn = LlConnectionCommon;
        let mut outgoing_tls = vec![0; 1024];
        let incoming_tls = &mut []; // don't care about this for now

        let mut outgoing_used = 0;
        loop {
            let state = conn.process_tls_records(incoming_tls)?;

            match state {
                State::AppDataAvailable(record) => {
                    let _data = record.decrypt()?;
                    // do stuff with `data`
                }

                State::EarlyDataAvailable(record) => {
                    let _early_data = record.decrypt()?;
                    // do stuff with `early_data`
                }

                State::MayEncryptAppData(mut encrypter) => {
                    let app_data = b"Hello, world!";
                    let res = encrypter.encrypt(app_data, &mut outgoing_tls[outgoing_used..]);
                    match res {
                        Ok(written) => {
                            outgoing_used += written;
                        }

                        Err(EncryptError { required_size }) => {
                            // example of on-the-fly buffer resizing
                            let new_len = outgoing_used + required_size;
                            outgoing_tls.resize(new_len, 0);

                            // don't forget to encrypt `app_data` after resizing!
                            encrypter
                                .encrypt(app_data, &mut outgoing_tls[outgoing_used..])
                                .expect("should not fail this time");
                        }
                    }

                    encrypter.done();
                }

                State::MayEncryptEarlyData(encrypter) => {
                    // not sending any early data in this example
                    encrypter.done();
                }

                State::MustEncryptTlsData(mut encrypter) => {
                    let res = encrypter.encrypt(&mut outgoing_tls[..outgoing_used]);

                    match res {
                        Ok(written) => {
                            outgoing_used += written;
                        }

                        Err(_) => {
                            // omitted but this is handled in the same way `MayEncryptAppData` was
                            // handled
                        }
                    }
                }

                State::MustTransmitTlsData => {
                    // send `&outgoing_tls[..outgoing_used]` through socket
                    outgoing_used = 0;

                    // XXX would it be worthwhile to make this variant include an opaque struct
                    // with a `done` method that advances the state machine? if anything it would
                    // make the match arms more "symmetric"
                }

                State::NeedsMoreTlsData => {
                    // read data from socket and place it in `incoming_tls`

                    // XXX same comment as above about opaque struct with `done` method
                }

                State::TrafficTransit(_) => {
                    // post-handshake logic
                }
            }
        }
    }
}
