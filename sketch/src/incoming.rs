use core::num::NonZeroUsize;

#[cfg(test)]
use crate::mock::{ClientState, ServerState};
use crate::Result;

// a user-facing version of `MessageDeframer.{buf,used}`
pub struct IncomingTls<B> {
    // NOTE this could be an enum to support `io::BorrowedBuf` when `cfg(feature = "std")`
    pub(super) buf: B,
    filled: usize,
    // keeps track of how many bytes have already been discarded from the first app-data record
    // - `None` indicates that the record in the front has not been decrypted in place
    // - `Some` indicates that the record in the front has been decrypted in place; the inner
    //   value indicates how many bytes have already been discarded
    partially_discarded: Option<usize>,
}

impl<B> IncomingTls<B>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Creates a new `IncomingTls` buffer
    pub fn new(buf: B) -> Self {
        Self {
            buf,
            filled: 0,
            partially_discarded: None,
        }
    }

    pub fn borrow(&mut self) -> IncomingTls<&mut [u8]> {
        IncomingTls {
            buf: self.buf.as_mut(),
            filled: self.filled,
            partially_discarded: self.partially_discarded,
        }
    }

    /// Returns an immutable view into the front of the buffer that already been filled with
    /// TLS data
    pub fn filled(&self) -> &[u8] {
        &self.buf.as_ref()[..self.filled]
    }

    /// Returns a mutable view into the back of the buffer that has not yet been filled with
    /// TLS data
    pub fn unfilled(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[self.filled..]
    }

    pub fn clear(&mut self) {
        self.filled = 0;
    }

    pub fn capacity(&self) -> usize {
        self.buf.as_ref().len()
    }

    /// Advances an internal cursor that tracks how full the buffer is
    pub fn advance(&mut self, num_bytes: usize) {
        let capacity = self.capacity();
        // XXX or `_num_records.min(self.decrypted_records)` could be used
        assert!(self.filled + num_bytes <= capacity, "programming error");
        self.filled += num_bytes;
    }

    // same as MessageDeframer.discard
    pub(super) fn discard_handshake_data(&mut self, new_end: usize) {
        if new_end == 0 {
            return;
        }

        self.discard(new_end);

        #[cfg(test)]
        eprintln!(
            "discarded {new_end}B of handshake records; new IncomingTls buffer size: {}B",
            self.filled
        );
    }

    // shared routine
    fn discard(&mut self, new_end: usize) {
        let taken = new_end;
        assert!(self.filled >= taken, "BUG");

        if taken > self.filled || taken == 0 {
            return;
        }

        self.buf.as_mut().copy_within(taken..self.filled, 0);
        self.filled -= taken;
    }

    /// `num_bytes` refers to number of bytes of decrypted payload.
    pub fn discard_app_data(&mut self, _num_bytes: usize) {
        // this discards sufficient entire records to reach `num_bytes` of app data
        //
        // `num_bytes` refers to number of bytes of decrypted payload. this method has to map that
        // value into the number of bytes at the wire level (add encryption size overhead,
        // add TLS header size, etc.)
        //
        // it also supports partially discarding the contents of an app-data record. in that
        // scenario, it keeps track of how much data from the front has been discarded in the
        // `partially_discarded` field
        //
        // this also discards all Alert records that _precede_ the app-data records that will be
        // discarded. if any of those Alert records is fatal, that should have already been raised
        // by the `IncomingAppData` iterator
        #[cfg(test)]
        match (ClientState.current(), ServerState.current()) {
            (0, 6) => {
                self.discard(103);
            }

            (11, 0) => {
                // alert record that follows the app-data record is not discarded in this call
                self.discard(95);
            }

            (i, j) => {
                panic!("unknown ClientState / ServerState: {i} / {j}")
            }
        }

        #[cfg(test)]
        eprintln!(
            "\ndiscarded {_num_bytes}B of app-data. new IncomingTls buffer size: {}B",
            self.filled
        );
    }

    // NOTE instead of this `wrap` + `into_inner` approach, the `buf` field could be made public but
    // that opens the possibility of corrupting the incoming TLS data with a `buf.shrink` operation.
    /// Retrieves the underlying `buffer`
    ///
    /// To avoid discarding TLS data this should only be called when `filled().is_empty()` is `true`
    pub fn into_inner(self) -> B {
        self.buf
    }
}

/// lazy in-place decryption of app-data records
pub struct IncomingAppData<'a, B> {
    pub(super) _incoming_tls: &'a mut IncomingTls<B>,
    #[cfg(test)]
    pub(super) is_client: bool,
}

impl<'a, B> Iterator for IncomingAppData<'a, B>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
{
    // incoming `Alert` messages may become `Error`s
    type Item = Result<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        #[cfg(test)]
        if self.is_client {
            match ClientState.advance() {
                9 => {
                    // TODO return a slice of `self._incoming_tls.buf`
                    const SIZE: usize = 73;
                    eprintln!(
                        "\ndecrypted in place a {}B app-data record with {SIZE}B of payload",
                        SIZE + crate::ENCRYPTED_TLS_SIZE_OVERHEAD
                    );
                    return Some(Ok(&[0; SIZE]));
                }

                10 => {
                    eprintln!("\nfound a non-fatal alert message (24B)");
                    // not critical; do not raise an error
                    // this is the end of the incoming TLS data
                    return None;
                }

                i => {
                    unreachable!("unexpected ClientState: {i}")
                }
            }
        } else {
            match ServerState.advance() {
                4 => {
                    // TODO return a slice of `self._incoming_tls.buf`
                    const SIZE: usize = 81;
                    eprintln!(
                        "\ndecrypted in place a {}B app-data record with {SIZE}B of payload",
                        SIZE + crate::ENCRYPTED_TLS_SIZE_OVERHEAD
                    );
                    return Some(Ok(&[0; SIZE]));
                }

                5 => return None,

                i => {
                    unreachable!("unexpected ServerState: {i}")
                }
            }
        }

        None
    }
}
