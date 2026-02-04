use std::io;

mod key_log_file;
pub use key_log_file::KeyLogFile;
use rustls::{ConnectionCommon, SideData};

mod stream;
pub use crate::stream::{Stream, StreamOwned};

/// This function uses `io` to complete any outstanding IO for
/// the connection.
///
/// This is a convenience function which solely uses other parts
/// of the public API.
///
/// What this means depends on the connection  state:
///
/// - If the connection [`is_handshaking()`], then IO is performed until
///   the handshake is complete.
/// - Otherwise, if [`wants_write()`] is true, [`write_tls()`] is invoked
///   until it is all written.
/// - Otherwise, if [`wants_read()`] is true, [`read_tls()`] is invoked
///   once.
///
/// The return value is the number of bytes read from and written
/// to `io`, respectively. Once both `read()` and `write()` yield `WouldBlock`,
/// this function will propagate the error.
///
/// Errors from TLS record handling (i.e., from [`process_new_packets()`])
/// are wrapped in an `io::ErrorKind::InvalidData`-kind error.
///
/// [`is_handshaking()`]: rustls::CommonState::is_handshaking
/// [`wants_read()`]: rustls::CommonState::wants_read
/// [`wants_write()`]: rustls::CommonState::wants_write
/// [`write_tls()`]: rustls::ConnectionCommon::write_tls
/// [`read_tls()`]: rustls::ConnectionCommon::read_tls
/// [`process_new_packets()`]: rustls::ConnectionCommon::process_new_packets
pub fn complete_io<S: SideData>(
    io: &mut (impl io::Read + io::Write),
    conn: &mut ConnectionCommon<S>,
) -> Result<(usize, usize), io::Error> {
    let mut eof = false;
    let mut wrlen = 0;
    let mut rdlen = 0;
    loop {
        let (mut blocked_write, mut blocked_read) = (None, None);
        let until_handshaked = conn.is_handshaking();

        if !conn.wants_write() && !conn.wants_read() {
            // We will make no further progress.
            return Ok((rdlen, wrlen));
        }

        while conn.wants_write() {
            match conn.write_tls(io) {
                Ok(0) => {
                    io.flush()?;
                    return Ok((rdlen, wrlen)); // EOF.
                }
                Ok(n) => wrlen += n,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    blocked_write = Some(err);
                    break;
                }
                Err(err) => return Err(err),
            }
        }
        if wrlen > 0 {
            io.flush()?;
        }

        if !until_handshaked && wrlen > 0 {
            return Ok((rdlen, wrlen));
        }

        // If we want to write, but are WouldBlocked by the underlying IO, *and*
        // have no desire to read; that is everything.
        if let (Some(_), false) = (&blocked_write, conn.wants_read()) {
            return match wrlen {
                0 => Err(blocked_write.unwrap()),
                _ => Ok((rdlen, wrlen)),
            };
        }

        while !eof && conn.wants_read() {
            let read_size = match conn.read_tls(io) {
                Ok(0) => {
                    eof = true;
                    Some(0)
                }
                Ok(n) => {
                    rdlen += n;
                    Some(n)
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    blocked_read = Some(err);
                    break;
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => None, // nothing to do
                Err(err) => return Err(err),
            };
            if read_size.is_some() {
                break;
            }
        }

        if let Err(e) = conn.process_new_packets() {
            // In case we have an alert to send describing this error, try a last-gasp
            // write -- but don't predate the primary error.
            let _ignored = conn.write_tls(io);
            let _ignored = io.flush();
            return Err(io::Error::new(io::ErrorKind::InvalidData, e));
        };

        // If we want to read, but are WouldBlocked by the underlying IO, *and*
        // have no desire to write; that is everything.
        if let (Some(_), false) = (&blocked_read, conn.wants_write()) {
            return match rdlen {
                0 => Err(blocked_read.unwrap()),
                _ => Ok((rdlen, wrlen)),
            };
        }

        // if we're doing IO until handshaked, and we believe we've finished handshaking,
        // but process_new_packets() has queued TLS data to send, loop around again to write
        // the queued messages.
        if until_handshaked && !conn.is_handshaking() && conn.wants_write() {
            continue;
        }

        let blocked = blocked_write.zip(blocked_read);
        match (eof, until_handshaked, conn.is_handshaking(), blocked) {
            (_, true, false, _) => return Ok((rdlen, wrlen)),
            (_, _, _, Some((e, _))) if rdlen == 0 && wrlen == 0 => return Err(e),
            (_, false, _, _) => return Ok((rdlen, wrlen)),
            (true, true, true, _) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            _ => {}
        }
    }
}
