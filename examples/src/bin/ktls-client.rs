//! This is an example showing how to use rustls' external connection API in
//! order to implement kTLS.
//!
//! In order to run this example you will need linux kernel version 5.1 or
//! newer and the kernel will need to have the ktls kernel module enabled
//! (either compiled in or as a module).
//!
//! There are two main parts to this example:
//! - `connect` uses the unbuffered API to set up a regular TLS connection
//!   and then configures kTLS encryption and decryption on the socket.
//! - `handle_control_message` reads a control message from the socket
//!   (a control message is anything other than application data) and handles it
//!   appropriately.
//!
//! Finally, `main` puts them together to make a HTTP request to example.com.
//!
//! This example is somewhat simplified from what you would actually want to do
//! for a full-fledged use of kTLS:
//! - It only allows TLS 1.3 with the AES-GCM-256 cipher.
//! - It does not check that we don't exceed the confidentiality limit for the
//!   cipher being used.
//! - It only does the bare minimum of control message handling.
//!
//! You can find the user-facing documentation for kTLS on linux at
//! <https://docs.kernel.org/networking/tls.html#kernel-tls>.

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(not(target_os = "linux"))]
    panic!("the ktls-client example is only supported on linux");

    #[cfg(target_os = "linux")]
    crate::linux::main()
}

// We're using linux's kTLS implementation here so this example will only work
// there.
#[cfg(target_os = "linux")]
mod linux {
    use std::error::Error;
    use std::ffi::{c_ulong, c_void};
    use std::io::{self, Read, Write};
    use std::net::{Shutdown, TcpStream};
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::Arc;

    use ktls_sys::bindings as sys;
    use rustls::client::UnbufferedClientConnection;
    use rustls::crypto::{CryptoProvider, aws_lc_rs};
    use rustls::external::ExternalConnection;
    use rustls::pki_types::ServerName;
    use rustls::unbuffered::{ConnectionState, EncodeError, UnbufferedStatus};
    use rustls::version::TLS13;
    use rustls::{
        AlertDescription, ClientConfig, ConnectionTrafficSecrets, ContentType, HandshakeType,
        ProtocolVersion, RootCertStore,
    };

    pub(crate) fn main() -> Result<(), Box<dyn Error>> {
        let root_store = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };

        // kTLS only supports a few cipher suites. We restrict ourselves more
        // than necessary here in order to simplify later steps.
        let provider = Arc::new(CryptoProvider {
            cipher_suites: vec![aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384],
            ..aws_lc_rs::default_provider()
        });

        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13])?
            .with_root_certificates(root_store)
            .with_no_client_auth();
        // We need to enable secret extraction otherwise attempting to create
        // the ExternalClient will result in an error.
        config.enable_secret_extraction = true;

        let config = Arc::new(config);
        let mut sock = TcpStream::connect("example.com:443")?;
        let mut conn = connect(config, "example.com".try_into().unwrap(), &mut sock)?;

        #[rustfmt::skip]
        let request = "\
            GET / HTTP/1.1\r\n\
            Host: example.com\r\n\
            Connection: close\r\n\
            Accept-Encoding: identity\r\n\
            \r\n\
        ";
        sock.write_all(request.as_bytes())?;

        let mut data = Vec::new();
        let mut workbuf = Vec::with_capacity(1024);

        loop {
            match sock.read_to_end(&mut data) {
                Ok(_) => break,
                // This part is somewhat tricky to figure out on your own.
                //
                // If you read the kTLS user documentation closely then you will see
                // a part that mentions that says (roughly) "if no cmsg buffer is
                // provided," then "an error is returned if a control message is
                // received." You may also note that the documentation doesn't actually
                // indicate _which_ error you'll receive in that case.
                //
                // EIO is that error. If you get EIO out of a read from a kTLS socket
                // then that means you need to handle some buffered control messages.
                Err(e) if e.raw_os_error() == Some(libc::EIO) => (),

                // Note that it is also possible to get EKEYEXPIRED if you receive a
                // key update message and have not yet updated the RX connection secrets.
                // You should never really run into this error if you're doing things
                // correctly with kTLS.
                Err(e) => return Err(e.into()),
            }

            handle_control_message(&mut sock, &mut conn, &mut workbuf)?;
        }

        send_close_notify(&mut sock)?;

        std::io::stdout().write_all(&data)?;
        Ok(())
    }

    /// Establish a TLS connection on `sock` then configure kTLS.
    fn connect(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        sock: &mut TcpStream,
    ) -> Result<ExternalConnection, Box<dyn Error>> {
        let mut conn = UnbufferedClientConnection::new(config, name)?;

        let mut incoming = vec![0u8; 8192];
        let mut outgoing = vec![0u8; 1024];

        let mut incoming_used = 0usize;
        let mut outgoing_used = 0usize;

        // Setting up the TLS ULP fails if either end of the socket is closed.
        // It is possible for this to happen if the other end of the connection
        // quickly writes their data and closes their end of the connection
        // (e.g. on localhost).
        //
        // By setting up the ULP before we do the handshake we can ensure that
        // any errors due to a connection hangup will also have meant that the
        // connection would have failed. We also avoid the case where we have a
        // socket buffer full of encrypted data but we've failed to enable the
        // TLS protocol an so have to decrypt it ourselves.
        match setup_tls_ulp(sock.as_raw_fd()) {
            Ok(_) => (),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                // ENOENT is confusing on its own so this gives a better error message
                return Err("kTLS is not supported by the current kernel".into());
            }
            Err(e) => return Err(e.into()),
        };

        loop {
            let UnbufferedStatus { discard, state } =
                conn.process_tls_records(&mut incoming[..incoming_used]);
            let state = state?;

            match state {
                ConnectionState::BlockedHandshake => {
                    // Read exactly one TLS record.
                    //
                    // We need to ensure that there's no data left over in incoming
                    // once we complete the handshake. We do this by reading messages
                    // one at a time. This makes the handshake somewhat more expensive
                    // than it could be, but it also ensures that there's no decrypted
                    // data that needs to be handled before using the kTLS socket.
                    let count = read_tls_record(sock, &mut incoming[incoming_used..])?;
                    incoming_used += count;
                }
                ConnectionState::PeerClosed | ConnectionState::Closed => {
                    return Err("peer closed the connection before the handshake completed".into());
                }
                ConnectionState::ReadEarlyData(_) => (),
                ConnectionState::EncodeTlsData(mut data) => {
                    match data.encode(&mut outgoing[outgoing_used..]) {
                        Ok(count) => outgoing_used += count,
                        Err(EncodeError::AlreadyEncoded) => unreachable!(),
                        Err(EncodeError::InsufficientSize(e)) => {
                            outgoing.resize(outgoing_used + e.required_size, 0u8);

                            match data.encode(&mut outgoing[outgoing_used..]) {
                                Ok(count) => outgoing_used += count,
                                Err(e) => unreachable!("encode failed after resizing buffer: {e}"),
                            }
                        }
                    }
                }
                ConnectionState::TransmitTlsData(data) => {
                    sock.write_all(&outgoing[..outgoing_used])?;
                    outgoing_used = 0;
                    data.done();
                }
                ConnectionState::WriteTraffic(_) => {
                    break;
                }
                ConnectionState::ReadTraffic(_) => {
                    unreachable!(
                        "ReadTraffic should not be encountered during the handshake process"
                    )
                }
                _ => unreachable!("unexpected connection state"),
            }

            if discard == incoming_used {
                incoming_used = 0;
            } else {
                incoming.copy_within(discard..incoming_used, 0);
                incoming_used -= discard;
            }
        }

        let (secrets, external) = conn.dangerous_into_external_connection()?;
        setup_tls_info(sock.as_raw_fd(), Direction::Tx, secrets.tx)?;
        setup_tls_info(sock.as_raw_fd(), Direction::Rx, secrets.rx)?;

        Ok(external)
    }

    /// This is the complicated bit of implementing kTLS.
    ///
    /// Application data is handled via regular reads and writes to the kTLS
    /// socket, but when a different message is received normal read calls will
    /// start returning EIO and you need to make a recvmsg call with a control
    /// message pointer in order to read the message contents.
    fn handle_control_message(
        sock: &mut TcpStream,
        conn: &mut ExternalConnection,
        data: &mut Vec<u8>,
    ) -> Result<(), Box<dyn Error>> {
        // The kernel returns the TLS record content type using a control
        let mut cmsg = CMsg::<1>::zeroed();
        data.clear();

        // In order to get non-application data messages you need to pass a
        // control message pointer to recvmsg.
        //
        // The kernel will then fill the cmsg buffer with the content type of
        // the received record.
        recvmsg_whole(sock.as_raw_fd(), data, Some(&mut cmsg), libc::MSG_DONTWAIT)?;
        if cmsg.level() != libc::SOL_TLS || cmsg.typ() != libc::TLS_GET_RECORD_TYPE {
            panic!(
                "recvmsg returned an unexpected control message (level = {}, type = {})",
                cmsg.level(),
                cmsg.typ()
            );
        }

        match ContentType::from(cmsg.data()[0]) {
            // We should be handling application data at the top level, and not
            // as a control message.
            //
            // It doesn't hurt you to do so, but it's generally easier to just
            // call read on the TcpStream instead of going through recvmsg.
            ContentType::ApplicationData => unreachable!(
                "this should never occur if we only call handle_control_message after getting EIO"
            ),

            // Alerts are easier since we skip a bit of the complexity here.
            // It's either a `CloseNotify` and we gracefully shut down, or it's
            // an alert and we abort with an error.
            ContentType::Alert => {
                let (level, desc) = match &data[..] {
                    &[level, desc] => (level, AlertDescription::from(desc)),
                    _ => {
                        send_fatal_alert(sock, AlertDescription::DecodeError)?;
                        return Err("peer sent an invalid TLS alert".into());
                    }
                };

                match desc {
                    // The peer has closed their end of the connection.
                    AlertDescription::CloseNotify => {
                        sock.shutdown(Shutdown::Read)?;
                    }

                    // TLS 1.2 doesn't require that the connection be terminated
                    // upon receiving a warning alert.
                    _ if level == ALERT_LEVEL_WARNING
                        && conn.protocol_version() == ProtocolVersion::TLSv1_2 => {}

                    // We just terminate the connection on receiving any other alert.
                    _ => {
                        return Err(format!(
                            "peer terminated the connection with an alert: {desc:?}"
                        )
                        .into());
                    }
                }
            }

            // Handshake messages are more complicated.
            //
            // The handshake message actually contains multiple smaller messages
            // within it. Parsing these isn't hard, but we do need to iterate
            // through them. Most of the handshake messages are only supposed to
            // occur during the handshake process but TLS 1.3 allows a few to
            // occur once the connection is established. These are:
            // - key updates, and,
            // - new session tickets
            //
            // We need to use the methods on ExternalConnection to handle both.
            ContentType::Handshake => {
                let mut first = true;
                let mut data = data.as_mut_slice();
                while !data.is_empty() {
                    let (ty, len, rest) = match data {
                        &mut [ty, a, b, c, ref mut rest @ ..] => (
                            HandshakeType::from(ty),
                            u32::from_be_bytes([0, a, b, c]) as usize,
                            rest,
                        ),
                        _ => {
                            send_fatal_alert(sock, AlertDescription::DecodeError)?;
                            return Err("peer sent an invalid TLS handshake message".into());
                        }
                    };

                    if rest.len() < len {
                        send_fatal_alert(sock, AlertDescription::DecodeError)?;
                        return Err("peer sent an invalid TLS handshake message".into());
                    }
                    let (msg, rest) = rest.split_at_mut(len);
                    data = rest;

                    match ty {
                        HandshakeType::KeyUpdate
                            if conn.protocol_version() == ProtocolVersion::TLSv1_3 =>
                        {
                            if msg.len() != 1 {
                                send_fatal_alert(sock, AlertDescription::DecodeError)?;
                                return Err("peer sent an invalid KeyUpdate message".into());
                            }

                            if !first || !data.is_empty() {
                                // KeyUpdates cannot be combined with any other handshake message
                                send_fatal_alert(sock, AlertDescription::UnexpectedMessage)?;
                                return Err("peer sent a key update in the same message as other handshake messages".into());
                            }

                            let rx = conn.update_rx_secret()?;
                            // The TLS sequence number always starts at 0.
                            setup_tls_info(sock.as_raw_fd(), Direction::Rx, rx)?;

                            match msg[0] {
                                KEY_UPDATE_NOT_REQUESTED => (),
                                KEY_UPDATE_REQUESTED => {
                                    let tx = conn.update_tx_secret()?;

                                    // This isn't an issue here, but if you are using the write end of the
                                    // socket independently of the read end then you need to make sure that
                                    // no writes happen between sending the key update message and updating
                                    // the TX secrets. The kernel will not help you here and will happily
                                    // encrypt data using the wrong encryption keys.
                                    #[rustfmt::skip]
                                    send_control_msg(
                                        sock,
                                        ContentType::Handshake,
                                        &[
                                            KEY_UPDATE, // key update message type
                                            0, 0, 1, // length 1
                                            KEY_UPDATE_NOT_REQUESTED,
                                        ],
                                    )?;

                                    setup_tls_info(sock.as_raw_fd(), Direction::Tx, tx)?;
                                }
                                _ => {
                                    send_fatal_alert(sock, AlertDescription::DecodeError)?;
                                    return Err("peer sent an invalid KeyUpdate message".into());
                                }
                            }
                        }

                        HandshakeType::NewSessionTicket
                            if conn.protocol_version() == ProtocolVersion::TLSv1_3 =>
                        {
                            conn.handle_new_session_ticket(msg)?;
                        }

                        _ => {
                            send_fatal_alert(sock, AlertDescription::UnexpectedMessage)?;
                            return Err(format!(
                                "peer sent an unexpected handshake message: {ty:?}"
                            )
                            .into());
                        }
                    }

                    first = false;
                }
            }

            typ => {
                send_fatal_alert(sock, AlertDescription::UnexpectedMessage)?;
                return Err(format!("peer sent an unexpected message: {typ:?}").into());
            }
        }

        Ok(())
    }

    fn send_fatal_alert(sock: &mut TcpStream, desc: AlertDescription) -> io::Result<()> {
        let message = [ALERT_LEVEL_FATAL, desc.into()];
        send_control_msg(sock, ContentType::Alert, &message)
    }

    fn send_close_notify(sock: &mut TcpStream) -> io::Result<()> {
        let message = [ALERT_LEVEL_WARNING, AlertDescription::CloseNotify.into()];
        send_control_msg(sock, ContentType::Alert, &message)
    }

    fn send_control_msg(sock: &mut TcpStream, typ: ContentType, data: &[u8]) -> io::Result<()> {
        let cmsg = CMsg::new(libc::SOL_TLS, libc::TLS_SET_RECORD_TYPE, [typ.into()]);
        sendmsg(sock.as_raw_fd(), &[io::IoSlice::new(data)], Some(&cmsg), 0).map(drop)
    }

    /// Read a single TLS record from stream to buf.
    fn read_tls_record(stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<usize> {
        let (header, rest) = buf.split_at_mut(5);
        stream.read_exact(header)?;

        let header = TlsHeader::decode(header.try_into().unwrap());

        let len = header.len as usize;
        stream.read_exact(&mut rest[..len])?;

        Ok(len + 5)
    }

    #[allow(dead_code)]
    struct TlsHeader {
        ty: rustls::ContentType,
        version: rustls::ProtocolVersion,
        len: u16,
    }

    impl TlsHeader {
        pub fn decode(bytes: [u8; 5]) -> Self {
            let ty = rustls::ContentType::from(bytes[0]);
            let version = rustls::ProtocolVersion::from(u16::from_be_bytes([bytes[1], bytes[2]]));
            let len = u16::from_be_bytes([bytes[3], bytes[4]]);

            Self { ty, version, len }
        }
    }

    /// Enable the TLS upper-level protocol on the socket.
    fn setup_tls_ulp(fd: RawFd) -> io::Result<()> {
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_TCP,
                libc::TCP_ULP,
                "tls".as_ptr() as _,
                "tls".len() as _,
            )
        };

        match ret {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }

    fn setup_tls_info(
        fd: RawFd,
        dir: Direction,
        (seq, secrets): (u64, ConnectionTrafficSecrets),
    ) -> io::Result<()> {
        let crypto = CryptoInfo::from_rustls((seq, secrets));
        let dir = match dir {
            Direction::Tx => libc::TLS_TX,
            Direction::Rx => libc::TLS_RX,
        };

        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_TLS,
                dir,
                &crypto.0 as *const _ as *const c_void,
                std::mem::size_of_val(&crypto.0) as _,
            )
        };

        match ret {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }

    #[repr(i32)]
    enum Direction {
        Tx = libc::TLS_TX as _,
        Rx = libc::TLS_RX as _,
    }

    struct CryptoInfo(sys::tls12_crypto_info_aes_gcm_256);

    impl CryptoInfo {
        fn from_rustls((seq, secrets): (u64, ConnectionTrafficSecrets)) -> Self {
            let (key, iv) = match secrets {
                ConnectionTrafficSecrets::Aes256Gcm { key, iv } => (key, iv),
                _ => unimplemented!(
                    "ciphers other than AES-256-GCM are not supported by this example"
                ),
            };

            let key = key.as_ref();
            let iv = iv.as_ref();

            let info = sys::tls12_crypto_info_aes_gcm_256 {
                info: sys::tls_crypto_info {
                    // We restricted ourselves to only TLS 1.3 so we can assume it here.
                    // In a full implementation you'd need to check the negotiated
                    // protocol version or the cipher suite to figure this out.
                    version: libc::TLS_1_3_VERSION,
                    cipher_type: sys::TLS_CIPHER_AES_GCM_256 as _,
                },
                key: key
                    .try_into()
                    .expect("AES-GCM-256 key is 32 bytes"),
                iv: iv
                    .get(4..)
                    .and_then(|iv| iv.try_into().ok())
                    .expect("AES-GCM-256 iv is 8 bytes"),
                salt: iv
                    .get(..4)
                    .and_then(|iv| iv.try_into().ok())
                    .expect("AES-GCM-256 salt is 4 bytes"),
                rec_seq: seq.to_be_bytes(),
            };

            Self(info)
        }
    }

    /// Use [`libc::recvmsg`] to receive a whole message (with optional control
    /// message).
    ///
    /// This will repeatedly call `recvmsg` until it reaches the end of the current
    /// record.
    pub(crate) fn recvmsg_whole<const N: usize>(
        fd: RawFd,
        data: &mut Vec<u8>,
        mut cmsg: Option<&mut CMsg<N>>,
        flags: i32,
    ) -> io::Result<i32> {
        if data.capacity() < 16 {
            data.reserve(16);
        }

        loop {
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            if let Some(cmsg) = cmsg.as_deref_mut() {
                msg.msg_control = cmsg as *mut _ as *mut c_void;
                msg.msg_controllen = std::mem::size_of_val(cmsg);
            }

            if data.spare_capacity_mut().is_empty() {
                data.reserve(128);
            }

            let spare = data.spare_capacity_mut();
            let mut iov = libc::iovec {
                iov_base: spare.as_mut_ptr() as *mut c_void,
                iov_len: spare.len(),
            };

            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;

            // SAFETY: We have made sure to initialize msg with valid pointers (or NULL).
            let ret = unsafe { libc::recvmsg(fd, &mut msg, flags) };
            let count = match ret {
                -1 => return Err(io::Error::last_os_error()),
                len => len as usize,
            };

            // SAFETY: recvmsg has just written count to the bytes in the spare capacity of
            //         the vector.
            unsafe { data.set_len(data.len() + count) };

            if msg.msg_flags & libc::MSG_EOR != 0 {
                break Ok(msg.msg_flags);
            }
        }
    }

    /// A wrapper around [`libc::sendmsg`].
    pub(crate) fn sendmsg<const N: usize>(
        fd: RawFd,
        data: &[io::IoSlice<'_>],
        cmsg: Option<&CMsg<N>>,
        flags: i32,
    ) -> io::Result<usize> {
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };

        if let Some(cmsg) = cmsg {
            msg.msg_control = cmsg as *const _ as *mut c_void;
            msg.msg_controllen = std::mem::size_of_val(cmsg);
        }

        msg.msg_iov = data.as_ptr() as *const _ as *mut libc::iovec;
        msg.msg_iovlen = data.len();

        let ret = unsafe { libc::sendmsg(fd, &msg, flags) };
        match ret {
            -1 => Err(io::Error::last_os_error()),
            len => Ok(len as usize),
        }
    }

    pub(crate) struct CMsg<const N: usize> {
        header: libc::cmsghdr,
        data: [u8; N],

        // This just ensures that CMsg is appropriately aligned.
        _align: [c_ulong; 0],
    }

    impl<const N: usize> CMsg<N> {
        pub const fn new(level: i32, typ: i32, data: [u8; N]) -> Self {
            Self {
                header: libc::cmsghdr {
                    cmsg_len: unsafe { libc::CMSG_LEN(data.len() as _) as _ },
                    cmsg_level: level,
                    cmsg_type: typ,
                },
                data,
                _align: [],
            }
        }

        pub const fn zeroed() -> Self {
            Self::new(0, 0, [0; N])
        }

        pub fn level(&self) -> i32 {
            self.header.cmsg_level
        }

        pub fn typ(&self) -> i32 {
            self.header.cmsg_type
        }

        pub fn data(&self) -> &[u8] {
            &self.data[..self.header.cmsg_len.min(N)]
        }
    }

    const ALERT_LEVEL_WARNING: u8 = 1;
    const ALERT_LEVEL_FATAL: u8 = 2;

    const KEY_UPDATE: u8 = 24;
    const KEY_UPDATE_NOT_REQUESTED: u8 = 0;
    const KEY_UPDATE_REQUESTED: u8 = 2;
}
