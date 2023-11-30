use core::pin::Pin;
use core::result::Result as CoreResult;
use core::task::Poll;
use core::{mem, task};
use std::error::Error as StdError;
use std::io;
use std::io::ErrorKind;
use std::sync::Arc;

use futures::io::{AsyncRead, AsyncWrite};
use futures::Future;
use pki_types::ServerName;
use rustls::client::UnbufferedClientConnection;
use rustls::unbuffered::{
    AppDataRecord, ConnectionState, EncodeError, EncryptError, InsufficientSizeError,
    UnbufferedStatus,
};
use rustls::ClientConfig;

// FIXME use an enum
pub type Error = Box<dyn StdError + Send + Sync>;
type Result<T> = CoreResult<T, Error>;

pub struct TcpConnector {
    config: Arc<ClientConfig>,
}

impl TcpConnector {
    pub fn connect<IO>(
        &self,
        domain: ServerName<'static>,
        stream: IO,
        // FIXME should not return an error but instead hoist it into a `Connect` variant
    ) -> Result<Connect<IO>>
    where
        IO: AsyncRead + AsyncWrite,
    {
        let conn = UnbufferedClientConnection::new(self.config.clone(), domain)?;

        Ok(Connect::new(conn, stream))
    }
}

impl From<Arc<ClientConfig>> for TcpConnector {
    fn from(config: Arc<ClientConfig>) -> Self {
        Self { config }
    }
}

pub struct Connect<IO> {
    inner: Option<ConnectInner<IO>>,
}

impl<IO> Connect<IO> {
    fn new(conn: UnbufferedClientConnection, io: IO) -> Self {
        Self {
            inner: Some(ConnectInner::new(conn, io)),
        }
    }
}

struct ConnectInner<IO> {
    conn: UnbufferedClientConnection,
    incoming: Buffer,
    io: IO,
    outgoing: Buffer,
}

impl<IO> ConnectInner<IO> {
    fn new(conn: UnbufferedClientConnection, io: IO) -> Self {
        Self {
            conn,
            incoming: Buffer::default(),
            io,
            outgoing: Buffer::default(),
        }
    }
}

impl<IO> Future for Connect<IO>
where
    IO: Unpin + AsyncRead + AsyncWrite,
{
    type Output = Result<TlsStream<IO>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let mut inner = self
            .inner
            .take()
            .expect("polled after completion");

        let mut updates = Updates::default();
        let poll = loop {
            let action = inner.advance(&mut updates)?;

            match action {
                Action::Continue => continue,

                Action::Write => {
                    let mut outgoing = mem::take(&mut inner.outgoing);
                    let would_block = poll_write(&mut inner.io, &mut outgoing, cx)?;

                    updates.transmit_complete = outgoing.is_empty();
                    inner.outgoing = outgoing;

                    if would_block {
                        break Poll::Pending;
                    }
                }

                Action::Read => {
                    let mut incoming = mem::take(&mut inner.incoming);

                    let would_block = poll_read(&mut inner.io, &mut incoming, cx)?;

                    inner.incoming = incoming;

                    if would_block {
                        break Poll::Pending;
                    }
                }

                Action::Break => {
                    // XXX should we yield earlier when it's already possible to encrypt
                    // application data? that would reduce the number of round-trips
                    let ConnectInner {
                        conn,
                        incoming,
                        io,
                        outgoing,
                    } = inner;

                    return Poll::Ready(Ok(TlsStream {
                        conn,
                        incoming,
                        io,
                        outgoing,
                    }));
                }
            }
        };

        self.inner = Some(inner);

        poll
    }
}

/// returns `true` if the operation would block
fn poll_read<IO>(io: &mut IO, incoming: &mut Buffer, cx: &mut task::Context) -> io::Result<bool>
where
    IO: AsyncRead + Unpin,
{
    if incoming.unfilled().is_empty() {
        // XXX should this be user configurable?
        incoming.reserve(1024);
    }

    let would_block = match Pin::new(io).poll_read(cx, incoming.unfilled()) {
        Poll::Ready(res) => {
            let read = res?;
            log::trace!("read {read}B from socket");
            incoming.advance(read);
            false
        }

        Poll::Pending => true,
    };

    Ok(would_block)
}

/// returns `true` if the operation would block
fn poll_write<IO>(io: &mut IO, outgoing: &mut Buffer, cx: &mut task::Context) -> io::Result<bool>
where
    IO: AsyncWrite + Unpin,
{
    let pending = match Pin::new(io).poll_write(cx, outgoing.filled()) {
        Poll::Ready(res) => {
            let written = res?;
            log::trace!("wrote {written}B into socket");
            outgoing.discard(written);
            log::trace!("{}B remain in the outgoing buffer", outgoing.len());
            false
        }

        Poll::Pending => true,
    };
    Ok(pending)
}

#[derive(Default)]
struct Updates {
    transmit_complete: bool,
}

impl<IO> ConnectInner<IO> {
    fn advance(&mut self, updates: &mut Updates) -> Result<Action> {
        log::trace!("incoming buffer has {}B of data", self.incoming.len());

        let UnbufferedStatus { discard, state } = self
            .conn
            .process_tls_records(self.incoming.filled_mut())?;

        log::trace!("state: {state:?}");
        let next = match state {
            ConnectionState::MustEncodeTlsData(mut state) => {
                try_or_resize_and_retry(
                    |out_buffer| state.encode(out_buffer),
                    |e| {
                        if let EncodeError::InsufficientSize(is) = &e {
                            Ok(*is)
                        } else {
                            Err(e.into())
                        }
                    },
                    &mut self.outgoing,
                )?;

                Action::Continue
            }

            ConnectionState::MustTransmitTlsData(state) => {
                if updates.transmit_complete {
                    updates.transmit_complete = false;
                    state.done();
                    Action::Continue
                } else {
                    Action::Write
                }
            }

            ConnectionState::NeedsMoreTlsData { .. } => Action::Read,

            ConnectionState::TrafficTransit(_) => Action::Break,

            state => unreachable!("{state:?}"), // due to type state
        };

        self.incoming.discard(discard);

        Ok(next)
    }
}

enum Action {
    Break,
    Continue,
    Read,
    Write,
}

pub struct TlsStream<IO> {
    conn: UnbufferedClientConnection,
    incoming: Buffer,
    io: IO,
    outgoing: Buffer,
}

impl<IO> AsyncWrite for TlsStream<IO>
where
    IO: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut outgoing = mem::take(&mut self.outgoing);

        // no IO here; just in-memory writes
        match self
            .conn
            .process_tls_records(&mut [])
            .map_err(map_err)?
            .state
        {
            ConnectionState::TrafficTransit(mut state) => {
                try_or_resize_and_retry(
                    |out_buffer| state.encrypt(buf, out_buffer),
                    |e| {
                        if let EncryptError::InsufficientSize(is) = &e {
                            Ok(*is)
                        } else {
                            Err(e.into())
                        }
                    },
                    &mut outgoing,
                )
                .map_err(map_err)?;
            }

            ConnectionState::ConnectionClosed => {
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::ConnectionAborted,
                    "connection closed by the peer",
                )));
            }

            state => unreachable!("{state:?}"),
        }

        // opportunistically try to write data into the socket
        // XXX should this be a loop?
        while !outgoing.is_empty() {
            let would_block = poll_write(&mut self.io, &mut outgoing, cx)?;
            if would_block {
                break;
            }
        }

        self.outgoing = outgoing;

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        let mut outgoing = mem::take(&mut self.outgoing);

        // write buffered TLS data into socket
        while !outgoing.is_empty() {
            let would_block = poll_write(&mut self.io, &mut outgoing, cx)?;

            if would_block {
                self.outgoing = outgoing;
                return Poll::Pending;
            }
        }

        self.outgoing = outgoing;

        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        // XXX send out close_notify here?
        Pin::new(&mut self.io).poll_close(cx)
    }
}

impl<IO> AsyncRead for TlsStream<IO>
where
    IO: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut incoming = mem::take(&mut self.incoming);
        let mut cursor = WriteCursor::new(buf);

        while !cursor.is_full() {
            log::trace!("incoming buffer has {}B of data", incoming.len());

            let UnbufferedStatus { mut discard, state } = self
                .conn
                .process_tls_records(incoming.filled_mut())
                .map_err(map_err)?;

            match state {
                ConnectionState::AppDataAvailable(mut state) => {
                    while let Some(res) = state.next_record() {
                        let AppDataRecord {
                            discard: new_discard,
                            payload,
                        } = res.map_err(map_err)?;
                        discard += new_discard;

                        let remainder = cursor.append(payload);

                        if !remainder.is_empty() {
                            // stash
                            todo!()
                        }
                    }
                }

                ConnectionState::TrafficTransit(_) => {
                    let would_block = poll_read(&mut self.io, &mut incoming, cx)?;

                    if would_block {
                        self.incoming = incoming;
                        return Poll::Pending;
                    }
                }

                ConnectionState::ConnectionClosed => break,

                state => unreachable!("{state:?}"),
            }

            incoming.discard(discard);
        }

        Poll::Ready(Ok(cursor.into_used()))
    }
}

struct WriteCursor<'a> {
    buf: &'a mut [u8],
    used: usize,
}

impl<'a> WriteCursor<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, used: 0 }
    }

    fn into_used(self) -> usize {
        self.used
    }

    fn append<'b>(&mut self, data: &'b [u8]) -> &'b [u8] {
        let len = self
            .remaining_capacity()
            .min(data.len());

        self.unfilled()[..len].copy_from_slice(&data[..len]);
        self.used += len;

        data.split_at(len).1
    }

    fn unfilled(&mut self) -> &mut [u8] {
        &mut self.buf[self.used..]
    }

    fn is_full(&self) -> bool {
        self.remaining_capacity() == 0
    }

    fn remaining_capacity(&self) -> usize {
        self.buf.len() - self.used
    }
}

fn map_err<E>(err: E) -> io::Error
where
    E: Into<Box<dyn StdError + Send + Sync>>,
{
    io::Error::new(ErrorKind::Other, err)
}

#[derive(Default)]
struct Buffer {
    inner: Vec<u8>,
    used: usize,
}

impl Buffer {
    fn advance(&mut self, num_bytes: usize) {
        self.used += num_bytes;
    }

    fn discard(&mut self, num_bytes: usize) {
        if num_bytes == 0 {
            return;
        }

        debug_assert!(num_bytes <= self.used);

        self.inner
            .copy_within(num_bytes..self.used, 0);
        self.used -= num_bytes;

        log::trace!("discarded {num_bytes}B");
    }

    fn reserve(&mut self, additional_bytes: usize) {
        let new_len = self.used + additional_bytes;
        self.inner.resize(new_len, 0);
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn len(&self) -> usize {
        self.filled().len()
    }

    fn filled(&self) -> &[u8] {
        &self.inner[..self.used]
    }

    fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.inner[..self.used]
    }

    fn unfilled(&mut self) -> &mut [u8] {
        &mut self.inner[self.used..]
    }

    fn capacity(&self) -> usize {
        self.inner.len()
    }
}

fn try_or_resize_and_retry<E>(
    mut f: impl FnMut(&mut [u8]) -> CoreResult<usize, E>,
    map_err: impl FnOnce(E) -> Result<InsufficientSizeError>,
    outgoing: &mut Buffer,
) -> Result<usize>
where
    E: StdError + Send + Sync + 'static,
{
    let written = match f(outgoing.unfilled()) {
        Ok(written) => written,

        Err(e) => {
            let InsufficientSizeError { required_size } = map_err(e)?;
            outgoing.reserve(required_size);
            log::trace!("resized `outgoing_tls` buffer to {}B", outgoing.capacity());

            f(outgoing.unfilled())?
        }
    };

    outgoing.advance(written);

    Ok(written)
}
