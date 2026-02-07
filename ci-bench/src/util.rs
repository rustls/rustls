pub(crate) mod async_io {
    //! Async IO building blocks required for sharing code between the instruction count and
    //! wall-time benchmarks

    use core::cell::{Cell, RefCell};
    use core::future::Future;
    use core::pin::{Pin, pin};
    use core::task::{Poll, RawWaker, RawWakerVTable, Waker};
    use core::{ptr, task};
    use std::collections::VecDeque;
    use std::fs::File;
    use std::io;
    use std::rc::Rc;

    use async_trait::async_trait;

    /// Block on a future that should complete in a single poll.
    ///
    /// Safe to use when the underlying futures are blocking (e.g. waiting for an IO operation to
    /// complete, and returning Poll::Ready afterwards, without yielding in between).
    ///
    /// Useful when counting CPU instructions, because the server and the client side of the
    /// connection run in two separate processes and communicate through stdio using blocking
    /// operations.
    pub(crate) fn block_on_single_poll(
        future: impl Future<Output = anyhow::Result<()>>,
    ) -> anyhow::Result<()> {
        // We don't need a waker, because the future will complete in one go
        let waker = noop_waker();
        let mut ctx = task::Context::from_waker(&waker);

        match pin!(future).poll(&mut ctx) {
            Poll::Ready(result) => result,
            Poll::Pending => {
                panic!("the provided future did not finish after one poll!")
            }
        }
    }

    /// Block on two futures that are run concurrently and return their results.
    ///
    /// Useful when measuring wall-time, because the server and the client side of the connection
    /// run in a single process _and_ thread to minimize noise. Each side of the connection runs
    /// inside its own future and they are polled in turns.
    ///
    /// Using this together with blocking futures can lead to deadlocks (i.e. when one of the
    /// futures is blocked while it waits on a message from the other).
    pub(crate) fn block_on_concurrent(
        x: impl Future<Output = anyhow::Result<()>>,
        y: impl Future<Output = anyhow::Result<()>>,
    ) -> (anyhow::Result<()>, anyhow::Result<()>) {
        let mut x = pin!(x);
        let mut y = pin!(y);

        // The futures won't complete right away, but since there are only two of them we can poll
        // them in turns without a more complex waking mechanism.
        let waker = noop_waker();
        let mut ctx = task::Context::from_waker(&waker);

        let mut x_output = None;
        let mut y_output = None;

        // Fuel makes sure we can exit a potential infinite loop if the futures are endlessly
        // waiting on each other due to a bug (e.g. a read without a corresponding write)
        let mut fuel = 1_000;
        loop {
            let futures_done = x_output.is_some() && y_output.is_some();
            if futures_done || fuel == 0 {
                break;
            }

            fuel -= 1;

            if x_output.is_none() {
                match x.as_mut().poll(&mut ctx) {
                    Poll::Ready(output) => x_output = Some(output),
                    Poll::Pending => {}
                }
            }

            if y_output.is_none() {
                match y.as_mut().poll(&mut ctx) {
                    Poll::Ready(output) => y_output = Some(output),
                    Poll::Pending => {}
                }
            }
        }

        match (x_output, y_output) {
            (Some(x_output), Some(y_output)) => (x_output, y_output),
            _ => panic!("at least one of the futures seems to be stuck"),
        }
    }

    // Copied from Waker::noop, which we cannot use directly because it hasn't been stabilized
    fn noop_waker() -> Waker {
        const VTABLE: RawWakerVTable = RawWakerVTable::new(|_| RAW, |_| {}, |_| {}, |_| {});
        const RAW: RawWaker = RawWaker::new(ptr::null(), &VTABLE);
        unsafe { Waker::from_raw(RAW) }
    }

    /// Read bytes asynchronously
    #[async_trait(?Send)]
    pub(crate) trait AsyncRead {
        async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
        async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()>;
    }

    /// Write bytes asynchronously
    #[async_trait(?Send)]
    pub(crate) trait AsyncWrite {
        async fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;
        async fn flush(&mut self) -> io::Result<()>;
    }

    // Blocking implementation of AsyncRead for files (used to read from stdin)
    #[async_trait(?Send)]
    impl AsyncRead for File {
        async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            io::Read::read(self, buf)
        }

        async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
            io::Read::read_exact(self, buf)
        }
    }

    // Blocking implementation of AsyncWrite for files (used to write to stdout)
    #[async_trait(?Send)]
    impl AsyncWrite for File {
        async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            io::Write::write_all(self, buf)
        }

        async fn flush(&mut self) -> io::Result<()> {
            io::Write::flush(self)
        }
    }

    /// Creates an unidirectional byte pipe of the given capacity, suitable for async reading and
    /// writing
    pub(crate) fn async_pipe(capacity: usize) -> (AsyncSender, AsyncReceiver) {
        let open = Rc::new(Cell::new(true));
        let buf = Rc::new(RefCell::new(VecDeque::with_capacity(capacity)));
        (
            AsyncSender {
                inner: AsyncPipeSide {
                    open: Rc::clone(&open),
                    buf: Rc::clone(&buf),
                },
            },
            AsyncReceiver {
                inner: AsyncPipeSide { open, buf },
            },
        )
    }

    /// The sender end of an asynchronous byte pipe
    pub(crate) struct AsyncSender {
        inner: AsyncPipeSide,
    }

    /// The receiver end of an asynchronous byte pipe
    pub(crate) struct AsyncReceiver {
        inner: AsyncPipeSide,
    }

    struct AsyncPipeSide {
        open: Rc<Cell<bool>>,
        buf: Rc<RefCell<VecDeque<u8>>>,
    }

    impl Drop for AsyncPipeSide {
        fn drop(&mut self) {
            self.open.set(false);
        }
    }

    #[async_trait(?Send)]
    impl AsyncRead for AsyncReceiver {
        async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            AsyncPipeReadFuture {
                reader: self,
                user_buf: buf,
            }
            .await
        }

        async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
            let mut read = 0;
            while read < buf.len() {
                read += self.read(&mut buf[read..]).await?;
            }

            Ok(())
        }
    }

    #[async_trait(?Send)]
    impl AsyncWrite for AsyncSender {
        async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            AsyncPipeWriteFuture {
                writer: self,
                user_buf: buf,
            }
            .await
        }

        async fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct AsyncPipeReadFuture<'a> {
        reader: &'a AsyncReceiver,
        user_buf: &'a mut [u8],
    }

    impl Future for AsyncPipeReadFuture<'_> {
        type Output = io::Result<usize>;

        fn poll(mut self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<Self::Output> {
            let inner_buf = &mut self.reader.inner.buf.borrow_mut();
            if inner_buf.is_empty() {
                return if self.reader.inner.open.get() {
                    // Wait for data to arrive, or EOF
                    Poll::Pending
                } else {
                    // EOF
                    Poll::Ready(Ok(0))
                };
            }

            let bytes_to_write = inner_buf.len().min(self.user_buf.len());

            // This is a convoluted way to copy the bytes from the inner buffer into the user's
            // buffer
            let (first_half, second_half) = inner_buf.as_slices();
            let bytes_to_write_from_first_half = first_half.len().min(bytes_to_write);
            let bytes_to_write_from_second_half =
                bytes_to_write.saturating_sub(bytes_to_write_from_first_half);
            self.user_buf[..bytes_to_write_from_first_half]
                .copy_from_slice(&first_half[..bytes_to_write_from_first_half]);
            self.user_buf[bytes_to_write_from_first_half..bytes_to_write]
                .copy_from_slice(&second_half[..bytes_to_write_from_second_half]);

            inner_buf.drain(..bytes_to_write);

            Poll::Ready(Ok(bytes_to_write))
        }
    }

    struct AsyncPipeWriteFuture<'a> {
        writer: &'a AsyncSender,
        user_buf: &'a [u8],
    }

    impl Future for AsyncPipeWriteFuture<'_> {
        type Output = io::Result<()>;

        fn poll(mut self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<Self::Output> {
            if !self.writer.inner.open.get() {
                return Poll::Ready(Err(io::Error::other("channel was closed")));
            }

            let mut pipe_buf = self.writer.inner.buf.borrow_mut();
            let capacity_left = pipe_buf.capacity() - pipe_buf.len();
            let bytes_to_write = self.user_buf.len().min(capacity_left);
            pipe_buf.extend(&self.user_buf[..bytes_to_write]);

            if self.user_buf.len() > capacity_left {
                self.user_buf = &self.user_buf[bytes_to_write..];

                // Continue writing later once capacity is available
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn test_block_on_concurrent_minimal_capacity() {
            test_block_on_concurrent(1);
        }

        #[test]
        fn test_block_on_concurrent_enough_capacity() {
            test_block_on_concurrent(100);
        }

        fn test_block_on_concurrent(capacity: usize) {
            let (mut server_writer, mut client_reader) = async_pipe(capacity);
            let (mut client_writer, mut server_reader) = async_pipe(capacity);

            let client = async {
                client_writer
                    .write_all(b"hello")
                    .await
                    .unwrap();

                let mut buf = [0; 2];
                client_reader
                    .read_exact(&mut buf)
                    .await
                    .unwrap();
                assert_eq!(&buf, b"42");

                client_writer
                    .write_all(b"bye bye")
                    .await
                    .unwrap();

                Ok(())
            };

            let server = async {
                let mut buf = [0; 5];
                server_reader
                    .read_exact(&mut buf)
                    .await
                    .unwrap();
                assert_eq!(&buf, b"hello");

                server_writer
                    .write_all(b"42")
                    .await
                    .unwrap();

                let mut buf = [0; 7];
                server_reader
                    .read_exact(&mut buf)
                    .await
                    .unwrap();
                assert_eq!(&buf, b"bye bye");

                Ok(())
            };

            let (client_result, server_result) = block_on_concurrent(client, server);
            client_result.unwrap();
            server_result.unwrap();
        }
    }
}

pub(crate) mod transport {
    //! Custom functions to interact between rustls clients and a servers.
    //!
    //! The goal of these functions is to ensure messages are exchanged in chunks of a fixed size, to make
    //! instruction counts more deterministic. This is particularly important for the receiver of the
    //! data. Without it, the amount of bytes received in a single `read` call can wildly differ among
    //! benchmark runs, which in turn influences the resizing of rustls' internal buffers, and therefore
    //! affects the instruction count (resulting in consistent noise above 2% for the client-side of the
    //! data transfer benchmarks, which is unacceptable).
    //!
    //! Note that this approach introduces extra copies, because we are using an intermediate buffer,
    //! but that doesn't matter (we are measuring performance differences, and overhead is automatically
    //! ignored as long as it remains constant).

    use std::io::{Cursor, Read, Write};

    use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
    use rustls::{ClientConnection, Connection, ServerConnection};

    use super::async_io::{AsyncRead, AsyncWrite};

    /// Sends one side's handshake data to the other side in one go.
    ///
    /// Because it is not possible for the receiver to know beforehand how many bytes are contained in
    /// the message, the transmission consists of a leading big-endian u32 specifying the message's
    /// length, followed by the message itself.
    ///
    /// The receiving end should use [`read_handshake_message`] to process the transmission.
    pub(crate) async fn send_handshake_message(
        conn: &mut impl Connection,
        writer: &mut dyn AsyncWrite,
        buf: &mut [u8],
    ) -> anyhow::Result<()> {
        // Write all bytes the connection wants to send to an intermediate buffer
        let mut written = 0;
        while conn.wants_write() {
            if written >= buf.len() {
                anyhow::bail!(
                    "Not enough space in buffer for outgoing message (buf len = {})",
                    buf.len()
                );
            }

            written += conn.write_tls(&mut &mut buf[written..])?;
        }

        if written == 0 {
            return Ok(());
        }

        // Write the whole buffer in one go, preceded by its length
        let mut length_buf = Vec::with_capacity(4);
        length_buf.write_u32::<BigEndian>(written as u32)?;
        writer.write_all(&length_buf).await?;
        writer
            .write_all(&buf[..written])
            .await?;
        writer.flush().await?;

        Ok(())
    }

    /// Receives one side's handshake data to the other side in one go.
    ///
    /// Used in combination with [`send_handshake_message`] (see that function's documentation for
    /// more details).
    pub(crate) async fn read_handshake_message(
        conn: &mut impl Connection,
        reader: &mut dyn AsyncRead,
        buf: &mut [u8],
    ) -> anyhow::Result<usize> {
        // Read the length of the message to an intermediate buffer and parse it
        let mut length_buf = [0; 4];
        reader
            .read_exact(&mut length_buf)
            .await?;
        let length = Cursor::new(length_buf).read_u32::<BigEndian>()? as usize;

        // Read the rest of the message to an intermediate buffer
        if length >= buf.len() {
            anyhow::bail!(
                "Not enough space in buffer for incoming message (msg len = {length}, buf len = {})",
                buf.len()
            );
        }

        reader
            .read_exact(&mut buf[..length])
            .await?;

        // Feed the data to rustls
        let in_memory_reader = &mut &buf[..length];
        while conn.read_tls(in_memory_reader)? != 0 {
            conn.process_new_packets()?;
        }

        Ok(length)
    }

    /// Reads plaintext until the reader reaches EOF, using a bounded amount of memory.
    ///
    /// Returns the amount of plaintext bytes received.
    pub(crate) async fn read_plaintext_to_end_bounded(
        client: &mut ClientConnection,
        reader: &mut dyn AsyncRead,
    ) -> anyhow::Result<usize> {
        let mut chunk_buf = [0u8; 262_144];
        let mut plaintext_buf = [0u8; 262_144];
        let mut total_plaintext_bytes_read = 0;

        loop {
            // Read until the whole chunk is received
            let mut chunk_buf_end = 0;
            while chunk_buf_end != chunk_buf.len() {
                let read = reader
                    .read(&mut chunk_buf[chunk_buf_end..])
                    .await?;
                if read == 0 {
                    // Stream closed
                    break;
                }

                chunk_buf_end += read;
            }

            if chunk_buf_end == 0 {
                // Stream closed
                break;
            }

            // Load the buffer's bytes into rustls
            let mut chunk_buf_offset = 0;
            while chunk_buf_offset < chunk_buf_end {
                let read = client.read_tls(&mut &chunk_buf[chunk_buf_offset..chunk_buf_end])?;
                chunk_buf_offset += read;

                // Process packets to free space in the message buffer
                let state = client.process_new_packets()?;
                let available_plaintext_bytes = state.plaintext_bytes_to_read();
                let mut plaintext_bytes_read = 0;
                while plaintext_bytes_read < available_plaintext_bytes {
                    plaintext_bytes_read += client
                        .reader()
                        .read(&mut plaintext_buf)?;
                }

                total_plaintext_bytes_read += plaintext_bytes_read;
            }
        }

        Ok(total_plaintext_bytes_read)
    }

    /// Writes a plaintext of size `plaintext_size`, using a bounded amount of memory
    pub(crate) async fn write_all_plaintext_bounded(
        server: &mut ServerConnection,
        writer: &mut dyn AsyncWrite,
        plaintext_size: usize,
    ) -> anyhow::Result<()> {
        let mut send_buf = [0u8; 262_144];
        assert_eq!(plaintext_size % send_buf.len(), 0);
        let iterations = plaintext_size / send_buf.len();

        for _ in 0..iterations {
            server.writer().write_all(&send_buf)?;

            // Empty the server's buffer, so we can re-fill it in the next iteration
            while server.wants_write() {
                let written = server.write_tls(&mut send_buf.as_mut())?;
                writer
                    .write_all(&send_buf[..written])
                    .await?;
                writer.flush().await?;
            }
        }

        Ok(())
    }
}
