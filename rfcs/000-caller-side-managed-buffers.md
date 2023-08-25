# Summary

This document proposes adding a new, lower-level `{Client,Server}Connection` API where TLS and plain-text buffers are managed by the caller / end-user.
The design goals of this new API are to reduce / minimize memcpys, be no-std compatible and allow `async` certificate verification.

# Motivation / Background

[Issue 1362][gh1362] lists some issues with the existing `{Client,Server}Connection` API but to summarize:

[gh1362]: https://github.com/rustls/rustls/issues/1362

- the internal buffering results in extra memcpy-ing
- because the buffers are internal they can't be resized nor deallocated, when they are no longer needed, by the caller / end-user
- the API is not no-std compatible because it uses the `io::{Read,Write}` traits which are defined in libstd

The `Connection` API in this proposal addresses the above issues by

- requiring the end user to manage all buffers -- thus end-users can resize, allocate, deallocate the buffers as they see fit
- not including the `io` traits in its API -- thus the API has no-std support out of the box
- being state machine like to support both blocking and async IO

Lastly, the current `Connection` API internally / implicitly performs certificate validation.
When verification is done using `rustls_webpki`, this is fine because that API does not perform any IO action.
However, in the future when using `rustls-platform-verifier` with `rustls` becomes possible,
implicit verification becomes an issue because, on some platforms, `rustls-platform-verifier` performs IO actions like file operations or even network operations in some cases (e.g. on macOS).

# Guide-level explanation

> **NOTE**: a mock implementation, with runnable tests / examples, of the API presented in this section can be found in the `sketch` directory located in the root of this branch

This section explains the new API from the point of view of an end user.

## Overview

The top level API are the `LlClientConnection` and `LlServerConnection` structs.
These are lower level version of the existing `{Client,Server}Connection` API.
Their constructors will pretty much mimic the constructors of the existing `Connection` types.

```rust
impl LlClientConnection {
    pub fn new(config: Arc<ClientConfig>, name: ServerName) -> Result<Self, Error> {
        // ..
    }
}

impl LlServerConnection {
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
        // ..
    }
}
```

The differences start in the way how IO is performed.
The `LlConnection` types do not operate on IO objects; they operate on buffers.
The main methods of the `LlConnection` types are shown below:

```rust
type Result<T> = core::result::Result<T, rustls::Error>;

// both `LlClientConnection` and `LlServerConnection` implement `DerefMut<Target = LlConnectionCommon>`
pub struct LlConnectionCommon { /* .. */ }

impl LlConnectionCommon {
    /// Handles TLS records
    ///
    /// This method must always be called and its returned `Status` checked prior to
    /// calling either `encrypt_outgoing` or `decrypt_incoming`
    pub fn handle_tls_records<B>(
        &mut self,
        incoming_tls: &mut IncomingTls<B>,
        outgoing_tls: &mut Vec<u8>,
    ) -> Result<Status>
    where
        B: AsRef<[u8]> + AsMut<[u8]>,
    {
       // ..
    }

    /// Encrypts `app_data` into the `outgoing_tls` buffer
    pub fn encrypt_outgoing(&self, app_data: &[u8], outgoing_tls: &mut Vec<u8>) { /* .. */ }

    /// Decrypts the application data in the `incoming_tls` buffer
    ///
    /// The returned iterator yields decrypted application data, one item per TLS record
    ///
    /// The iterator will return an `Err`or in these cases
    /// - a record that's not application data was found, e.g. a handshake record
    /// - a fatal Alert record was found
    pub fn decrypt_incoming<'a, B>(
        &self,
        incoming_tls: &'a mut IncomingTls<B>,
    ) -> impl Iterator<Item = Result<&'a [u8]>> {
        // ..
    }
}
```

At a high level:

`encrypt_outgoing` prepares outgoing application data.
The plain-text data is encrypted, framed and placed in the outgoing TLS buffer.

`decrypt_incoming` extracts application data from the incoming, AKA received, TLS data.

`handle_tls_records` drives the handshake process to completion and handles TLS records that are not application data.
TLS records that are not application data may need to be sent as part of the handshake process so this method needs write access to the `outgoing_tls` buffer.

As the API documentation states the end-user must call `handle_tls_records` and check the returned `Status` prior to using the other two methods.
The flags in the `Status` struct indicate when it's possible to use the other two methods as application data may only be exchanged after the handshake process is complete.

## `Status` flags

The flags in the `Status` struct are accessed with the getter methods shown below.
The actions to take when each flag is set are documented in the method-level API docs.

```rust
impl Status {
    /// Handshake is complete. New TLS data will be application data
    pub fn may_receive_app_data(&self) -> bool {
        self.may_receive_app_data
    }

    /// `encrypt_outgoing` may now be used
    pub fn may_send_app_data(&self) -> bool {
        self.may_send_app_data
    }

    /// `encrypt_early_data` may now be used
    pub fn may_send_early_data(&self) -> bool {
        self.may_send_early_data
    }

    /// `incoming_tls` has application data that `decrypt_incoming` can decrypt
    pub fn received_app_data(&self) -> bool {
        self.received_app_data
    }

    /// `incoming_tls` has early ("0-RTT") data that `decrypt_early_data` can decrypt
    pub fn received_early_data(&self) -> bool {
        self.received_early_data
    }

    /// More TLS data needs to be added to the `incoming_tls` buffer to continue with the
    /// handshake process
    ///
    /// After new data has been appended to `incoming_tls` buffer, `handle_tls_record` must
    /// be called
    pub fn wants_read(&self) -> bool {
        self.wants_read
    }

    /// TLS records related to the handshake has been placed in the `outgoing_tls` buffer and
    /// must be transmitted to continue with the handshake process
    pub fn wants_write(&self) -> bool {
        self.wants_write
    }
}
```

The order in which these flags are processed is important so that's documented in the struct-level API docs:

```rust
/// the flags in this struct must be handled in the following order
/// - `received_early_data`
/// - `received_app_data`
/// - `may_send_early_data`
/// - `may_send_app_data`
/// - `wants_write`
/// - `wants_read`
/// - `may_receive_app_data`
#[derive(Default, Clone, Copy)]
#[must_use]
pub struct Status { /* .. */ }
```

## The `IncomingTls` buffer

The `outgoing_tls` buffer is relatively simple:
it's a `Vec` (vector) of bytes that must be transmitted in its entirety every now and then.

The `incoming_tls` buffer needs to support in-place decryption, appending data as well as removing data from the front.
To support these operations the `IncomingTls` type is provided.
This type wraps a generic slice of bytes object that can provide both immutable and mutable views into its contents.
Its main methods are shown below:

```rust
pub struct IncomingTls<B> { /* .. */ }

impl<B> IncomingTls<B>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Creates a new `IncomingTls` buffer
    pub fn new(buffer: B) -> Self { /* .. */ }

    /// Retrieves the underlying `buffer`
    ///
    /// To avoid discarding TLS data this should only be called when `filled().is_empty()` is `true`
    pub fn into_inner(self) -> B { /* .. */ }

    /// Returns a mutable view into the back of the buffer that has not yet been filled with
    /// TLS data
    pub fn unfilled(&mut self) -> &mut [u8] { /* .. */ }

    /// Returns an immutable view into the front of the buffer that already been filled with
    /// TLS data
    pub fn filled(&self) -> &[u8] { /* .. */ }

    /// Advances an internal cursor that tracks how full the buffer is
    pub fn advance(&mut self, num_bytes: usize) { /* .. */  }

    /// Discards `num_bytes` of application data from the front of the buffer
    pub fn discard_app_data(&mut self, num_bytes: usize) { /* .. */ }
}
```

To append data the `unfilled` and `advance` methods are used.
`unfilled` returns a mutable view into the part of the buffer that has not yet been filled with TLS data.
`advance` advances an internal cursor that tracks how full the buffer is.

```rust
// example: appending data to `IncomingTls`

let mut socket: std::net::TcpStream;
let mut incoming_tls: IncomingTls<_>;

// ..

let nbytes = socket.read(incoming_tls.unfilled())?;
incoming_tls.advance(nbytes);
```

`process_tls_records` will automatically remove handshake records from the front of the `incoming_tls` buffer once it's done processing them.
When the `decrypt_incoming` iterator is advanced, it becomes the end-user responsibility to discard application data records from the front of `incoming_tls` using the `discard_app_data` method.
`discard_app_data` uses number of bytes, instead of number of records, so it's possible to partially discard a record.

```rust
// example: discarding entire app data records

let mut conn: LlClientConnection;
let mut incoming_tls: IncomingTls<_>;

let mut num_bytes = 0;
for res in conn.decrypt_incoming(&mut incoming_tls) {
    let record = res?;
    num_bytes += record.len();
    handle(record);
}

incoming_tls.discard_app_data(num_bytes);
```

`discard_app_data` discards data from the front of the buffer;
this operation involves memcpy-ing data around.
For that reason, it's preferred to call `discard_app_data` _once_ after exhausting the iterator instead of on each iteration.

## Example event loop

Here's a complete event loop that completes the handshake process and includes some inline examples of application logic.

```rust
let mut conn: LlClientConnection;
let mut incoming_tls: IncomingTls<_>;
let mut outgoing_tls: Vec<u8>;
let mut socket: std::net::TcpStream;

// ..

loop {
    let status = conn.handle_tls_records(&mut incoming_tls, &mut outgoing_tls);

    if status.received_early_data() {
        // this is a client so this branch should never be hit
        #[cfg(debug_assertions)]
        unreachable!();
    }

    if status.received_app_data() {
        // application-specific logic goes here; contrived server-like example:

        let request = conn.decrypt_incoming(&mut incoming_tls).next().unwrap()?;
        handle(request);
    }

    if status.may_send_early_data() {
        // application-specific logic goes here; contrived example:

        let early_data = prepare_early_data();
        conn.encrypt_early_data(&early_data, &mut outgoing_tls);
        socket.write_all(&outgoing_tls)?;
        outgoing_tls.clear();
    }

    if status.may_send_app_data() {
        // application-specific logic goes here; contrived client-like example:

        let request = prepare_request();
        conn.encrypt_early_data(&early_data, &mut outgoing_tls);
        socket.write_all(&outgoing_tls)?;
        outgoing_tls.clear();

        let read = socket.read(incoming_tls.unfilled())?;
        incoming_tls.advance(read);
        if let Some(res) = conn.decrypt_incoming(&mut incoming_tls).next() {
            let response = res?;
            handle(response);
        }
    }

    if status.wants_write() {
        socket.write_all(&outgoing_tls)?;
        outgoing_tls.clear();
    }

    if status.want_read() {
        let read = socket.read(incoming_tls.unfilled())?;
        incoming_tls.advance(read);
    }

    if status.may_receive_app_data() {
        // application-specific logic goes here; contrived server-like example:

        let read = socket.read(incoming_tls.unfilled())?;
        incoming_tls.advance(read);

        if let Some(res) = conn.decrypt_incoming(&mut incoming_tls).next() {
            let request = res?;
            handle(request);
        }
    }
}
```

## Resizing buffers

One of the goals of this new API is to support resizing of all involved buffers.
An example is provided below:

```rust
let handshake_size: usize = 64 * 1024;
let mut outgoing_tls = Vec::with_capacity(handshake_size);
let mut incoming_tls = IncomingTls::new(vec![0; handshake_size]);

// complete the handshake process
loop {
    // ..
}

let post_handshake_size: usize = 4096;
if incoming_tls.filled().is_empty() {
    let mut buf = incoming_tls.into_inner();
    buf.truncate(post_handshake_size);
    incoming_tls = IncomingTls::new(buf);
}

if outgoing_tls.len() <= post_handshake_size {
    outgoing_tls.truncate(post_handshake_size);
}

// ..
```

In the case of `IncomingTls`, care must be taken to check that the buffer is empty prior to resizing.

In the case of `outgoing_tls`, the buffer can be resized while it contains data but
care must be taken not to discard existing data if truncating it.

## Early ("0-RTT") data

To handle early data, `LlClientConnection` and `LlServerConnection` have the following methods:

```rust
impl LlClientConnection {
    /// Encrypts `early_data` and appends it to the `outgoing_tls` buffer
    pub fn encrypt_early_data(&mut self, _early_data: &[u8], _outgoing_tls: &mut Vec<u8>) { /* .. */ }
}

impl LlServerConnection {
    /// Decrypts the early ("0-RTT") record that's in the front of the `incoming_tls` buffer
    ///
    /// Returns `None` if a record of said type is not available at the front of the `incoming_tls` buffer
    pub fn decrypt_early_data<'a, B>(
        &mut self,
        incoming_tls: &'a mut IncomingTls<B>,
    ) -> Option<Result<&'a [u8]>>
    where
        B: AsRef<[u8]> + AsMut<[u8]>,
    {
        // ..
    }

    /// Discards the early ("0-RTT") record that's in the front of the `incoming_tls` buffer
    pub fn discard_early_data(&mut self) { /* .. */ }
}
```

Before calling these, the `Status` flags `received_early_data` and `may_send_early_data` must be checked first.

# Implementation details

This section contains implementation details about the new API.

## Partially discarding app data records

To implement an equivalent of `rustls::Stream` API using the `LlConnection` types and, in particular, to implement the `io::Read` trait,
it's necessary to support partially discarding app data records.

Because `io::Read::read` works on mutable slices, the situation where it's not possible to copy an entire record into the provided buffer arises:

```rust
impl io::Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let capacity = buf.len();
        let mut cursor = 0;

        // ..

        let incoming_appdata = self.conn.decrypt_incoming(&mut self.incoming_tls);
        for res in incoming_appdata {
            let new_data = res?;

            let available = capacity - cursor;
            let tocopy = new_data.len().min(available);
            buf[cursor..cursor + tocopy].copy_from_slice(&new_data[..tocopy]);
            cursor += tocopy;

            if cursor == capacity {
                // `buf` is full; do not decrypt in place any other record
                break;
            }
        }

        // when the `cursor == capacity` condition is hit above, this call needs to partially
        // discard a record
        self.incoming_tls.discard_app_data(cursor);

        // ..
    }
}
```

This proposal suggests tracking partially discarded records in the `IncomingTls` data structure.

```rust
pub struct IncomingTls<B> {
    buf: B,

    filled: usize,

    // keeps track of how many bytes have already been discarded from the first app-data record
    // - `None` indicates that the record in the front has not been decrypted in place
    // - `Some` indicates that the record in the front has been decrypted in place; the inner
    //   value indicates how many bytes have already been discarded
    partially_discarded: Option<usize>,
}
```

As described in the code comment, when `discard_app_data` results in partially discarding a record,
the `partially_discarded` field is set to the `Some` variant.
The `decrypt_incoming` iterator will read the `partially_discarded` field and
only yield the part of the record that has not been discard.

The `decrypt_incoming` iterator also checks the variant of `partially_discarded` as an indicator of
whether the first record in `incoming_tls` has already been decrypted in place or not.
When `partially_discarded` is `None`, the first record is expected to be encrypted;
when it's `Some`, the expectation is that the record has already been decrypted.

Because the `decrypt_incoming` iterator decrypts a record each time `next` is called,
with the suggested approach, this can result in a runtime error in the following scenario:

```rust
let mut records = conn.decrypt_incoming(&mut incoming_tls);
drop(records.next().unwrap()?);

// forgot to call this!
// incoming_tls.discard_app_data();

let mut records = conn.decrypt_incoming(&mut incoming_tls);
assert!(records.next().unwrap().is_err());
```

Basically, every record decrypted using `next()` must be discarded, or partially discarded, prior to using a new instance of the `decrypt_incoming` iterator or that iterator will eventually error on a `next` call when it sees a decrypted record when a encrypted one was expected.

There are ways to address this last issue: `IncomingTls` could also store the numbers of records that have already been decrypted in place.
`partially_discarded` would still refer to the first record.
It's unclear if decrypting records that won't be immediately used should be supported or encouraged.
At first glance, it seems wasteful but "decrypting ahead of time" could have some use case.

## Misusing the API

This section describes some scenarios where the API is misused and what the outcomes are.

- `wants_read` returns `true`, no data or an incomplete TLS record is appended to `incoming_tls` and `process_tls_records` is called
  - the newly returned `Status` will also have `wants_read` set to true. the handshake won't make progress until sufficient data is appended to `incoming_tls`
- `wants_read` and `wants_write` are both set to `true`, `wants_read` is handled first by doing a read operation on the network socket
  - this will likely cause the read operation to block forever, or time out if timeouts were configured

Also see the 'unresolved questions' section.

# Supporting async certificate verification

> NOTE this section is still very much WIP / in-flux

In the API described thus far the certificate verification still happens implicitly in `process_tls_records`.

To support both blocking and async certificate verification without "coloring" the API, the API will be revised as follows:

- `LlClientConnection` and `LlServerConnection` will not implicitly perform certificate verification
- `LlClientConnection` and `LlServerConnection` will not contain a `ServerCertVerifier` / `ClientCertVerifier` trait object
- `CertificateVerifier` will be a separate object that the user of the `LlConnection` API must manage
- `Status` will gain flags related to the certificate verification process:
  - certificate verification related data can be decrypted from the front of the `incoming_tls` buffer
  - certificate verification can be canceled
  - the result of certificate verification must be fed back into `LlConnection`
- `LlConnectionCommon` will gain an API to decrypt certificate verification related data from `incoming_tls` buffer
- `LlConnectionCommon` will gain an API to incorporate the results from the certificate verification process into the handshake process

Letting the end-user manage the certificate verification process means that they can decide whether to perform it in a blocking fashion, either serially, concurrently using `select` or in parallel using `thread::spawn`; or asynchronously, either concurrently using `join!` / `select!` / `FuturesUnordered` or in parallel using `task::spawn`.

The exact API changes / additions required to achieve async support have yet to be fleshed out but a rough sketch (it may not even compile) is presented below:

```rust
impl Status {
    pub fn received_certificate_verification_data(&self) -> bool {
        self.received_certificate_verification_data
    }

    pub fn needs_certificate_verification_result(&self) -> bool {
        self.needs_certificate_verification_result
    }
}

pub enum CertificationVerificationData<'a> {
    // ..
}

pub enum CertificateVerificationOutcome {
    Success(SuccessfulCertificatieVerification),
    Failure,
}

pub struct SuccessfulCertificatieVerification {
    // ..
}

impl LlConnectionCommon {
    pub fn decrypt_certificate_verification_data<'a, B>(
        &self,
        incoming_tls: &'a mut IncomingTls<B>,
    ) -> Result<CertificationVerificationData<'a>> {
        // ..
    }

    pub fn provide_certificate_verification_outcome(
        &self,
        outcome: CertificateVerificationOutcome,
        outgoing_tls: &mut Vec<u8>,
    ) {
        // ..
    }
}
```

Example event loop using the above API

```rust
let mut conn: LlClientConnection;
let mut incoming_tls: IncomingTls<_>;
let mut cert_verifier: ServerCertVerifier;

loop {
    let status = conn.handle_tls_records(&mut incoming_tls, &mut outgoing_tls);

    // ..

    if status.received_certificate_verification_data() {
        let data = conn.decrypt_certificate_verification_data(&mut incoming_tls)?;
        cert_verifier.handle(data)?;
    }

    if status.needs_certificate_verification_result() {
        let outcome = cert_verifier.finish()?;
        conn.provide_certificate_verification_outcome(outcome, &mut outgoing_tls);
    }

    // ..
}
```

# Alternatives

## More proactive `Status`

In the proposed API, the `Status` object only contains boolean flags.
After checking these flags, one must call API like `decrypt_early_data`.
In some cases this can feel like one is performing redundant checks:

```rust
if status.received_early_data() {
    if let Some(early_data) = conn.decrypt_early_data(&mut incoming_tls) {
        // ..

        conn.discard_early_data();
    }
}
```

An alternative to this is to, for example, include the early data in the `Status` itself

```rust
impl Status {
    pub fn early_data(&self) -> Option<&[u8]> { /* .. */ }
}
```

But this alternative has two issues:
`Status` would have to gain a lifetime that ties it to the `incoming_tls` buffer.
Given how Rust works, even if `early_data` were to return `None` the `status` value would still "freeze" `incoming_tls` meaning that it can't be mutated until `status` goes out of scope / is dropped.

The other issues is that if `process_tls_records` automatically decrypts early data, the end-user no longer has the option to discard the early data without decrypting it first (see snippet below) to save some CPU work.

```rust
// this is possible with the API in the main proposal

if status.received_early_data() {
    conn.discard_early_data();
    // without decrypting it first
}
```

## `Status` enum

The boolean flags in the `Status` struct must be handled in a particular order.
The onus is on the end-user to follow the documented processing order.

Given that `Status` only contains boolean flags, an alternative is to turn `Status` into an enum where all the flags become variants.
This has the advantage that `process_tls_records` can yield the variants in the order they need to be processed eliminating the possibility of handling them in the wrong order.

This alternative changes the usual event loop with several `if` statement into a one loop with a single `match` statement:

```rust
loop {
    let status = conn.handle_tls_records(&mut incoming_tls, &mut outgoing_tls);
    match status {
        Status::WantsRead => {
            // read socket here
        }

        Status::WantsWrite => {
            // write to socket here
        }

        // ..
    }
}
```

A `match` statement requires that all variants are managed.
This has the downside that unreachable variants like `ReceivedEarlyData`, in the case of a client, have to be explicitly ignored.
On the flip side, one is less likely to forget to handle one of the variants.

Some of the existing flags like `may_send_app_data` and `may_received_app_data` don't make much sense as variants so
perhaps `handle_tls_records` should return both a `State` enum and boolean flags in a `Capabilities` struct.

```rust
pub struct Capabilities {
    may_receive_app_data: bool,
    may_send_app_data: bool,
    may_send_early_data: bool,
}

pub enum State {
    /// TLS data must be appended to `incoming_tls` to continue with the handshake
    WantsRead,

    /// `outgoing_tls` buffer must be transmitted to continue with the handshake
    WantsWrite,

    /// early data in `incoming_tls` must be decrypted or discarded to continue with the handshake
    ReceivedEarlyData,

    /// app data is available in `incoming_tls`
    ReceivedAppData,

    /// Handshake complete; connection secured
    Secured,
}

loop {
    let (caps, state) = conn.handle_tls_records(&mut incoming_tls, &mut outgoing_tls);

    match state {
        State::WantsWrite => {
            if caps.may_send_app_data {
                // append app data to `outgoing_tls` before transmitting
            }

            // ..
        }

        // ..
    }
}
```

# Unresolved questions

what should the behavior be in these scenarios

- `Status::wants_write` returns `true`, `outgoing_tls` is not fully transmitted and `process_tls_records` is called
  - should `wants_write` "latch" to the `true` value until `outgoing_tls` is observed as being empty?
- `Status::may_send_app_data` returns `false` and `encrypt_outgoing` is called
  - do nothing?
  - consider this a programmer error, a "bug", and panic
  - return a `Result::Err`
  - panic when `debug_assertions` are enabled; do nothing when they are disabled
- `Status::may_send_early_data` returns `false` and `encrypt_early_data` is called
- `discard_app_data` is called during the handshake process when there are still no application data records in `incoming_tls`
- `discard_app_data` is called with a wrong value: e.g. greater than `filled().len()`
- etc.

how to best fit the `std::io::Read::read_buf` API (`BorrowedCursor`, `BorrowedBuf`) into this design

# References

- Comments in the GitHub issue ["Allow for more flexible buffer management"][gh1362]
- Brian Smith's [comment][gh850] on making certificate verification async

[gh850]: https://github.com/rustls/rustls/issues/850#issuecomment-999798205
