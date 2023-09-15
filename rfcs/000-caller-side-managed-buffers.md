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
The `LlConnection` types only have a single method:

```rust
type Result<T> = core::result::Result<T, crate::Error>;

// both `LlClientConnection` and `LlServerConnection` implement `DerefMut<Target = LlConnectionCommon>`
pub struct LlConnectionCommon { /* .. */ }

impl LlConnectionCommon {
    /// Processes TLS records in the `incoming_tls` buffer
    pub fn process_tls_records<'c, 'i>(
        &'c mut self,
        incoming_tls: &'i mut [u8],
    ) -> Result<Status<'c, 'i>, crate::Error> {
       // ..
    }
}
```

`process_tls_records` handles TLS records in the `incoming_tls` buffer and drives the handshake process to completion.
The returned `Status` value contains a newtype over `LlConnection` that enables operations like decrypting received app-data records and encrypting application data depending on the current state of the TLS connection.

## `Status`

`Status` is a struct with two public fields: `state` and `discard`.

```rust
#[must_use]
pub struct Status<'c, 'i> {
    /// number of bytes that must be discarded from the *front* of `incoming_tls` *after* handling
    /// `state` and *before* the next `process_tls_records` call
    pub discard: usize,

    /// the current state of the handshake process
    pub state: State,
}
```

The `discard` field indicates how many bytes must be discarded from the front of the `incoming_tls` buffer _after_ handling `state` and _before_ the next `process_tls_records` call.
Examples of how this can be achieved with different collections will be presented later.

`State` is an enum that represent the current state of the handshake process.
The different states are described in the following snippet.

```rust
pub enum State<'c, 'i> {
    /// One, or more, application data record is available
    AppDataAvailable(AppDataAvailable<'c, 'i>),

    /// An early data record is available
    EarlyDataAvailable(EarlyDataAvailable<'c, 'i>),

    /// Application data may be encrypted at this stage of the handshake
    MayEncryptAppData(MayEncryptAppData<'c>),

    /// Early (0-RTT) data may be encrypted
    MayEncryptEarlyData(MayEncryptEarlyData<'c>),

    /// A Handshake record must be encrypted into the `outgoing_tls` buffer
    MustEncryptTlsData(MustEncryptTlsData<'c>),

    /// TLS records related to the handshake have been placed in the `outgoing_tls` buffer and must
    /// be transmitted to continue with the handshake process
    MustTransmitTlsData(MustTransmitTlsData<'c>),

    /// More TLS data needs to be added to the `incoming_tls` buffer to continue with the handshake
    NeedsMoreTlsData {
        /// number of bytes required to complete a TLS record. `None` indicates that
        /// no information is available
        num_bytes: Option<NonZeroUsize>,
    },

    /// Handshake is complete.
    TrafficTransit(TrafficTransit<'c>),

    // .. other variants are omitted for now ..
}
```

Most variants contain a single, unnamed field.
These unnamed fields are new types over `LlConnectionCommon` and restrict the operations that are possible.
The following subsections cover the API of these fields.

### `AppDataAvailable`

Application data records are available in the `incoming_tls` buffer and can be decrypted.
This state generally occurs after the handshake is complete but may also happen during the handshake process.

```rust
/// A decrypted application data record
pub struct AppDataRecord<'i> {
    /// number of the bytes associated to this record that must discarded from the front of
    /// the `incoming_tls` buffer before the next `process_tls_record` call
    pub discard: NonZeroUsize,

    pub payload: &'i [u8],
}

impl<'c, 'i> Iterator for AppDataAvailable<'c, 'i> {
    type Item = Result<AppDataRecord<'i>, crate::Error>;

    // ..
}

impl<'c, 'i> AppDataAvailable<'c, 'i> {
    /// returns the payload size of the next app-data record *without* decrypting it
    ///
    /// returns `None` if there are no more app-data records
    pub fn peek_len(&self) -> Option<NonZeroUsize> { /* .. */ }
}
```

The `AppDataAvailable` type implements the `Iterator` trait and yields decrypted application data records (`AppDataRecord`).
The actual iterator `Item` type is a `Result`.
The `Error` variant can be returned in these scenarios:

- decryption failed
- an Alert record of the fatal kind was found

The `discard` field of `AppDataRecord` is similar to the `discard` field of `Status`:
it's the number of bytes that must be removed from the front of the `incoming_tls` buffer before
the next `process_tls_records` call.

The `AppDataAvailable` type also provide a `peek_len` method that returns the _payload_ size of the next app-data record.

### `EarlyDataAvailable`

This state only occurs on the server-side of a TLS connection.
The only operation available in this state is decrypting the record.

```rust
impl<'c, 'i> EarlyDataAvailable<'c, 'i> {
    /// returns the decrypted payload of the early data record
    pub fn decrypt(self) -> Result<AppDataRecord<'i>, crate::Error> { /* .. */ }
}
```

An `Error` is returned when decryption fails.

### `MayEncryptAppData`

This state may occur during the handshake process and allows sending app-data records alongside handshake records in the same, e.g. TCP, packet.

```rust
/// Provided buffer was too small
pub struct InsufficientSizeError {
    /// buffer must be at least this size
    pub required_size: usize,
}

impl<'c> MayEncryptAppData<'c> {
    /// encrypts `application_data` into `outgoing_tls`
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    pub fn encrypt(
        &mut self,
        application_data: &[u8],
        outgoing_tls: &mut [u8],
    ) -> Result<usize, InsufficientSize> { /* .. */ }

    /// No more encryption will be performed; continue with the handshake process
    pub fn done(self) { /* .. */ }
}
```

The `encrypt` operation is fallible because the `outgoing_tls` buffer may not be large enough.
The error type, `InsufficientSizeError`, includes a field that indicates how large `outgoing_tls` must be for the operation to succeed.
The `encrypt` operation can be retried in the error case.
An example of how to handle `InsufficientSizeError` will be provided in a later section.

The `done` method must be called to continue with the `handshake` process.
If one does not want to send application data during the handshake process,
one can call `done` without calling `encrypt` first.

### `MayEncryptEarlyData`

This state only occurs on the client side of a TLS connection.
The API of this state is the same as the API of the `MayEncryptAppData` state.

```rust
impl<'c> MayEncryptEarlyData<'c> {
    /// Encrypts `early_data` into the `outgoing_tls` buffer
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    pub fn encrypt(
        &mut self,
        early_data: &[u8],
        outgoing_tls: &mut [u8],
    ) -> Result<usize, InsufficientSize> { /* .. */ }

    /// Continue with the handshake process
    pub fn done(self) { /* .. */ }
}
```

### `MustEncryptTlsData`

This state provides a single method: `encrypt`.

```rust
/// An error occurred while encrypting a handshake record
pub enum EncryptError {
    /// Provided buffer was too small
    InsufficientSize(InsufficientSizeError),

    /// The handshake record has already been encrypted; do not call `encrypt` again
    AlreadyEncrypted,
}

impl<'c> MustEncryptTlsData<'c> {
    /// Encrypts a handshake record into the `outgoing_tls` buffer
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    pub fn encrypt(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, InsufficientSize> {
        // ..
    }
}
```

The method will fail with the `InsufficientSizeError` variant if the provided buffer is too small, in which case the operation can be retried.
If the method is called again after the last call succeed, it'll fail with the `AlreadyEncrypted` variant.
To continue with the handshake process, the method call must succeed.

### `MustTransmitTlsData`

This state indicates that all the data in the `outgoing_tls` buffer must be transmitted.
How this is performed, e.g. in a blocking or asynchronous manner, is entirely up to the user.
Once the data has been transmitted, the `done` must be called to continue with the handshake.

```rust
impl<'c> MustTransmitTlsData<'c> {
    pub fn done(self) { /* .. */ }
}
```

To prevent sending the same TLS data again, it's recommended that the `outgoing_tls` buffer is "cleared" or emptied after transmission.

### `NeedsMoreTlsData`

This state indicates that more TLS data needs to be added to the `incoming_tls` buffer to continue with the handshake process.
This usually involves reading out new data from a network socket and placing it in the `incoming_tls` buffer.
Again, how that IO operation is performed is entirely up to the user.

In the case an incomplete TLS record in the `incoming_tls` buffer is observed, the state will report how many additional bytes are required to complete that record.
Note that several TLS records are usually packed in a single network packet to speed up the handshake process so reading out one record at a time from the network socket may not be the most efficient way to complete the handshake phase.
In other words, the `num_bytes` field should be treated as a _hint_ and not as the best route of action.

### `TrafficTransit`

This state indicates that the handshake phase is complete and the connection is secured;
application may be exchanged bidirectionally at this stage.

```rust
impl<'c> TrafficTransit<'c> {
    /// Encrypts `application_data` into the `outgoing_tls` buffer
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    pub fn encrypt(
        &mut self,
        application_data: &[u8],
        outgoing_tls: &mut [u8],
    ) -> Result<usize, InsufficientSize> { /* .. */ }
}
```

The state only provides an `encrypt` method which can be used to transmit TLS data.
To receive TLS data one can add new data -- retrieved from a network socket -- to `incoming_tls` and call `process_tls_records`.
If enough TLS data was provided, `process_tls_records` will return the `AppDataAvailable` state.

## Handling `InsufficientSizeError`

This section contains an example of handling the `InsufficientSizeError` when the `outgoing_tls` buffer is a `Vec`.

```rust
let mut outgoing_tls = Vec::new();
let mut outgoing_used = 0;

// some sort of event loop
loop {
    // ..
    match state {
        State::MayEncryptAppData(mut state) {
            let some_app_data = /* .. */;

            let res = state.encrypt(some_app_data, &mut outgoing_tls[outgoing_used..]);

            match res {
                Ok(written) => {
                    outgoing_used += written;
                }

                Err(InsufficientSizeError { required_size }) => {
                    let new_len = outgoing_used + required_size;
                    outgoing_tls.resize(new_len, 0);

                    // don't forget to encrypt `some_app_data` after resizing the buffer!
                    let written = state
                        .encrypt(some_app_data, &mut outgoing_tls[outgoing_used..])
                        .expect("should not fail after resizing");

                    outgoing_used += written;
                }
            }

            state.done();
        }

        // ..
    }
}
```

## Example event loop with blocking IO

This section contains an example of a complete event loop.

```rust
let mut conn: LlClientConnection;
let mut sock: std::net::TcpStream;

// .. configure / inititiaize `conn` and `sock`

let mut incoming_tls = [0; 16 * 1024];
let mut incoming_used = 0;

let mut outgoing_tls = Vec::new();
let mut outgoing_used = 0;

loop {
    let Status { discard, state } = conn.process_tls_records(&incoming_tls);
    let mut discard = discard.get();

    match state {
        // logic similar to the one presented in the 'handling InsufficientSizeError' section is
        // used in these states
        State::MustEncryptTlsData(state) => { /* .. */ }
        State::MayEncryptAppData(state) => { /* .. */ }

        State::MustTransmitTlsData(state) => {
            sock.write_all(&outgoing_tls[..outgoing_used])?;

            outgoing_used = 0;

            state.done();
        }

        State::NeedsMoreTlsData { .. } => {
            // NOTE real code needs to handle the scenario where `incoming_tls` is not big enough
            let read = sock.read(&mut incoming_tls[incoming_used..])?;
            incoming_used += read;
        }

        State::MayEncryptEarlyData(state) => {
            // this example does not send any early data
            state.done();
        }

        State::AppDataAvailable(records) => {
            for res in records {
                let AppDataRecord {
                    discard: new_discard,
                    payload,
                } = res?;

                discard += new_discard.get();

                // do app-specific stuff with `payload`
            }
        }

        State::EarlyDataAvailable(_) => {
            // unreachable since this is a client
            #[cfg(debug_assertions)]
            unreachable!();
        }

        State::TrafficTransit(_) => {
            // post-handshake logic
        }
    }

    // discard TLS records
    if discard != 0 {
        incoming_tls.copy_within(discard .. incoming_used, 0);
        incoming_used -= discard;
    }
}
```

The parts of this example that are worth highlighting are:

Discarding TLS record has to happen after `state` has been consumed by the `match` statement.
This is due to how the borrow checker works:
`state` mutably borrows the `incoming_tls` buffer so the buffer cannot be modified while `state` is "alive".

After decrypting records in the `AppDataAvailable` and `EarlyDataAvailable` states, the records need to be discarded.
The "discard N bytes" information appears in the `discard` field of the `AppDataRecord` struct.
All the `discard` information needs be "collected", that is summed up, and executed all at once after `state` has been consumed.
It's less efficient (as in, it requires more CPU cycles) to discard one TLS record at a time while iterating `AppDataAvailable` but this is not possible because of borrow checking:
`AppDataAvailable` mutably borrows the `incoming_tls` so `incoming_tls` can only be modified after `AppDataAvailable` goes out of scope.

# `read_buf` API (`Borrowed{Buf,Cursor}`) support

The proposed API is compatible with the `read_buf` API as is.
The end-user-side changes required to use the `read_buf` API are shown below:

```rust
let mut conn: LlClientConnection;
let mut sock: std::net::TcpStream;

// .. configure / inititiaize `conn` and `sock`

let mut incoming_tls = [MaybeUninit::uninit(); 16 * 1024];
let mut incoming_tls = BorrowedBuf::from(&mut incoming_tls[..]);
let mut incoming_used = 0;

let mut outgoing_tls = Vec::new();
let mut outgoing_used = 0;

loop {
    let Status { mut discard, state } = conn.process_tls_records(&incoming_tls);

    match state {
        // no change in the handling of these states
        State::AppDataAvailable(state) => { /* .. */ }
        State::EarlyDataAvailable(state) => { /* .. */ }
        State::MayEncryptAppData(state) => { /* .. */ }
        State::MayEncryptEarlyData(state) => { /* .. */ }
        State::MustEncryptTlsData(state) => { /* .. */ }
        State::MustTransmitTlsData(state) => { /* .. */ }
        State::TrafficTransit(state) => { /* .. */ }

        State::NeedsMoreTlsData { .. } => {
            let read = sock.read_buf(incoming_tls.unfilled())?;
            //              ^^^^^^^^             ^^^^^^^^^^^
            incoming_used += read;
        }

    }

    // discard TLS records
    if discard != 0 {
        incoming_tls
            .filled_mut() // <-
            .copy_within(discard..incoming_used, 0);

        incoming_tls.clear(); // <-
        unsafe {
            incoming_tls.unfilled().advance(incoming_used - discard); // <-
        }

        incoming_used -= discard;
    }
}
```

# Supporting async certificate verification

In the API described thus far the certificate verification still happens implicitly in `process_tls_records`.

To support both blocking and async certificate verification without "coloring" the API, the API will be revised as follows:

- `LlClientConnection` and `LlServerConnection` will not implicitly perform certificate verification
- `LlClientConnection` and `LlServerConnection` will not contain a `ServerCertVerifier` / `ClientCertVerifier` trait object
- `CertificateVerifier` will be a separate object that the user of the `LlConnection` API must manage
- `State` will gain variants related to the certificate verification process

Letting the end-user manage the certificate verification process means that they can decide whether to perform it in a blocking fashion, either serially, concurrently using `select` or in parallel using `thread::spawn`; or asynchronously, either concurrently using `join!` / `select!` / `FuturesUnordered` or in parallel using `task::spawn`.

The other key aspect is that `LlConnection` will _not_ invoke methods on a `CertVerifier` object but instead expect its results to come in as values / data.
This means the `LlConnection` API will not include trait bounds on traits like `ServerCertVerifier`;
this avoids both "coloring" the `LlConnection` API and the need for creating an async version of the `*CertVerifier` traits.

The required changes to the `LlConnection` are described in the following sections.

> NOTE this proposal does not require that `LlConnection` is implemented in two steps / stages.
> The two-stage structure of this document is mainly used to avoid presenting a lot of details to the reader upfront.

## New `State` variants

`State` gains the following variants:

```rust
pub enum State<'c, 'i> {
    // ..

    /// the supported verify schemes must be provided using to continue with the handshake
    NeedsSupportedVerifySchemes(NeedsSupportedVerifySchemes<'c>),

    /// Received a `Certificate` message
    ReceivedCertificate(ReceivedCertificate<'c, 'i>),

    /// Received a `ServerKeyExchange` (TLS 1.2) / `CertificateVerify` (TLS 1.3) message
    ReceivedSignature(ReceivedSignature<'c, 'i>),

    /// Needs to send back the `message` signed. provide it with the either `handshake_signature`
    NeedsSignature(NeedsSignature<'c>),
}
```

The API of these new states are covered in the following subsections

### `NeedsSupportedVerifySchemes`

This state provides a method to pass in the verify schemes supported by a certificate verifier.

```rust
impl<'c> NeedsSupportedVerifySchemes<'c> {
    /// Provide the verify schemes supported by the certificate verifier
    pub fn add_supported_verify_schemes(self, schemes: Vec<SignatureScheme>) { /* .. */ }
}
```

### `ReceivedCertificate`

This state provides a method to decrypt the contents of the received Certificate record.

```rust
impl<'c, 'i> ReceivedCertificate<'c, 'i> {
    /// Decrypts the received Certificate record and returns an iterator over the
    /// certificate entries contained in it
    pub fn decrypt(self) -> impl Iterator<Item = Result<CertificateEntry<'i>>, crate::Error> { /* .. */ }
}
```

To keep in line with non-allocating behavior of the rest of the API,
this proposal _suggests_ tweaking the `CertificateEntry` type to support both the current allocating version and a new lazy / non-allocating version.
Such change would likely be a **breaking change** as it requires adding a lifetime parameter to several types.

Current allocating version:

```rust
pub struct CertificateEntry {
    pub cert: Certificate,
    pub exts: Vec<CertificateExtension>,
}

pub struct Certificate(pub Vec<u8>);

pub enum CertificateExtension {
    CertificateStatus(CertificateStatus),
    Unknown(UnknownExtension),
}

pub struct CertificateStatus {
    pub ocsp_response: PayloadU24,
}

pub struct PayloadU24(pub Vec<u8>);

pub struct UnknownExtension {
    pub typ: ExtensionType,
    pub payload: Payload,
}

#[derive(Clone, Copy)]
pub enum ExtensionType { /* .. */  }

pub struct Payload(pub Vec<u8>);
```

New non-allocating version:

```rust
pub struct CertificateEntry<'i> {
    pub cert: Certificate<'i>,
    pub exts: /* a concrete iterator? (not a boxed trait object) */ <CertificateExtension<'i>>,
}

pub struct Certificate<i>(pub Cow<'i, [u8]>);

pub enum CertificateExtension<'i> {
    CertificateStatus(CertificateStatus<'i>),
    Unknown(UnknownExtension<'i>),
}

pub struct CertificateStatus<'i> {
    pub ocsp_response: PayloadU24<'i>,
}

pub struct PayloadU24<'i>(pub Cow<'i, [u8]>);

pub struct UnknownExtension<'i> {
    pub typ: ExtensionType,
    pub payload: Payload<'i>,
}

#[derive(Clone, Copy)]
pub enum ExtensionType { /* .. */  }

pub struct Payload<'i>(pub Cow<'i, [u8]>);
```

### `ReceivedSignature`

This state provides a method to decrypt the contents of the received ServerKeyExchange / CertificateVerify record.

```rust
impl<'c, 'i> ReceivedSignature<'c, 'i> {
    pub fn decrypt(self) -> Result<DigitallySignedStruct<'i>, crate::Error> { /* .. */ }
}
```

Like in the previous section,
this proposal suggests tweaking the `DigitallySignedStruct` type to support non-allocating decoding.
This change will, likely, also be a **breaking change**.

Current, allocating version:

```rust
pub struct DigitallySignedStruct {
    pub scheme: SignatureScheme,
    sig: PayloadU16,
}

#[derive(Clone, Copy)]
pub enum SignatureScheme { /* .. */ }

pub struct PayloadU16(pub Vec<u8>);
```

New, non-allocating version:

```rust
pub struct DigitallySignedStruct<'i> {
    pub scheme: SignatureScheme,
    sig: PayloadU16<'i>,
}

#[derive(Clone, Copy)]
pub enum SignatureScheme { /* .. */ }

pub struct PayloadU16<'i>(pub Cow<'i, [u8]>);
```

### `NeedsSignature`

This state indicates that certificate verification process needs to be completed to continue with the handshake process.
The type provides the following methods:

```rust
pub enum VerificationOutcome {
    Valid {
        cert_verified: ServerCertVerified,
        sig_verified: HandshakeSignatureValid,
    },

    Failed,
}

impl<'c> NeedsSignature<'c> {
    /// The message that needs to be signed
    pub fn message(&self) -> &'c [u8] { /* .. */ }

    /// The negotiated protocol version
    pub fn protocol_version(&self) -> ProtocolVersion { /* .. */ }

    /// Provide the outcome of the certificate verification process
    pub fn done(self, _verification_outcome: VerificationOutcome) { /* .. */ }
}
```

`message` returns the message that needs to be signed as part of the certificate verification process.

`protocol_version` returns the TLS version that has been negotiated.

`done` accepts the outcome of the certificate verification process.

## Non-async event loop example

This section presents an updated event loop that handles the new states.
This example uses the `ServerCertVerifier` trait methods but that is not strictly required.

```rust
let server_name: ServerName;
let mut cert_verifier: WebPkiServerCertVerifier;
let mut conn: LlClientConnection;
let mut socket: std::net::TcpStream;

// .. configure / inititiaize the above variables

let mut incoming_tls = [0; 16 * 1024];
let mut incoming_used = 0;

let mut outgoing_tls = Vec::new();
let mut outgoing_used = 0;

let mut certificate_entries: Vec<CertificateEntry> = vec![];
let mut dss: Option<DigitallySignedStruct> = None;

loop {
    let Status { mut discard, state } = conn.process_tls_records(&incoming_tls);

    match state {
        // omitting states unrelated to certificate verification, which have already been
        // covered in a previous example

        State::NeedsSupportedVerifySchemes(state) => {
            let schemes = cert_verifier.supported_verify_schemes();
            state.add_supported_verify_schemes(schemes);
        }

        State::ReceivedCertificate(state) => {
            let new_entries: Vec<_> = state.decrypt().map(/* to_owned */).collect()?;
            certificate_entries.extend(new_entries);
        }

        State::ReceivedSignature(state) => {
            let new_dss = state.decrypt()?;
            dss = Some(new_dss.to_owned());
        }

        State::NeedsSignature(state) => {
            let res = (|| {
                let dss = dss.as_ref()?;
                let (end_entity, intermediates) = split(&mut certificate_entries)?;
                let oscp_response = extract_ocsp_response(&end_entity).unwrap_or(&[]);

                let cert_verified = cert_verifier.verify_server_cert(
                    &end_entity.cert,
                    &intermediates,
                    server_name,
                    ocsp_response,
                ).ok()?;

                let protocol_version = state.protocol_version();
                let message = state.message();
                let sig_verified = match protocol_version {
                    ProtocolVersion::TLSv1_2 => {
                        cert_verifier.verify_tls12_signature(message, &end_entity.cert, dss)
                    }

                    ProtocolVersion::TLSv1_3 => {
                        cert_verifier.verify_tls13_signature(message, &end_entity.cert, dss)
                    }

                    _ => return None,
                };

                Some((cert_verified, sig_verified.ok()?))
            })();

            let outcome = match res {
                Some((cert_verified, sig_verified)) => CertificateVerificationOutcome::Success {
                    cert_verified,
                    sig_verified,
                }

                None = CertificateVerificationOutcome::Failure,
            };

            state.done(outcome);
        }
    }

    // omitting the discard operation which has been covered in a previous example
}
```

## Multi-threaded async event loop example

This example demonstrates how to perform the certificate verification in parallel using a multi-threaded async runtime.
`AsyncPlatformVerifier` is a made-up certificate verifier.

```rust
let server_name: ServerName;
let mut conn: LlClientConnection;
let mut socket: std::net::TcpStream;
let mut cert_verifier: AsyncPlatformVerifier; // <- DIFFERENT

// .. configure / inititiaize the above variables

let mut incoming_tls = [0; 16 * 1024];
let mut incoming_used = 0;

let mut outgoing_tls = Vec::new();
let mut outgoing_used = 0;

let mut dss: Option<DigitallySignedStruct> = None;

let mut cert_verifier = Some(cert_verifier); // <- NEW
let mut handle: Option<JoinHandle<_>> = None; // <- NEW

loop {
    let Status { mut discard, state } = conn.process_tls_records(&incoming_tls);

    match state {
        // omitting states unrelated to certificate verification, which have already been
        // covered in a previous example

        // no change in how these states are handled
        State::NeedsSupportedVerifySchemes(state) => { /* .. */ }
        State::ReceivedSignature(state) => { /* .. */ }

        State::ReceivedCertificate(state) => {
            let mut certificate_entries: Vec<_> = state.decrypt().map(/* to_owned */).collect()?;
            let mut cert_verifier = cert_verifier.take().ok_or(/* relevant error type */)?;

            handle = Some(task::spawn(async move {
                let (end_entity, intermediates) = split(&mut certificate_entries)?;

                let oscp_response = extract_ocsp_response(&end_entity).unwrap_or(&[]);

                let cert_verified = cert_verifier.async_verify_server_cert(
                    &end_entity.cert,
                    &intermediates,
                    server_name,
                    ocsp_response,
                ).await.ok()?;

                Some((cert_verifier, cert_verified, end_entity))
            }));
        }

        State::NeedsSignature(state) => {
            let mut opt = if let Some(handle) = handle.take() {
                handle.await
            } else {
                None
            };

            let res = (|| {
                let dss = dss.as_ref()?;

                let (cert_verifier, cert_verified, end_entity) = opt.take()?;

                let protocol_version = state.protocol_version();
                let message = state.message();

                let sig_verified = match protocol_version {
                    ProtocolVersion::TLSv1_2 => {
                        cert_verifier.verify_tls12_signature(message, &end_entity.cert, dss)
                    }

                    ProtocolVersion::TLSv1_3 => {
                        cert_verifier.verify_tls13_signature(message, &end_entity.cert, dss)
                    }

                    _ => return None,
                };

                Some((cert_verified, sig_verified.ok()?))
            })();

            let outcome = match res {
                Some((cert_verified, sig_verified)) => CertificateVerificationOutcome::Success {
                    cert_verified,
                    sig_verified,
                }

                None = CertificateVerificationOutcome::Failure,
            };

            state.done(outcome);
        }
    }

    // omitting the discard operation which has been covered in a previous example
}
```

Note that some (most?) async runtimes provide a task API with "detach on drop" semantics.
To not waste resources, the handling of any fatal error while the async task is in flight should also cancel the task.

## The `dangerous_configuration` feature

The proposed API requires making types like `ServerCertVerified`, `HandshakeSignatureValid`, etc. public.
These types are currently gated behind the `dangerous_configuration` Cargo feature.

The needed types will become public regardless of the state of the `dangerous_configuration` feature but
their constructors, for example `ServerCertVerified::assertion`, will continue to be feature gated.

# Alternatives

## `IncomingTls` newtype

In a previous iteration of this RFC,
the `incoming_tls` parameter was not a plain slice but a newtype over a generic slice: `IncomingTls`.

The `IncomingTls` API was basically a public version of the `buf` and `used` fields of the private `MessageDeframer` type.
It made the usage of the `LlConnection` a bit easier because it provided a method that handled discarding records from the front of the buffer (see the `MessageDeframer::discard` method).

Because `IncomingTls` was generic over the underlying buffer (`B: AsRef<[u8]> + AsMut<[u8]>`) it supported both `[u8]` and `Vec`;
however it wasn't clear how to make it support the `read_buf` types: `Borrowed{Buf,Cursor}`.
Chances are the `BorrowedBuf` type would need to be in the `IncomingTls` struct, perhaps using an `enum`;
as the `Borrowed*` types are only available in libstd that would have lead to the use of conditional compilation (`cfg(feature = "std")`), which makes the implementation more complex.

The current proposal uses `&mut [u8]` as the type of the `incoming_tls` parameter and it's compatible with the `read_buf` API without any conditional compilation.
It does require however that the `MessageDeframer::discard` functionality is implemented by the end user so that's the trade-off.

For more details about the `IncomingTls` API, check the older revisions of this branch / PR.

# Unresolved questions

are more variants required in `State` to support server-side verification of client certificates?

are more variants required in `State` to support the `EncryptedClientHello` (ECH) extension?

should `EarlyDataAvailable` provide a `discard` method to discard the early data record _without_ decrypting it first?

can several early-data records appear in a single, e.g. TCP, packet? if yes, should `EarlyDataAvailable` become an iterator like `AppDataAvailable`?

should the 'close notify' alert record be reported as a new, separate `State` variant, say `State::ConnectionClosed`?

during the handshake, is it _always_ possible to send encrypted application data back after encrypted application data has been received? if yes, then the `AppDataAvailable` type should provide an `encrypt(app_data, outgoing_tls)` method.

is it possible to receive a _non-fatal_ Alert record after the handshake has been finished and "sandwich-ed" between app-data records? if yes, how should these be handled by the `AppDataAvailable` type? some options:

- yield `None` when one of these Alert record is found and let `process_tls_record` handle it
- yield `Some(AppDataRecord { discard: /* alert record size */, payload: &[] })`
- don't yield an `AppDataRecord` for the Alert record but include its `discard` size into the `discard` field of the next `AppDataRecord`

# References

- Comments in the GitHub issue ["Allow for more flexible buffer management"][gh1362]
- Brian Smith's [comment][gh850] on making certificate verification async

[gh850]: https://github.com/rustls/rustls/issues/850#issuecomment-999798205
