# `sketch`

This is a mock implementation of the the API described in the 'caller-managed buffers' RFC.

The crate includes a few unit tests that you can run locally with:

```console
$ cargo t -- --nocapture client

$ cargo t -- --nocapture server
```

The unit tests print logs that match [logs collected from running][logs-branch] the `tlsclient-mio` and `tlsserver-mio` examples in the rustls (v0.21.6) repository.

[logs-branch]: https://github.com/japaric/rustls/tree/logs/examples

In addition to the unit tests, a re-implementation of the `rustls::Stream` on top of the proposed `LlConnection` API is included in the `stream.rs` file.
This re-implementation does not include tests.

## Sequence diagrams

### TLS 1.3

The unit tests replicate this exchange between `tlsclient-mio` and `tlsserver-mio`.
The numbers of bytes in the unit tests logs and this sequence diagram may not match exactly.

```mermaid
sequenceDiagram
  participant ServerCertVerifier
  participant HTTPClient

  HTTPClient ->> ClientConnection: ApplicationData/Request (81B)
  ClientConnection ->> ServerCertVerifier: supported_verify_schemes()
  ClientConnection ->> ServerBuffers: HS::ClientHello (236B)
  ServerBuffers ->> ClientBuffers: write_tls / read_tls (236B)

  ClientBuffers ->> ServerConnection: HS::ClientHello (231B)
  ServerConnection ->> ClientBuffers: HS::ServerHello (127B)
  ServerConnection ->> ClientBuffers: ChangeCipherSpec (6B)
  ServerConnection ->> ClientBuffers: [encr]HS::EncryptedExtensions (27B)
  ServerConnection ->> ClientBuffers: [encr]HS::Certificate (1,050B)
  ServerConnection ->> ClientBuffers: [encr]HS::CertificateVerify (281B)
  ServerConnection ->> ClientBuffers: [encr]HS::Finished (69B)
  ClientBuffers ->> ServerBuffers: write_tls / read_tls (1580B)

  ServerBuffers ->> ClientConnection: HS::ServerHello (122B)
  ClientConnection ->> ServerBuffers: ChangeCipherSpec (6B)
  ServerBuffers ->> ClientConnection: ChangeCipherSpec (1B)
  ServerBuffers ->> ClientConnection: [encr]HS::EncryptedExtensions (27B)
  ServerBuffers ->> ClientConnection: [encr]HS::Certificate (1,050B)
  ServerBuffers ->> ClientConnection: [encr]HS::CertificateVerify (281B)
  ClientConnection ->> ServerCertVerifier: verify_server_cert(..)
  ClientConnection ->> ServerCertVerifier: verify_tls13_signature(..)
  ServerBuffers ->> ClientConnection: [encr]HS::Finished (69B)
  ClientConnection ->> ServerBuffers: [encr]HS::Finished (69B)
  ClientConnection ->> ServerBuffers: [encr]ApplicationData/Request (98B)
  ServerBuffers ->> ClientBuffers: write_tls / read_tls (183B)

  ClientBuffers ->> ServerConnection: ChangeCipherSpec (1B)
  ClientBuffers ->> ServerConnection: [encr]HS::Finished (69B)
  ServerConnection ->> ClientBuffers: [encr]HS::NewSessionTicket (98B)
  ServerConnection ->> ClientBuffers: [encr]HS::NewSessionTicket (98B)
  ServerConnection ->> ClientBuffers: [encr]HS::NewSessionTicket (98B)
  ServerConnection ->> ClientBuffers: [encr]HS::NewSessionTicket (98B)
  ClientBuffers ->> ServerConnection: [encr]ApplicationData/Request (98B)
  ServerConnection ->> HTTPServer: ApplicationData/Request (81B)
  HTTPServer ->> ServerConnection: ApplicationData/Response (73B)
  ServerConnection ->> ClientBuffers: [encr]ApplicationData (95B)
  ServerConnection ->> ClientBuffers: [encr]Alert (19B)
  ClientBuffers ->> ServerBuffers: write_tls / read_tls (531B)

  ServerBuffers ->> ClientConnection: [encr]HS::NewSessionTicket (98B)
  ServerBuffers ->> ClientConnection: [encr]HS::NewSessionTicket (98B)
  ServerBuffers ->> ClientConnection: [encr]HS::NewSessionTicket (98B)
  ServerBuffers ->> ClientConnection: [encr]HS::NewSessionTicket (98B)
  ServerBuffers ->> ClientConnection: [encr]ApplicationData (90B)
  ServerBuffers ->> ClientConnection: [encr]Alert (19B)

  ClientConnection ->> HTTPClient: ApplicationData/Response (73B)
```
