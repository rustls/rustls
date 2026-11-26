Returns an object that can derive key material from the agreed connection secrets.

See [RFC 5705][] for more details on what this is for.

This function can be called at most once per connection.

This function will error:

- if called prior to the handshake completing; (check with
  [`CommonState::is_handshaking`][crate::CommonState::is_handshaking] first).
- if called more than once per connection.
- for TLS1.2 connections that did not negotiate the extended main secret
  extension ([RFC 7627 section 5.4][]); (check with
  [`ConnectionOutputs::extended_main_secret`][crate::ConnectionOutputs::extended_main_secret] first).

[RFC 5705]: https://www.rfc-editor.org/info/rfc5705
[RFC 7627 section 5.4]: https://www.rfc-editor.org/info/rfc7627#section-5.4
