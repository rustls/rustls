Returns an object that can derive key material from the agreed connection secrets.

See [RFC 5705][] for more details on what this is for.

This function can be called at most once per connection.

This function will error:

- if called prior to the handshake completing; (check with
  [`CommonState::is_handshaking`] first).
- if called more than once per connection.

[RFC 5705]: https://datatracker.ietf.org/doc/html/rfc5705
