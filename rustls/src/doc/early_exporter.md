Returns the "early" exporter that can derive key material for use in early data

See [RFC 5705][] for general details on what exporters are, and [RFC 9846 S7.5][] for
specific details on the "early" exporter.

**Beware** that the early exporter requires care, as it is subject to the same
potential for replay as early data itself.  See [RFC 9846 appendix F.5.1][] for
more detail.

This function can be called at most once per connection. This function will error
if called more than once per connection.

If you are looking for the normal exporter, this is available from
[`Connection::exporter()`].

[RFC 5705]: https://datatracker.ietf.org/doc/html/rfc5705
[RFC 9846 S7.5]: https://datatracker.ietf.org/doc/html/rfc9846#section-7.5
[RFC 9846 appendix F.5.1]: https://datatracker.ietf.org/doc/html/rfc9846#appendix-F.5.1
[`Connection::exporter()`]: crate::conn::Connection::exporter()
