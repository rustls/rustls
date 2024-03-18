# Rustls Test CA

This directory contains various test certificate authorities, intermediates,
end-entity, and client certificates that are used by Rustls integration tests.

You can regenerate the data in this directory by running the
`rustls/examples/internal/test_ca.rs` tool:

```bash
cargo run -p rustls --example test_ca
```
