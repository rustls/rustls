## How to run the example on `STM32f429ZI` 

Install `probe-rs` or `probe-run`, and choose one runner in `.cargo/config.toml`

```toml
#runner = "probe-rs run --chip STM32F429ZITx"
runner = "probe-run --chip STM32F429ZITx"
```

Connect the dev kit to ethernet on the same network than your computer.
Run the demo with `cargo run --release`

## TLS version

The demo works with `TLS1.3`.

## HEAP

Run the demo in `release` mode.

The maximum usable heap size is `const HEAP_SIZE: usize = 25 * KB + 11*1024;`; to test `github.com` we only need `25 KB`; however `www.google.com` needs 
`36 KB`. If you increase further the size of the heap you will have an unrecoverable error (`HardFault`)!

```bash
TRACE 4533B in incoming TLS buffer
└─ no_std_embedded_demo::converse::{async_fn#0} @ src/main.rs:188
────────────────────────────────────────────────────────────────────────────────
stack backtrace:
   0: HardFaultTrampoline
      <exception entry>
   1: cortex_m::asm::inline::__udf
        at /home/aissata/.cargo/registry/src/index.crates.io-6f17d22bba15001f/cortex-m-0.7.7/src/../asm/inline.rs:181:5
   2: cortex_m::asm::udf
```

## DHCP

DHCP sometimes fail and also cause a `Hardfault` as above. You can try the default configuration.
If it doesn't work, replace the placeholders with your device and router IP (must be on the same network).
Use static resolution and replace `gateway` with your router address, and 

```rust
// Dynamic resolution sometimes provokes a stack overflow down the line.
// If it doesn't work, choose your router address as a `gateway`
//let net_config = embassy_net::Config::dhcpv4(Default::default());
let mut dns_servers = heapless::Vec::new();
let _ = dns_servers.push(Ipv4Address::new(1, 1, 1, 1).into());

let net_config = embassy_net::Config::ipv4_static(embassy_net::StaticConfigV4 {
    // your devide IP, on the same network vvvvvvvvvvvvvvvvvvv
    address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 50, 204), 24),
    dns_servers,
    // your router IP address here    vvvvvvvvvvvvvvvvvvvvvvvvvv
    gateway: Some(Ipv4Address::new(192, 168, 50, 1)),
});
```


## X25519 ECDH issue

At time of writing, `example.com` doesn't support X25519 ECDH, which is the only SupportedKxGroup the CryptoProvider sets. The test will work for:
- `github.com`
- `www.cloudflare.com`
- `www.google.com`

Running this code with `example.com` will cause `ERROR Rustls(AlertReceived(HandshakeFailure))`.

## Cargo.toml

TODO: edit your `Cargo.toml` when [PR 1502](https://github.com/rustls/rustls/pull/1502) is merged. It is now depending on a custom branch:

```toml
rustls = { git = "https://github.com/japaric/rustls", branch = "no-std-support", default-features = false, features = [
    "tls12",
] }
```

## Logs

We included logs of a successful run (`log_github.txt`) and a log with the `HandshakeFailure` when trying to connect to example.com (`log_example.txt`).

## rust-toolchain

The toolchain version is set in the [`embassy`](https://github.com/embassy-rs/embassy/blob/main/rust-toolchain.toml) project.
