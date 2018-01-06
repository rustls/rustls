perf: ./target/release/examples/bench
	perf record -F9999 --call-graph dwarf -- ./target/release/examples/bench bulk TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf-aes128-rustls.svg

perffull: ./target/release/examples/bench
	perf record -F9999 --call-graph dwarf -- ./target/release/examples/bench bulk TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf-aes256-rustls.svg
	perf record -F9999 --call-graph dwarf -- ./target/release/examples/bench bulk TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf-chacha-rustls.svg
	
	perf record -F9999 --call-graph dwarf -- ./target/release/examples/bench handshake TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf-fullhs-rustls.svg
	perf record -F9999 --call-graph dwarf -- ./target/release/examples/bench handshake-resume TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf-resume-rustls.svg
	perf record -F9999 --call-graph dwarf -- ./target/release/examples/bench handshake-ticket TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf-ticket-rustls.svg

measure: ./target/release/examples/bench
	$^ bulk TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	$^ bulk TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	$^ bulk TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	$^ handshake TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	$^ handshake-resume TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	$^ handshake-ticket TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
