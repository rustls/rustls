.PHONY: perf perffull perf13 measure memory clean

RECORD=perf record -F2000 --call-graph dwarf,16000 --
FLAMEGRAPH=perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl >
MEMUSAGE=/usr/bin/env time -f %M
BENCH:=./target/release/examples/bench

perf: $(BENCH)
	$(RECORD) $(BENCH) bulk TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	$(FLAMEGRAPH) perf-aes128-rustls.svg

perffull: $(BENCH)
	$(RECORD) $(BENCH) bulk TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	$(FLAMEGRAPH) perf-aes256-rustls.svg
	$(RECORD) $(BENCH) bulk TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	$(FLAMEGRAPH) perf-chacha-rustls.svg
	$(RECORD) $(BENCH) handshake TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	$(FLAMEGRAPH) perf-fullhs-rustls.svg
	$(RECORD) $(BENCH) handshake-resume TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	$(FLAMEGRAPH) perf-resume-rustls.svg
	$(RECORD) $(BENCH) handshake-ticket TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	$(FLAMEGRAPH) perf-ticket-rustls.svg

perf13:
	$(RECORD) $(BENCH) handshake-ticket TLS13_AES_256_GCM_SHA384
	$(FLAMEGRAPH) perf-ticket13-rustls.svg

measure: $(BENCH)
	$^ bulk TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	$^ bulk TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	$^ bulk TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	$^ bulk TLS13_AES_256_GCM_SHA384
	$^ handshake TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	$^ handshake TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	$^ handshake-resume TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	$^ handshake-ticket TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	$^ handshake TLS13_AES_256_GCM_SHA384
	$^ handshake-resume TLS13_AES_256_GCM_SHA384
	$^ handshake-ticket TLS13_AES_256_GCM_SHA384

memory: $(BENCH)
	$(MEMUSAGE) $^ memory TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 100
	$(MEMUSAGE) $^ memory TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 1000
	$(MEMUSAGE) $^ memory TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 5000
	$(MEMUSAGE) $^ memory TLS13_AES_256_GCM_SHA384 100
	$(MEMUSAGE) $^ memory TLS13_AES_256_GCM_SHA384 1000
	$(MEMUSAGE) $^ memory TLS13_AES_256_GCM_SHA384 5000

clean:
	rm -f perf-*.svg
	cargo clean

$(BENCH): .FORCE
	cargo build --profile=bench -p rustls --example bench

.FORCE:
