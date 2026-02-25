.PHONY: perf perffull perf13 measure memory clean

RECORD=perf record -F2000 --call-graph dwarf,16000 --
FLAMEGRAPH=perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl >
MEMUSAGE=/usr/bin/env time -f %M
BENCH:=./target/release/rustls-bench
PROVIDER:=aws-lc-rs

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
	$^ --key-type rsa2048 bulk TLS13_AES_256_GCM_SHA384
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

threads: $(BENCH)
	for t in $(shell admin/threads-seq.rs) ; do \
	  $^ --threads $$t handshake TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ; \
	  $^ --threads $$t handshake-resume TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ; \
	  $^ --threads $$t handshake-ticket TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ; \
	  $^ --key-type rsa2048 --threads $$t handshake TLS13_AES_256_GCM_SHA384 ; \
	  $^ --threads $$t handshake-ticket TLS13_AES_256_GCM_SHA384 ; \
	  $^ --threads $$t bulk TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ; \
	  $^ --key-type rsa2048 --threads $$t bulk TLS13_AES_256_GCM_SHA384 ; \
	done

thread-latency: $(BENCH)
	$^ --threads $$(nproc) --api buffered --key-type rsa2048 --latency-prefix latency-fullhs-tls12 handshake TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	$^ --threads $$(nproc) --api buffered --key-type rsa2048 --latency-prefix latency-fullhs-tls13 handshake TLS13_AES_256_GCM_SHA384
	$^ --threads $$(nproc) --api buffered --key-type rsa2048 --latency-prefix latency-resume-tls12 handshake-resume TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	$^ --threads $$(nproc) --api buffered --key-type rsa2048 --latency-prefix latency-resume-tls13 handshake-ticket TLS13_AES_256_GCM_SHA384

clean:
	rm -f perf-*.svg
	cargo clean

$(BENCH): .FORCE
	cargo build --release -p rustls-bench --features $(PROVIDER)

.FORCE:
