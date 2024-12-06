#!/bin/bash

# nb:
# - symcrypt: weird allocator failure during first handshake
# - wolfcrypt: panics loading rsa keys
set -xe

for prov in aws-lc-rs boringssl graviola mbedtls openssl ring rustcrypto; do
    if [ "$prov" == "mbedtls" ] ; then
        export BENCH_MULTIPLIER=2
    else
        export BENCH_MULTIPLIER=8
    fi

    make -f admin/bench-measure.mk measure PROVIDER=$prov | tee result-$prov.txt
done
