#!/bin/sh

set -xe

rm -rf rsa/ ecdsa/
mkdir -p rsa/ ecdsa/

openssl req -nodes \
          -x509 \
          -newkey rsa:8192 \
          -keyout rsa/ca.key \
          -out rsa/ca.cert \
          -sha256 \
          -batch \
          -subj "/CN=ponytown RSA CA"

openssl req -nodes \
          -newkey rsa:3072 \
          -keyout rsa/inter.key \
          -out rsa/inter.req \
          -sha256 \
          -batch \
          -subj "/CN=ponytown RSA level 2 intermediate"

openssl req -nodes \
          -newkey rsa:2048 \
          -keyout rsa/end.key \
          -out rsa/end.req \
          -sha256 \
          -batch \
          -subj "/CN=testserver.com"

# ecdsa
openssl ecparam -name prime256v1 -out ecdsa/nistp256.pem
openssl ecparam -name secp384r1 -out ecdsa/nistp384.pem

openssl req -nodes \
          -x509 \
          -newkey ec:ecdsa/nistp384.pem \
          -keyout ecdsa/ca.key \
          -out ecdsa/ca.cert \
          -sha256 \
          -batch \
          -subj "/CN=ponytown ECDSA CA"

openssl req -nodes \
          -newkey ec:ecdsa/nistp256.pem \
          -keyout ecdsa/inter.key \
          -out ecdsa/inter.req \
          -sha256 \
          -batch \
          -subj "/CN=ponytown ECDSA level 2 intermediate"

openssl req -nodes \
          -newkey ec:ecdsa/nistp256.pem \
          -keyout ecdsa/end.key \
          -out ecdsa/end.req \
          -sha256 \
          -batch \
          -subj "/CN=testserver.com"

for kt in rsa ecdsa ; do
  openssl x509 -req \
            -in $kt/inter.req \
            -out $kt/inter.cert \
            -CA $kt/ca.cert \
            -CAkey $kt/ca.key \
            -sha256 \
            -set_serial 123 \
            -extensions v3_inter -extfile openssl.cnf

  openssl x509 -req \
            -in $kt/end.req \
            -out $kt/end.cert \
            -CA $kt/inter.cert \
            -CAkey $kt/inter.key \
            -sha256 \
            -set_serial 456 \
            -extensions v3_end -extfile openssl.cnf

  cat $kt/inter.cert $kt/ca.cert > $kt/end.chain
  openssl asn1parse -in $kt/ca.cert -out $kt/ca.der > /dev/null
done
