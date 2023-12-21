#!/usr/bin/env bash

set -xe

rm -rf rsa/ ecdsa-p256/ ecdsa-p384/ ecdsa-p521/ eddsa/
mkdir -p rsa/ ecdsa-p256/ ecdsa-p384/ ecdsa-p521/ eddsa/

openssl req -nodes \
          -x509 \
          -days 3650 \
          -newkey rsa:4096 \
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

openssl rsa \
          -in rsa/end.key \
          -out rsa/end.rsa

openssl req -nodes \
          -newkey rsa:2048 \
          -keyout rsa/client.key \
          -out rsa/client.req \
          -sha256 \
          -batch \
          -subj "/CN=ponytown client"

openssl rsa \
          -in rsa/client.key \
          -out rsa/client.rsa

# ecdsa
for curve in p256 p384 p521 ; do
    case $curve in
      p256)
        openssl ecparam -name prime256v1 -out ecdsa-$curve/curve.pem
        ;;
      p384)
        openssl ecparam -name secp384r1 -out ecdsa-$curve/curve.pem
        ;;
      p521)
        openssl ecparam -name secp521r1 -out ecdsa-$curve/curve.pem
        ;;
    esac

    openssl req -nodes \
              -x509 \
              -newkey ec:ecdsa-$curve/curve.pem \
              -keyout ecdsa-$curve/ca.key \
              -out ecdsa-$curve/ca.cert \
              -sha256 \
              -batch \
              -days 3650 \
              -subj "/CN=ponytown ECDSA $curve CA"

    openssl req -nodes \
              -newkey ec:ecdsa-$curve/curve.pem \
              -keyout ecdsa-$curve/inter.key \
              -out ecdsa-$curve/inter.req \
              -sha256 \
              -batch \
              -days 3000 \
              -subj "/CN=ponytown ECDSA $curve level 2 intermediate"

    openssl req -nodes \
              -newkey ec:ecdsa-$curve/curve.pem \
              -keyout ecdsa-$curve/end.key \
              -out ecdsa-$curve/end.req \
              -sha256 \
              -batch \
              -days 2000 \
              -subj "/CN=testserver.com"

    openssl req -nodes \
              -newkey ec:ecdsa-$curve/curve.pem \
              -keyout ecdsa-$curve/client.key \
              -out ecdsa-$curve/client.req \
              -sha256 \
              -batch \
              -days 2000 \
              -subj "/CN=ponytown client"
done

# eddsa

# TODO: add support for Ed448
# openssl genpkey -algorithm Ed448 -out eddsa/ca.key
openssl genpkey -algorithm Ed25519 -out eddsa/ca.key

openssl req -nodes \
          -x509 \
          -key eddsa/ca.key \
          -out eddsa/ca.cert \
          -sha256 \
          -batch \
          -days 3650 \
          -subj "/CN=ponytown EdDSA CA"

openssl genpkey -algorithm Ed25519 -out eddsa/inter.key

openssl req -nodes \
          -new \
          -key eddsa/inter.key \
          -out eddsa/inter.req \
          -sha256 \
          -batch \
          -subj "/CN=ponytown EdDSA level 2 intermediate"

openssl genpkey -algorithm Ed25519 -out eddsa/end.key

openssl req -nodes \
          -new \
          -key eddsa/end.key \
          -out eddsa/end.req \
          -sha256 \
          -batch \
          -subj "/CN=testserver.com"

# TODO: add support for Ed448
# openssl genpkey -algorithm Ed448 -out eddsa/client.key
openssl genpkey -algorithm Ed25519 -out eddsa/client.key

openssl req -nodes \
          -new \
          -key eddsa/client.key \
          -out eddsa/client.req \
          -sha256 \
          -batch \
          -subj "/CN=ponytown client"

# Generate a CRL revoking a specific certificate, signed by the specified issuer.
# Arguments:
#  1. the key type (e.g. "rsa")
#  2. signature hash algorithm (e.g. "sha256")
#  3. the name of the issuer (e.g. "inter")
#  4. the name of the certificate to revoke (e.g. "end")
function gen_crl {
  local kt=$1
  local hash=$2
  local issuer_name=$3
  local revoked_cert_name=$4

  # Overwrite the CA state for each revocation - this avoids an
  # "already revoked" error since we're re-using serial numbers across
  # key types.
  echo -n '' > index.txt
  echo '1000' > crlnumber

  # Revoke the certificate in the openssl CA index. This produces a CRL but
  # doesn't include the revoked certificate in the CRL...
  openssl ca \
            -config ./crl-openssl.cnf \
            -keyfile "$kt/$issuer_name.key" \
            -cert "$kt/$issuer_name.cert" \
            -gencrl \
            -md $hash \
            -crldays 7 \
            -revoke "$kt/$revoked_cert_name.cert" \
            -crl_reason keyCompromise \
            -out "$kt/$revoked_cert_name.revoked.crl.pem"

  # Run -gencrl again to actually include the revoked certificate in the CRL.
  openssl ca \
            -config ./crl-openssl.cnf \
            -keyfile "$kt/$issuer_name.key" \
            -cert "$kt/$issuer_name.cert" \
            -md $hash \
            -gencrl \
            -crldays 7 \
            -out "$kt/$revoked_cert_name.revoked.crl.pem"
}

for kt in rsa ecdsa-p256 ecdsa-p384 ecdsa-p521 eddsa ; do
  case $kt in 
    rsa)
      hash=sha256
      ;;
    ecdsa-p256)
      hash=sha256
      ;;
    ecdsa-p384)
      hash=sha384
      ;;
    ecdsa-p521)
      hash=sha512
      ;;
    eddsa)
      hash=sha512
      ;;
  esac

  openssl x509 -req \
            -in $kt/inter.req \
            -out $kt/inter.cert \
            -CA $kt/ca.cert \
            -CAkey $kt/ca.key \
            -$hash \
            -days 3650 \
            -set_serial 123 \
            -extensions v3_inter -extfile openssl.cnf

  openssl x509 -req \
            -in $kt/end.req \
            -out $kt/end.cert \
            -CA $kt/inter.cert \
            -CAkey $kt/inter.key \
            -$hash \
            -days 2000 \
            -set_serial 456 \
            -extensions v3_end -extfile openssl.cnf

  openssl x509 -req \
            -in $kt/client.req \
            -out $kt/client.cert \
            -CA $kt/inter.cert \
            -CAkey $kt/inter.key \
            -$hash \
            -days 2000 \
            -set_serial 789 \
            -extensions v3_client -extfile openssl.cnf

  # Generate a CRL revoking the client certificate
  gen_crl $kt $hash inter client
  # Generate a CRL revoking the server certificate
  gen_crl $kt $hash inter end
  # Generate a CRL revoking the intermediate certificate
  gen_crl $kt $hash ca inter

  cat $kt/inter.cert $kt/ca.cert > $kt/end.chain
  cat $kt/end.cert $kt/inter.cert $kt/ca.cert > $kt/end.fullchain

  cat $kt/inter.cert $kt/ca.cert > $kt/client.chain
  cat $kt/client.cert $kt/inter.cert $kt/ca.cert > $kt/client.fullchain

  openssl asn1parse -in $kt/ca.cert -out $kt/ca.der > /dev/null
done

# Tidy up openssl CA state.
rm index.txt* || true
rm crlnumber* || true
