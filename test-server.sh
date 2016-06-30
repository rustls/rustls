#!/bin/sh

./target/debug/examples/tlsserver --verbose \
    --key test-ca/rsa/end.rsa --certs test-ca/rsa/end.fullchain --port 8443 http &
server=$!
sleep 1

echo "GET / HTTP/1.0" | openssl s_client -connect localhost:8443 -msg -debug -state -ign_eof &
client=$!
sleep 5
kill $server
kill $client
