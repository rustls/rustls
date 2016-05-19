#!/bin/sh

openssl s_server -www -accept 8443 -key test/key.pem -cert test/cert.pem -msg -debug -state &
server=$!
sleep 1

./target/debug/s_client &
client=$!
sleep 5

kill $server
kill $client
