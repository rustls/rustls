#!/bin/sh

openssl s_server -www -accept 8443 -key test/end.key -cert test/end.cert -CAfile test/end.chain -msg -debug -state &
server=$!
sleep 1

./target/debug/s_client &
client=$!
sleep 5

kill $server
kill $client
