#!/bin/sh

openssl s_server -www -accept 8443 -key test/end.key -cert test/end.cert -CAfile test/end.chain -msg -debug -state > server.log 2>&1 &
server=$!
sleep 1

./target/debug/s_client > client.log 2>&1 &
client=$!
sleep 5

kill $server
kill $client
