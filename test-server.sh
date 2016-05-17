#!/bin/sh

./target/debug/s_server &
server=$!
sleep 1

openssl s_client -connect localhost:8443 -msg -debug -state &
client=$!
sleep 5
kill $server
kill $client
