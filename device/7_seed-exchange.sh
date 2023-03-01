#!/bin/sh -x

tpm2_getrandom 16 -o device-seed.key

curl -k -d \
"{ \
\"seed\" : \"`xxd -p -c 99999 device-seed.key`\" \
}" \
-H "Content-Type: application/json" -H "`cat device.jwt`" -X POST https://localhost/api/key-exchange > seed-exchange-resp.json

printf "\nserver response:\n%s\n\n" "`cat seed-exchange-resp.json`"