#!/bin/sh -x

echo `jq -r '.data.hmac' seed-exchange-resp.json` | xxd -r -p - > server-seed.key
cat server-seed.key device-seed.key > seed.key
tpm2_hmac -c hmac.ctx -o aes.key seed.key
rm seed.key
