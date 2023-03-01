#!/bin/sh -x

# Get server challenge
curl -k -d \
"{ \
\"id\" : \"`xxd -p -c 99999 did.decrypted`\" \
}" \
-H "Content-Type: application/json" -X POST https://localhost/api/get-challenge > get-challenge-resp.json

printf "\nserver response:\n%s\n\n" "`cat get-challenge-resp.json`"

# Sign server challenge (HMAC)
echo `jq -r '.data.challenge' get-challenge-resp.json` | xxd -r -p - > challenge
tpm2_hmac -c hmac.ctx -o hmac.sig challenge 

# Sign server challenge (RSA)
tpm2_sign -c rsa.ctx -g sha256 -o rsa.sig.orig challenge
tpm2_verifysignature -c rsa.ctx -g sha256 -s rsa.sig.orig -m challenge 
dd bs=2 skip=1 if=rsa.sig.orig of=rsa.sig
rm rsa.sig.orig

# Sign server challenge (ECC)
tpm2_sign -c ecc.ctx -g sha256 -o ecc.sig.orig challenge
tpm2_verifysignature -c ecc.ctx -g sha256 -s ecc.sig.orig -m challenge 
dd bs=2 skip=1 if=ecc.sig.orig of=ecc.sig
rm ecc.sig.orig

curl -i -k -d \
"{ \
\"id\" : \"`xxd -p -c 99999 did.decrypted`\", \
\"sigHmac\" : \"`xxd -p -c 99999 hmac.sig`\", \
\"sigRsa\" : \"`xxd -p -c 99999 rsa.sig`\", \
\"sigEcc\" : \"`xxd -p -c 99999 ecc.sig`\" \
}" \
-H "Content-Type: application/json" -X POST https://localhost/api/get-jwt > get-jwt-resp.json

printf "\nserver response:\n%s\n\n" "`cat get-jwt-resp.json`"

cat get-jwt-resp.json | grep Authorization | tr -d "\r\n\t\v" > device.jwt
