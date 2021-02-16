#!/bin/sh -x

curl -k -d \
"{ \
\"id\" : \"`xxd -p -c 99999 did.decrypted`\", \
\"sigHmac\" : \"`xxd -p -c 99999 hmac.sig`\", \
\"sigRsa\" : \"`xxd -p -c 99999 rsa.sig`\", \
\"sigEcc\" : \"`xxd -p -c 99999 ecc.sig`\" \
}" \
-H "Content-Type: application/json" -X POST https://localhost/api/onboard-ack > onboard-ack-resp.json

printf "\nserver response:\n%s\n\n" "`cat onboard-ack-resp.json`"

