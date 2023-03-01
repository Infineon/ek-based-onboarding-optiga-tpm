#!/bin/sh -x

curl -k -d \
"{ \
\"gid\" : \"infineon\", \
\"ekCrt\" : \"`xxd -p -c 99999 ek.crt`\", \
\"srkPub\" : \"`xxd -p -c 99999 parent.pub`\" \
}" \
-H "Content-Type: application/json" -X POST https://localhost/api/onboard > onboard-resp.json

printf "\nserver response:\n%s\n\n" "`cat onboard-resp.json`"

