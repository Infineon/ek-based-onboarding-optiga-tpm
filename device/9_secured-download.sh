#!/bin/sh -x

curl -k -d \
"{ \
\"name\" : \"beach.3gp\" \
}" \
-H "Content-Type: application/json" -H "`cat device.jwt`" -X POST https://localhost/api/download > blob.3gp 

head -c 16 blob.3gp > iv.3gp
tail -c +17 blob.3gp > encrypted.3gp
openssl enc -d -aes-256-cbc -K `xxd -p -c 99999 aes.key` -iv `xxd -p -c 99999 iv.3gp` -in encrypted.3gp -out decrypted.3gp

curl -k -d \
"{ \
\"name\" : \"plain.txt\" \
}" \
-H "Content-Type: application/json" -H "`cat device.jwt`" -X POST https://localhost/api/download > blob.txt

head -c 16 blob.txt > iv.txt
tail -c +17 blob.txt > encrypted.txt
openssl enc -d -aes-256-cbc -K `xxd -p -c 99999 aes.key` -iv `xxd -p -c 99999 iv.txt` -in encrypted.txt -out decrypted.txt

curl -k -d \
"{ \
\"name\" : \"hex\" \
}" \
-H "Content-Type: application/json" -H "`cat device.jwt`" -X POST https://localhost/api/download > blob.hex

head -c 16 blob.hex > iv.hex
tail -c +17 blob.hex > encrypted.hex
openssl enc -d -aes-256-cbc -K `xxd -p -c 99999 aes.key` -iv `xxd -p -c 99999 iv.hex` -in encrypted.hex -out decrypted.hex

