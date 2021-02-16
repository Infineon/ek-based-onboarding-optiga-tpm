#!/bin/sh -x

# Retrieve credential blob 
echo `jq -r '.data.cred.secret' onboard-resp.json` | xxd -r -p - > credential.seed
printf "%04x" `cat credential.seed | wc -c` | xxd -r -p - > credential.seed.len
echo `jq -r '.data.cred.cred' onboard-resp.json` | xxd -r -p - > credential.cred
echo "badcc0de00000001" | xxd -r -p - > credential.header
cat credential.header credential.cred credential.seed.len credential.seed > credential.blob
rm credential.header credential.cred credential.seed.len credential.seed

# TPM activate credential
tpm2_startauthsession --policy-session -S session.ctx
TPM2_RH_ENDORSEMENT=0x4000000B
tpm2_policysecret -S session.ctx -c $TPM2_RH_ENDORSEMENT
tpm2_activatecredential -c 0x81000001 -C 0x81010001 -i credential.blob -o decryption.key -P "session:session.ctx"
tpm2_flushcontext session.ctx
rm session.ctx credential.blob

# Decrypt device id
echo `jq -r '.data.encID' onboard-resp.json` | xxd -r -p - > did.encrypted
openssl enc -aes-128-cfb -d -in did.encrypted -out did.decrypted -K `xxd -p -c 99999 decryption.key` -nosalt -iv 00000000000000000000000000000000
rm did.encrypted

# Import HMAC key
echo `jq -r '.data.dupHmac.pub' onboard-resp.json` | xxd -r -p - > hmac.pub
echo `jq -r '.data.dupHmac.dup' onboard-resp.json` | xxd -r -p - > hmac.dup
printf "%04x" `cat hmac.dup | wc -c` | xxd -r -p - > hmac.dup.len
cat hmac.dup.len hmac.dup > hmac.dup.blob
rm hmac.dup.len hmac.dup
echo `jq -r '.data.dupHmac.seed' onboard-resp.json` | xxd -r -p - > hmac.seed
printf "%04x" `cat hmac.seed | wc -c` | xxd -r -p - > hmac.seed.len
cat hmac.seed.len hmac.seed > hmac.seed.blob
rm hmac.seed.len hmac.seed
tpm2_import -C 0x81000001 -u hmac.pub -i hmac.dup.blob -r hmac.priv -s hmac.seed.blob -k decryption.key
tpm2_load -C 0x81000001 -u hmac.pub -r hmac.priv -c hmac.ctx
rm hmac.dup.blob hmac.seed.blob hmac.pub hmac.priv

# Import RSA key
echo `jq -r '.data.dupRsa.pub' onboard-resp.json` | xxd -r -p - > rsa.pub
echo `jq -r '.data.dupRsa.dup' onboard-resp.json` | xxd -r -p - > rsa.dup
printf "%04x" `cat rsa.dup | wc -c` | xxd -r -p - > rsa.dup.len
cat rsa.dup.len rsa.dup > rsa.dup.blob
rm rsa.dup.len rsa.dup
echo `jq -r '.data.dupRsa.seed' onboard-resp.json` | xxd -r -p - > rsa.seed
printf "%04x" `cat rsa.seed | wc -c` | xxd -r -p - > rsa.seed.len
cat rsa.seed.len rsa.seed > rsa.seed.blob
rm rsa.seed.len rsa.seed
tpm2_import -C 0x81000001 -u rsa.pub -i rsa.dup.blob -r rsa.priv -s rsa.seed.blob -k decryption.key
tpm2_load -C 0x81000001 -u rsa.pub -r rsa.priv -c rsa.ctx
rm rsa.dup.blob rsa.seed.blob rsa.pub rsa.priv

# Import ECC key
echo `jq -r '.data.dupEcc.pub' onboard-resp.json` | xxd -r -p - > ecc.pub
echo `jq -r '.data.dupEcc.dup' onboard-resp.json` | xxd -r -p - > ecc.dup
printf "%04x" `cat ecc.dup | wc -c` | xxd -r -p - > ecc.dup.len
cat ecc.dup.len ecc.dup > ecc.dup.blob
rm ecc.dup.len ecc.dup
echo `jq -r '.data.dupEcc.seed' onboard-resp.json` | xxd -r -p - > ecc.seed
printf "%04x" `cat ecc.seed | wc -c` | xxd -r -p - > ecc.seed.len
cat ecc.seed.len ecc.seed > ecc.seed.blob
rm ecc.seed.len ecc.seed
tpm2_import -C 0x81000001 -u ecc.pub -i ecc.dup.blob -r ecc.priv -s ecc.seed.blob -k decryption.key
tpm2_load -C 0x81000001 -u ecc.pub -r ecc.priv -c ecc.ctx
rm ecc.dup.blob ecc.seed.blob ecc.pub ecc.priv
rm decryption.key

# Sign server challenge (HMAC)
echo `jq -r '.data.challenge' onboard-resp.json` | xxd -r -p - > challenge
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
