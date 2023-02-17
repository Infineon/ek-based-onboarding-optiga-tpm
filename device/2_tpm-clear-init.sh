#!/bin/sh -x

# Create RSA endorsement key
tpm2_clear -c p
tpm2_createek -G rsa -u ek.pub -c ek.ctx
tpm2_evictcontrol -C o -c ek.ctx 0x81010001
rm ek.pub ek.ctx
tpm2_nvread 0x1c00002 -o ek.crt

# Create primary key
tpm2_createprimary -G rsa -C o -c primary.ctx 
tpm2_evictcontrol -C o -c primary.ctx 0x81000001
rm primary.ctx
tpm2_readpublic -c 0x81000001 -o parent.pub -n parent.name

# Create csv whitelist
openssl x509 -modulus -in ek.crt -inform der -noout | sed "s/Modulus=//" > whitelist.csv

