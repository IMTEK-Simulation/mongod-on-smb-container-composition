#!/bin/bash
# generate root certificate
#
# sources:
# - https://medium.com/@rajanmaharjan/secure-your-mongodb-connections-ssl-tls-92e2addb3c89
# - http://apetec.com/support/GenerateSAN-CSR.htm
set -x

# generate and self-sign root certificate
openssl genrsa -out rootCA.key 2048
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.pem -config root_ca.cnf -batch
