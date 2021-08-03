#!/bin/bash
set -x
# generate client key and certificate, sign with root certificate, bundle .pem files in tar archive
# expects $name as first argument and openssl config file $name.cnf

# sources:
# - https://medium.com/@rajanmaharjan/secure-your-mongodb-connections-ssl-tls-92e2addb3c89
# - http://apetec.com/support/GenerateSAN-CSR.htm
name=$1
conf="${name}.cnf"
subdir="$(date +%Y%m%d%H%M)-${name}-client-cert"

mkdir -p "${subdir}"
PASSW=$(openssl rand -base64 32)
echo "$PASSW" > "${subdir}/passw"

# generate key
openssl genrsa -out "${subdir}/tls_key.pem" 2048
# generate certificate request
openssl req -new -key "${subdir}/tls_key.pem" -out "${subdir}/tls_cert.csr" -config "${conf}" -batch

# print request to stdout
openssl req -text -noout -in "${subdir}/tls_cert.csr"
# generate self-signed certifictae
openssl x509 -req -in "${subdir}/tls_cert.csr" -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out "${subdir}/tls_cert.pem" -days 500 -sha256 -extensions v3_req -extfile "${conf}"
# concatenate key and signed certificate in simple file
cat "${subdir}"/tls_key.pem "${subdir}/tls_cert.pem" > "${subdir}/tls_key_cert.pem"
# concatenate key and signed certificate in p12 file
openssl pkcs12 -export -in "${subdir}/tls_cert.pem" -inkey "${subdir}/tls_key_cert.pem" -out "${subdir}/tls_key_cert.p12" -password pass:$PASSW

cp rootCA.pem "${subdir}/rootCA.pem"
tar cvzf "${subdir}.tar.gz" ${subdir}/*.pem