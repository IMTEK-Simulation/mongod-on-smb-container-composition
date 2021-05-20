#!/bin/bash
# generate derived set of self-signed certificates
#
# sources:
# - https://medium.com/@rajanmaharjan/secure-your-mongodb-connections-ssl-tls-92e2addb3c89
# - http://apetec.com/support/GenerateSAN-CSR.htm
set -x

cnf_arr=( "mongodb.cnf" "mongodb_backup.cnf" )
subdir_arr=( "mongodb" "mongodb_backup" )

PASSW=$(openssl rand -base64 32)
echo "$PASSW" > passw

for ((i=0;i<${#cnf_arr[@]};++i)); do
    subdir="${subdir_arr[i]}"

    mkdir -p "${subdir}"
    # generate key
    openssl genrsa -out "${subdir}/tls_key.pem" 2048
    # generate certificate request
    openssl req -new -key "${subdir}/tls_key.pem" -out "${subdir}/tls_cert.csr" -config "${cnf_arr[i]}" -batch
    # print request to stdout
    openssl req -text -noout -in "${subdir}/tls_cert.csr"
    # generate self-signed certifictae
    openssl x509 -req -in "${subdir}/tls_cert.csr" -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out "${subdir}/tls_cert.pem" -days 500 -sha256 -extensions v3_req -extfile "${cnf_arr[i]}"
    # concatenate key and signed certificate in simple file
    cat "${subdir}"/tls_key.pem "${subdir}/tls_cert.pem" > "${subdir}/tls_key_cert.pem"
    # concatenate key and signed certificate in p12 file
    openssl pkcs12 -export -in "${subdir}/tls_cert.pem" -inkey "${subdir}/tls_key_cert.pem" -out "${subdir}/tls_key_cert.p12" -password pass:$PASSW
    # print content of generated .pem certificate to stdout
    openssl x509 -in ${subdir}/tls_cert.pem -text
done
