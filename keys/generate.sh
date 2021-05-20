#!/bin/bash
# generate root certificate and derived set of self-signed certificates for testing purposes
#
# TODO:
# * CN field apparently overridden by SAN (subject alternative names) in openssl.cnf. Fix that.
#
# sources:
# - https://medium.com/@rajanmaharjan/secure-your-mongodb-connections-ssl-tls-92e2addb3c89
# - http://apetec.com/support/GenerateSAN-CSR.htm
set -x
temp_subj="/C=DE/ST=Some state/L=Some city/O=Some organization/OU=Some department/emailAddress=none@none"
root_subj="$temp_subj"

subj_suffix_arr=( "/CN=mongodb" "/CN=mongodb-backup" )
subdir_arr=( "mongodb" "mongodb_backup" )

PASSW=$(openssl rand -base64 32)
echo "$PASSW" > passw

# generate and self-sign root certificate
openssl genrsa -out rootCA.key 2048
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.pem -config openssl.cnf -subj "${root_subj}" -batch

for ((i=0;i<${#subj_suffix_arr[@]};++i)); do
    subj="${temp_subj}${subj_suffix_arr[i]}"
    subdir="${subdir_arr[i]}"

    mkdir -p "${subdir}"
    # generate key
    openssl genrsa -out "${subdir}/tls_key.pem" 2048
    # generate certificate request
    openssl req -new -key "${subdir}/tls_key.pem" -out "${subdir}/tls_cert.csr" -config openssl.cnf -subj "${subj}" -batch
    # print request to stdout
    openssl req -text -noout -in "${subdir}/tls_cert.csr"
    # generate self-signed certifictae
    openssl x509 -req -in "${subdir}/tls_cert.csr" -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out "${subdir}/tls_cert.pem" -days 500 -sha256 -extensions v3_req -extfile openssl.cnf
    # concatenate key and signed certificate in simple file
    cat "${subdir}"/tls_key.pem "${subdir}/tls_cert.pem" > "${subdir}/tls_key_cert.pem"
    # concatenate key and signed certificate in p12 file
    openssl pkcs12 -export -in "${subdir}/tls_cert.pem" -inkey "${subdir}/tls_key_cert.pem" -out "${subdir}/tls_key_cert.p12" -password pass:$PASSW
done
