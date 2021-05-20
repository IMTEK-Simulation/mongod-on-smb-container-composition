#!/bin/bash
set -x
# pack root certificate and client certificates

subdir="$(date +%Y%m%d%H%M)-root-and-service-certs"

bash copy.sh ${subdir}

tar cvzf "${subdir}.tar.gz" ${subdir}/*