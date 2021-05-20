#!/bin/bash
#
# usage:
#
#     copy.sh DEST
#
# Copies all *.pem files possibly nested within the hierarchy below the
# current working directory to the same relative hierarchy at DEST, creating
# missing subdirectories as necessary. Avoids the use of rsync.
set -x

# first run generate.sh, then copy.sh DEST to move relevant files (without rootCA.key) to DEST
DEST="${1%%/}"
# set restrictive permissions on local files
chmod -R go-rwx .

# -not -path './[0-9]*' option excludes subdirs beginning with timestamp
# create target directory hierarchy
find . -type f -not -path './[0-9]*' -name '*.pem' -printf "%h\n" | sort -u | sed -E 's|^\./||' | xargs -n 1 -I {} echo "${DEST}/{}" | xargs -n 1 mkdir -p
# printf "%h\n" prints only the file's leading directory name
# http://man7.org/linux/man-pages/man1/find.1.html
# sed command removes leading curdir '.' character followed by path separator '/' from directory names

# set restrictive permissions on target directory hierarchy
chmod -R go-rwx "${DEST}"

# copy all *.pem key and certificate files to target hierarchy
find . -type f -not -path './[0-9]*' -name '*.pem' | xargs -n 1 -I {} cp "{}" "${DEST}/{}"