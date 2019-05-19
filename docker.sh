#!/usr/bin/env bash
#
# [ osctrl 🎛 ]: Script to build osctrl in docker
#

NAME="osctrl"

# We want the provision script to fail as soon as there are any errors
set -e

echo "[+] Preparing certificates for $NAME-nginx"

# This is for development purposes, in production environments use 2048 or 4096 bits
_BITS="1024"

CSR_FILE="$NAME.csr"
KEY_FILE="$NAME.key"
CRT_FILE="$NAME.crt"

echo "[+] Generating $CRT_FILE and $KEYFILE"
openssl req -nodes -newkey rsa:$_BITS -keyout "$KEY_FILE" -out "$CSR_FILE" -subj "/O=$NAME"
openssl x509 -req -days 365 -in "$CSR_FILE" -signkey "$KEY_FILE" -out "$CRT_FILE"

DH_FILE="dhparam.pem"
echo "[+] Generating $DH_FILE, it may take a bit"
openssl dhparam -out "$DH_FILE" $_BITS &>/dev/null

echo "[+] Building containers"
docker-compose build

echo "[+] Running containers"
docker-compose up

exit 0

# kthxbai
