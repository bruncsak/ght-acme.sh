#!/bin/sh

#    letsencrypt.sh - a simple shell implementation for the acme protocol
#    Copyright (C) 2015 Gerhard Heift
#    Copyright (C) 2022 Attila Bruncsak
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# temporary files to store input/output of curl or openssl

trap 'rm -f "$OPENSSL_CONFIG" "$OPENSSL_IN" "$OPENSSL_OUT" "$OPENSSL_ERR" "$TMP_SERVER_CSR"' 0 1 2 3 9 11 13 15

# tmp config for openssl for addional domains
OPENSSL_CONFIG="`mktemp -t gen-csr.$$.openssl.cnf.XXXXXX`"
# file to store openssl output
OPENSSL_IN="`mktemp -t gen-csr.$$.openssl.in.XXXXXX`"
OPENSSL_OUT="`mktemp -t gen-csr.$$.openssl.out.XXXXXX`"
OPENSSL_ERR="`mktemp -t gen-csr.$$.openssl.err.XXXXXX`"
# file to store the CSR
TMP_SERVER_CSR="`mktemp -t gen-csr.$$.server.csr.XXXXXX`"

# global variables:

# the private key, which should be signed by the CA
SERVER_KEY=

# the location, where the certificate signing request should be stored
SERVER_CSR=

# a list of domains, which should be assigned to the certificate
DOMAINS=

# no wildcard domain name is permitted by default
DOMAIN_EXTRA_PAT=

LOGLEVEL=1

# utility functions

base64url() {
    openssl base64 | tr '+/' '-_' | tr -d '\r\n='
}

err_exit() {
    RETCODE="$?"
    [ -n "$2" ] && RETCODE="$2"
    [ -n "$1" ] && printf "%s\n" "$1" >& 2
    exit "$RETCODE"
}

validate_domain() {
    DOMAIN_IN="$1"
    if [ "$DOMAIN_IN" = _ ]; then
        return 1
    fi

    DOMAIN_OUT="`printf "%s\n" "$DOMAIN_IN" | sed -e 's/^...$/!/; s/^.\{254,\}$/!/; s/^'"$DOMAIN_EXTRA_PAT"'\([a-zA-Z0-9]\([-a-zA-Z0-9]\{0,61\}[a-zA-Z0-9]\)\{0,1\}\.\)\{1,\}\([a-zA-Z]\([-a-zA-Z0-9]\{0,61\}[a-zA-Z]\)\)$/_/;'`"

    if [ "$DOMAIN_OUT" = _ ]; then
        return 0
    else
        return 1
    fi
}

handle_openssl_exit() {
    OPENSSL_EXIT=$1
    OPENSSL_ACTION=$2

    if [ "$OPENSSL_EXIT" "!=" 0 ]; then
        echo "error while $OPENSSL_ACTION" >& 2
        echo "openssl exit status: $OPENSSL_EXIT" >& 2
        cat "$OPENSSL_ERR" >& 2
        exit 1
    fi
}

log() {
    if [ "$LOGLEVEL" -gt 0 ]; then
        echo "$@" >& 2
    fi
}

# this function generates the csr from the private server key and a list of domains

gen_csr_with_private_key() {
    log generate certificate request

    set -- $DOMAINS

    FIRST_DOM="$1"
    validate_domain "$FIRST_DOM" || err_exit "invalid domain: $FIRST_DOM"

    ALT_NAME="subjectAltName=DNS:$1"
    shift

    for DOMAIN do
        validate_domain "$DOMAIN" || err_exit "invalid domain: $DOMAIN"
        ALT_NAME="$ALT_NAME,DNS:$DOMAIN"
    done

    if [ -r /etc/ssl/openssl.cnf ]; then
        cat /etc/ssl/openssl.cnf > "$OPENSSL_CONFIG"
    else
        cat /etc/pki/tls/openssl.cnf > "$OPENSSL_CONFIG"
    fi
    echo '[SAN]' >> "$OPENSSL_CONFIG"
    echo "$ALT_NAME" >> "$OPENSSL_CONFIG"

    openssl req -new -sha512 -key "$SERVER_KEY" -subj "/CN=$FIRST_DOM" -reqexts SAN -config $OPENSSL_CONFIG \
        > "$TMP_SERVER_CSR" \
        2> "$OPENSSL_ERR"
    handle_openssl_exit $? "creating certificate request"
}

usage() {
    cat << EOT
gen-csr.sh [-q] -k server_key [-R server_csr] domain ...
    -q                quiet operation
    -k server_key     the private key of the server certificate
    -R server_csr     the location where to store the certificate request
                      if not specified, printed to stdout
                      if not writeable, printed to stderr
EOT
}

DO_REGISTER=
PRINT_THUMB=

while getopts hqk:R: name; do
    case "$name" in
        h) usage; exit;;
        q) LOGLEVEL=0;;
        k) SERVER_KEY="$OPTARG";;
        R) SERVER_CSR="$OPTARG";;
    esac
done

shift $((OPTIND - 1))

if [ -z "$SERVER_KEY" ]; then
    echo no server key specified >& 2
    exit 1
fi

if [ '!' -r "$SERVER_KEY" ]; then
    echo could not read server key >& 2
    exit 1
fi

if [ -z "$1" ]; then
    echo "need at least on domain" >& 2
    exit 1
fi

DOMAIN_EXTRA_PAT='\(\*\.\)\{0,1\}'
DOMAINS=$*

# CSR will be stored in TMP_SERVER_CSR
gen_csr_with_private_key

if [ -z "$SERVER_CSR" ]; then
    cat "$TMP_SERVER_CSR"
else
    mv "$TMP_SERVER_CSR" "$SERVER_CSR"
    if [ "$?" '!=' 0 ]; then
        [ -r "$TMP_SERVER_CSR" ] && cat "$TMP_SERVER_CSR" >& 2
    fi
fi
