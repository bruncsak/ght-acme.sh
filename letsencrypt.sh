#!/bin/sh

#    letsencrypt.sh - a simple shell implementation for the acme protocol
#    Copyright (C) 2015 Gerhard Heift
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

trap 'rm -f "$RESP_HEADER" "$RESP_BODY" "$LAST_NONCE" "$LAST_NONCE_FETCH" "$OPENSSL_CONFIG" "$OPENSSL_IN" "$OPENSSL_OUT" "$OPENSSL_ERR"' 0 2 3 9 11 13 15

# file to store header of http request
RESP_HEADER="`mktemp`"
# file to store body of http request
RESP_BODY="`mktemp`"
# file with Replay-Nonce header of last request
LAST_NONCE="`mktemp`"
# tmp file for new Replay-Nonce header
LAST_NONCE_FETCH="`mktemp`"
# tmp config for openssl for addional domains
OPENSSL_CONFIG="`mktemp`"
# file to store openssl output
OPENSSL_IN="`mktemp`"
OPENSSL_OUT="`mktemp`"
OPENSSL_ERR="`mktemp`"

CA="https://acme-v01.api.letsencrypt.org"
# CA="https://acme-staging.api.letsencrypt.org"

base64url() {
    base64 | tr '+/' '-_' | tr -d '\r\n='
}

# global variables:

# base64url encoded JSON nonce, generated from Replay-Nonce header
# see gen_protected()
PROTECTED=

# base64url encoded JSON request object
PAYLOAD=

# base64url encoded signature of PROTECTED and PAYLOAD
# see also gen_signature()
SIGNATURE=

# the account key used to send the requests and to verify the domain challenges
ACCOUNT_KEY=

# the JSON Web Key is the representation of the key as JSON object
ACCOUNT_JWK=

# the JSON object to specify the signature format
REQ_JWKS=

# the thumbprint is the checksum of the JWK and is used for the challenges
ACCOUNT_THUMB=

# the private key, which should be signed by the CA
SERVER_KEY=

# the location, where the certificate should be stored
SERVER_CERT=

# the e-mail address to be used with the account key, only needed if account
# key is not yet registred
ACCOUNT_EMAIL=

# a list of domains, which should be assigned to the certificate
DOMAINS=

# a list of domains, challenge uri and token
DOMAIN_DATA=

QUIET=

# utility functions

handle_curl_exit() {
    CURL_EXIT="$1"
    CURL_URI="$2"

    if [ "$CURL_EXIT" "!=" 0 ]; then
        echo "error while making a web request to \"$CURL_URI\"" > /dev/stderr
        echo "curl exit status: $CURL_EXIT" > /dev/stderr
        case "$CURL_EXIT" in
            # see man curl "EXIT CODES"
             3) echo "  malformed URI" > /dev/stderr;;
             6) echo "  could not resolve host" > /dev/stderr;;
             7) echo "  failed to connect" > /dev/stderr;;
            28) echo "  operation timeout" > /dev/stderr;;
            35) echo "  SSL connect error" > /dev/stderr;;
        esac

        exit 1
    fi
}

log() {
    if [ -z "$QUIET" ]; then
        echo "$@" > /dev/stderr
    fi
}

handle_openssl_exit() {
    OPENSSL_EXIT=$1
    OPENSSL_ACTION=$2

    if [ "$OPENSSL_EXIT" "!=" 0 ]; then
        echo "error while $OPENSSL_ACTION" > /dev/stderr
        echo "openssl exit status: $OPENSSL_EXIT" > /dev/stderr
        cat "$OPENSSL_ERR" > /dev/stderr
        exit 1
    fi
}

check_http_status() {
    fgrep -q "HTTP/1.1 $1 " "$RESP_HEADER"
}

unhandled_response() {
    echo "unhandled response while $1" > /dev/stderr
    echo > /dev/stderr

    cat "$RESP_HEADER" "$RESP_BODY" > /dev/stderr

    echo > /dev/stderr

    exit 1
}

show_error() {
    if [ -n "$1" ]; then
        echo "error while $1" > /dev/stderr
    fi

    ERR_TYPE="`sed -e 's/.*"type":"\([^"]*\)".*/\1/' "$RESP_BODY"`"
    ERR_DETAILS="`sed -e 's/.*"detail":"\([^"]*\)".*/\1/' "$RESP_BODY"`"

    echo "  $ERR_DETAILS ($ERR_TYPE)" > /dev/stderr
}

# generate the PROTECTED variable, which contains a nonce retrieved from the
# server in the Replay-Nonce header

gen_protected(){
    NONCE="`cat "$LAST_NONCE"`"
    if [ -z "$NONCE" ]; then
        # echo fetch new nonce > /dev/stderr
        curl -D "$LAST_NONCE_FETCH" -o /dev/null -s "$CA/directory"
        handle_curl_exit $? "$CA/directory"

        sed -e '/Replay-Nonce: / ! d; s/^Replay-Nonce: //' "$LAST_NONCE_FETCH" \
            | tr -d '\r\n' \
            > "$LAST_NONCE"

        NONCE="`cat "$LAST_NONCE"`"
        if [ -z "$NONCE" ]; then
            echo "nonce is empty?" > /dev/stderr
            full_exit
        fi
    fi

    PROTECTED="`echo '{"nonce":"'"$NONCE"'"}' \
        | tr -d '\n\r' \
        | base64url`"

    echo | tr -d '\n\r' > "$LAST_NONCE"
}

# generate the signature for the request

gen_signature() {
    printf "%s" "$PROTECTED.$PAYLOAD" > "$OPENSSL_IN"
    openssl dgst -sha256 -binary -sign "$ACCOUNT_KEY" < "$OPENSSL_IN" > "$OPENSSL_OUT" 2> "$OPENSSL_ERR"
    handle_openssl_exit "$?" "signing request"
    SIGNATURE="`base64url < "$OPENSSL_OUT"`"
}

# helper functions to create the json web key object

key_get_modulus(){
    openssl pkey -inform perm -in "$1" -noout -text_pub > "$OPENSSL_OUT" 2> "$OPENSSL_ERR"
    handle_openssl_exit $? "extracting account key modulus"

    sed -e '/^----/d; /^Public-Key:/ d; /^Modulus/ d; /Exponent: / d; s/[ :]//g' \
        < "$OPENSSL_OUT" \
        | tr -d '\r\n' \
        | sed 's/^\(00\)*//' \
        | xxd -r -p \
        | base64url
}

key_get_exponent(){
    openssl pkey -inform perm -in "$1" -noout -text_pub > "$OPENSSL_OUT" 2> "$OPENSSL_ERR"
    handle_openssl_exit $? "extracting account key exponent"

    sed -e '/Exponent: / ! d; s/Exponent: [0-9]*\s\+(\(\(0\)x\([0-9]\)\|0x\)\(\([0-9][0-9]\)*\))/\2\3\4/' \
        < "$OPENSSL_OUT" \
        | xxd -r -p \
        | base64url
}


# make a request to the specified URI
# the payload is signed by the ACCOUNT_KEY
# the response header is stored in the file $RESP_HEADER, the body in the file $RESP_BODY

send_req(){
    URI="$1"

    gen_protected
    PAYLOAD="`echo "$2" | base64url`"
    gen_signature

    DATA='{"header":'"$REQ_JWKS"',"protected":"'"$PROTECTED"'","payload":"'"$PAYLOAD"'","signature":"'"$SIGNATURE"'"}'

    curl -s -d "$DATA" -D "$RESP_HEADER" -o "$RESP_BODY" "$URI"
    handle_curl_exit $? "$URI"

    # store the nonce for the next request
    sed -e '/Replay-Nonce: / ! d; s/^Replay-Nonce: //' "$RESP_HEADER" | tr -d '\r\n' > "$LAST_NONCE"
}

register_account_key(){
    log register account

    NEW_REG='{"resource":"new-reg","contact":["mailto:'"$ACCOUNT_EMAIL"'"],"agreement":"https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"}'
    send_req "$CA/acme/new-reg" "$NEW_REG"

    if check_http_status 201; then
        return
    elif check_http_status 409; then
        echo "account exists, just continue" > /dev/stderr
    else
        unhandled_response "registering account"
    fi
}

# This function returns the certificate request in base64url encoding
# arguments: domain ...
#   key: the private key, which is used for the domains
#   domain: a list of domains for which the certificate should be valid


request_challenge_domain(){
    log request challenge for $DOMAIN

    NEW_AUTHZ='{"resource":"new-authz","identifier":{"type":"dns","value":"'"$DOMAIN"'"}}'
    send_req "$CA/acme/new-authz" "$NEW_AUTHZ"

    if check_http_status 201; then
        DOMAIN_CHALLENGE="`sed -e '/"http-01"/ ! d; s/.*{\([^}]*"type":"http-01"[^}]*\)}.*/\1/' "$RESP_BODY"`"
        DOMAIN_TOKEN="`echo "$DOMAIN_CHALLENGE" | sed 's/.*"token":"\([^"]*\)".*/\1/'`"
        DOMAIN_URI="`echo "$DOMAIN_CHALLENGE" | sed 's/.*"uri":"\([^"]*\)".*/\1/'`"

        DOMAIN_DATA="$DOMAIN_DATA $DOMAIN $DOMAIN_URI $DOMAIN_TOKEN"
    elif check_http_status 403; then
        # account not registred?
        show_error "requesting challenge for $DOMAIN"
        exit 1
    else
        unhandled_response "requesting challenge for $DOMAIN"
    fi
}

request_challenge(){
    set -- $DOMAINS
    for DOMAIN do
        request_challenge_domain
    done
}

push_response_domain() {
    log push response for $DOMAIN

    # do something with DOMAIN, DOMAIN_TOKEN and DOMAIN_RESPONSE

    # echo "$DOMAIN_RESPONSE" > "/srv/www/$DOMAIN/.well-known/acme-challenge/$DOMAIN_TOKEN"
    return
}

push_response() {
    set -- $DOMAIN_DATA
    while [ -n "$1" ]; do
        DOMAIN="$1"
        DOMAIN_URI="$2"
        DOMAIN_TOKEN="$3"

        shift 3

        DOMAIN_RESPONSE="$DOMAIN_TOKEN.$ACCOUNT_THUMB"
    
        push_response_domain
    done
}

request_domain_verification() {
    log request verification of $DOMAIN

    send_req $DOMAIN_URI '{"resource":"challenge","type":"http-01","keyAuthorization":"'"$DOMAIN_TOKEN.$ACCOUNT_THUMB"'","token":"'"$DOMAIN_TOKEN"'"}'

    if check_http_status 202; then
        printf ""
    else
        unhandled_response "requesting verification of challenge of $DOMAIN"
    fi
}

request_verification() {
    set -- $DOMAIN_DATA
    
    while [ -n "$1" ]; do
        DOMAIN="$1"
        DOMAIN_URI="$2"
        DOMAIN_TOKEN="$3"
    
        shift 3

        request_domain_verification
    done
}

check_verification() {
    ALL_VALID=true
    
    while [ -n "$DOMAIN_DATA" ]; do
        sleep 1
    
        set -- $DOMAIN_DATA
        DOMAIN_DATA=""
    
        while [ -n "$1" ]; do
            DOMAIN="$1"
            DOMAIN_URI="$2"
            DOMAIN_TOKEN="$3"
        
            shift 3
        
            log check verification of $DOMAIN

            curl -D "$RESP_HEADER" -o "$RESP_BODY" -s "$DOMAIN_URI"
            handle_curl_exit $? "$DOMAIN_URI"
        
            if check_http_status 202; then
                DOMAIN_STATUS="`sed -e 's/.*"status":"\(invalid\|valid\|pending\)".*/\1/' "$RESP_BODY"`"
                case "$DOMAIN_STATUS" in
                    valid)
                        log $DOMAIN is valid
                        ;;
                    invalid)
                        echo $DOMAIN: invalid > /dev/stderr
                        show_error

                        ALL_VALID=false
                        ;;
                    pending)
                        log $DOMAIN is pending
                        DOMAIN_DATA="$DOMAIN_DATA $DOMAIN $DOMAIN_URI $DOMAIN_TOKEN"
                        ;;
                    *)
                        unhandled_response "checking verification status of $DOMAIN"
                        ;;
                esac
            else
                unhandled_response "checking verification status of $DOMAIN"
            fi
        done
    done

    if ! $ALL_VALID; then
        exit 1
    fi
}

request_certificate(){
    log request certificate

    set -- $DOMAINS

    ALT_NAME="subjectAltName=DNS:$1"
    shift

    while [ -n "$1" ]; do
        ALT_NAME="$ALT_NAME,DNS:$1"
        shift
    done

    cat /etc/ssl/openssl.cnf > "$OPENSSL_CONFIG"
    echo '[SAN]' >> "$OPENSSL_CONFIG"
    echo "$ALT_NAME" >> "$OPENSSL_CONFIG"


    openssl req -new -sha512 -key "$SERVER_KEY" -subj / -reqexts SAN -config $OPENSSL_CONFIG \
        > "$OPENSSL_OUT" \
        2> "$OPENSSL_ERR"
    handle_openssl_exit $? "creating certifacte request"

    NEW_CERT="`
            sed -e 's/-----BEGIN CERTIFICATE REQUEST-----/{"resource":"new-cert","csr":"/; s/-----END CERTIFICATE REQUEST-----/"}/;s/+/-/g;s!/!_!g;s/=//g' "$OPENSSL_OUT" \
            | tr -d '\r\n' \
    `"

    send_req "$CA/acme/new-cert" "$NEW_CERT"
    
    if check_http_status 201; then
        openssl x509 -inform der -outform pem -in "$RESP_BODY" -out "$OPENSSL_OUT" 2> "$OPENSSL_ERR"
        handle_openssl_exit $? "converting certificate"
        cp -- "$OPENSSL_OUT" "$SERVER_CERT"
    elif check_http_status 429; then
        show_error "requesting certificate"
        exit 1
    else
        unhandled_response "requesting certificate"
    fi
}

usage() {
    cat << EOT
letsencrypt [-q] -a account_key [-n -e email] -k server_key -c signed_key domain ...
letsencrypt -p plain|nginx -a account_key
    -q                quiet operation
    -a account_key    the private key
    -n                register the account key at the service
    -e email          the email address assigned to the account key during the registration
    -k server_key     the privat key of the server certificate
    -c signed_key     the location where to store the signed key
    -p format         print the thumbprint of the account key or a sample configuration
EOT
}

DO_REGISTER=
PRINT_THUMB=

while getopts hqa:nk:c:rp:e: name; do
    case "$name" in
        h) usage; exit;;
        q) QUIET=1;;
        a) ACCOUNT_KEY="$OPTARG";;
        k) SERVER_KEY="$OPTARG";;
        c) SERVER_CERT="$OPTARG";;
        n) DO_REGISTER=1;;
        e) ACCOUNT_EMAIL="$OPTARG";;
        p) PRINT_THUMB="$OPTARG";;
    esac
done

shift $(($OPTIND - 1))

if [ -z "$ACCOUNT_KEY" ]; then
    echo no account key specified > /dev/stderr
    exit 1
fi

if [ '!' -r "$ACCOUNT_KEY" ]; then
    echo could not read account key > /dev/stderr
    exit 1
fi

# generate JWK and JWK thumbprint

ACCOUNT_JWK='{"e":"'"`key_get_exponent $ACCOUNT_KEY`"'","kty":"RSA","n":"'"`key_get_modulus $ACCOUNT_KEY`"'"}'
REQ_JWKS='{"alg":"RS256","jwk":'"$ACCOUNT_JWK"'}'
ACCOUNT_THUMB="`echo "$ACCOUNT_JWK" | tr -d '\r\n' | openssl dgst -sha256 -binary | base64url`"

if [ -n "$PRINT_THUMB" ]; then
    case "$PRINT_THUMB" in
        plain)
            echo $ACCOUNT_THUMB
            exit
            ;;
        nginx)
            cat <<"HERE" | sed "s/ACCOUNT_THUMB/$ACCOUNT_THUMB/g"
location ~ "^/.well-known/acme-challenge/([-_a-zA-Z0-9]*)$" {
    default_type text/plain;
    return 200 "$1.ACCOUNT_THUMB";
}
HERE
            exit
            ;;
        *)
            echo unknown format > /dev/stderr
            exit 1
            ;;
    esac
fi

if [ -z "$SERVER_KEY" ]; then
    echo no server key specified > /dev/stderr
    exit 1
fi

if [ -z "$SERVER_CERT" ]; then
    echo no server certificate specified > /dev/stderr
    exit 1
fi

if [ '!' -r "$SERVER_KEY" ]; then
    echo could not read server key > /dev/stderr
    exit 1
fi

if [ -z "$1" ]; then
    echo "need at least on domain" > /dev/stderr
    exit 1
fi

DOMAINS=$1
shift

while [ -n "$1" ]; do
    DOMAINS="$DOMAINS $1"
    shift
done

if [ -n "$DO_REGISTER" ]; then
    if [ -z "$ACCOUNT_EMAIL" ]; then
        echo need email address to register account key > /dev/stderr
        exit 1
    fi

    register_account_key
fi

request_challenge
push_response
request_verification
check_verification
request_certificate