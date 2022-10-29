#!/bin/sh

#    letsencrypt.sh - a simple shell implementation for the acme protocol
#    Copyright (C) 2015 Gerhard Heift
#    Copyright (C) 2016-2022 Attila Bruncsak
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

CADIR="https://api.test4.buypass.no/acme/directory"
CADIR="https://acme-staging-v02.api.letsencrypt.org/directory"

# Prefix the following line with "# letsencrypt-production-server #", to use
# the staging server of letsencrypt. The staging server has lower rate limits,
# but does not issue valid certificates. To automatically remove the comment
# again on commiting the file, add the filter to your git config by running
#   git config filter.production-server.clean misc/filter-production-server

CADIR="https://api.buypass.com/acme/directory"
CADIR="https://acme-v02.api.letsencrypt.org/directory"

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
ACCOUNT_ID=

# the thumbprint is the checksum of the JWK and is used for the challenges
ACCOUNT_THUMB=

# the private key, which should be signed by the CA
SERVER_KEY=

# the certificate signing request, which sould be used
SERVER_CSR=

# the location, where the certificate should be stored
SERVER_CERT=

# the location, where the certificate with the signing certificate(s) should be stored
SERVER_FULL_CHAIN=

# the location, where the signing certificate(s) should be stored
SERVER_SIGNING_CHAIN=

# selection of the signing chain
SIGNING_CHAIN_SELECTION=0

# the e-mail address to be used with the account key, only needed if account
# key is not yet registred
ACCOUNT_EMAIL=

# a list of domains, which should be assigned to the certificate
DOMAINS=

# a list of domains, challenge uri, token and authorization uri
DOMAIN_DATA=

# the directory, where to push the response
# $DOMAIN or ${DOMAIN} will be replaced with the actual domain
WEBDIR=

# the script to be called to push the response to a remote server
PUSH_TOKEN=

# the script to be called to push the response to a remote server needs the commit feature
PUSH_TOKEN_COMMIT=

# set the option of the preferred IP family for connecting to the ACME server
IPV_OPTION=

# the challenge type, can be dns-01 or http-01 (default)
CHALLENGE_TYPE="http-01"

# the date of the that version
VERSION_DATE="2022-10-29"

# The meaningful User-Agent to help finding related log entries in the ACME server log
USER_AGENT="bruncsak/ght-acme.sh $VERSION_DATE"

LOGLEVEL=1

# utility functions

tolower() {
    printf '%s' "$*" | tr A-Z a-z
}

HexadecimalStringToOctalEscapeSequence() {
tr '[A-F]' '[a-f]' "$@" | tr -d '\r\n' |
sed -e 's/[^0-9a-f]//g; s/^\(\(..\)\{0,\}\).$/\1/;
s/\([0-9a-f]\)\([0-9a-f]\)/\1_\2/g; s/$/\\c/;
s/_0/o0/g; s/_1/o1/g; s/_2/o2/g; s/_3/o3/g;
s/_4/o4/g; s/_5/o5/g; s/_6/o6/g; s/_7/o7/g;
s/_8/i0/g; s/_9/i1/g; s/_a/i2/g; s/_b/i3/g;
s/_c/i4/g; s/_d/i5/g; s/_e/i6/g; s/_f/i7/g;
s/0o/\\000/g; s/0i/\\001/g; s/1o/\\002/g; s/1i/\\003/g;
s/2o/\\004/g; s/2i/\\005/g; s/3o/\\006/g; s/3i/\\007/g;
s/4o/\\010/g; s/4i/\\011/g; s/5o/\\012/g; s/5i/\\013/g;
s/6o/\\014/g; s/6i/\\015/g; s/7o/\\016/g; s/7i/\\017/g;
s/8o/\\020/g; s/8i/\\021/g; s/9o/\\022/g; s/9i/\\023/g;
s/ao/\\024/g; s/ai/\\025/g; s/bo/\\026/g; s/bi/\\027/g;
s/co/\\030/g; s/ci/\\031/g; s/do/\\032/g; s/di/\\033/g;
s/eo/\\034/g; s/ei/\\035/g; s/fo/\\036/g; s/fi/\\037/g;
'
}

hex2bin() {
    xxd -r -p
    # echo $ECHOESCFLAG "`HexadecimalStringToOctalEscapeSequence`"
}

base64url() {
    openssl base64 | tr '+/' '-_' | tr -d '\r\n='
}

log() {
    if [ "$LOGLEVEL" -gt 0 ]; then
        echo "$@" >& 2
    fi
}

dbgmsg() {
    if [ "$LOGLEVEL" -gt 1 ]; then
        echo "$@" >& 2
    fi
}

err_exit() {
    RETCODE="$?"
    [ -n "$2" ] && RETCODE="$2"
    [ -n "$1" ] && printf "%s\n" "$1" >& 2
    exit "$RETCODE"
}

required_commands() {
    REQUIRED_COMMANDS="basename cat cp rm sed grep egrep fgrep tr mktemp expr tail xxd openssl"

    if [ "$USE_WGET" = yes ] ;then
        REQUIRED_COMMANDS="$REQUIRED_COMMANDS wget"
    else
        REQUIRED_COMMANDS="$REQUIRED_COMMANDS curl"
    fi
    for command in $REQUIRED_COMMANDS ;do
        command -v $command > /dev/null || err_exit "The command '$command' is required to run $PROGNAME"
    done
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

handle_wget_exit() {
    WGET_EXIT="$1"
    WGET_URI="$2"

    if [ "$WGET_EXIT" -ne 0 -a "$WGET_EXIT" -ne 8 -o -s "$WGET_OUT" ]; then
        echo "error while making a web request to \"$WGET_URI\"" >& 2
        echo "wget exit status: $WGET_EXIT" >& 2
        case "$WGET_EXIT" in
            # see man wget "EXIT STATUS"
             4) echo "  Network failure" >& 2;;
             5) echo "  SSL verification failure" >& 2;;
             8) echo "  Server issued an error response" >& 2;;
        esac

        cat "$WGET_OUT" >& 2
        cat "$RESP_HEABOD" >& 2

        exit 1
    elif [ "$WGET_EXIT" -eq 8 -a ! -s "$RESP_HEABOD" ] ;then
        echo "error while making a web request to \"$WGET_URI\"" >& 2
        echo "wget exit status: $WGET_EXIT" >& 2
        err_exit "Server issued an error response and no error document returned and no --content-on-error flag available. Upgrade your wget or use curl instead." 1
    fi

    tr -d '\r' < "$RESP_HEABOD" | sed -e '/^$/,$d' > "$RESP_HEADER"
    tr -d '\r' < "$RESP_HEABOD" | sed -e '1,/^$/d' > "$RESP_BODY"
}

handle_curl_exit() {
    CURL_EXIT="$1"
    CURL_URI="$2"

    if [ "$CURL_EXIT" "!=" 0 ]; then
        echo "error while making a web request to \"$CURL_URI\"" >& 2
        echo "curl exit status: $CURL_EXIT" >& 2
        case "$CURL_EXIT" in
            # see man curl "EXIT CODES"
             3) echo "  malformed URI" >& 2;;
             6) echo "  could not resolve host" >& 2;;
             7) echo "  failed to connect" >& 2;;
            28) echo "  operation timeout" >& 2;;
            35) echo "  SSL connect error" >& 2;;
            52) echo "  the server did not reply anything" >& 2;;
            56) echo "  failure in receiving network data" >& 2;;
        esac

        exit 1
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

fetch_http_status() {
    HTTP_STATUS="`sed -e '/^HTTP\// !d; s/^HTTP\/[0-9.]\{1,\}  *\([^ ]*\).*$/\1/' "$RESP_HEADER" | tail -n 1`"
}

check_http_status() {
    [ "$HTTP_STATUS" = "$1" ]
}

check_acme_error() {
    fgrep -q "urn:ietf:params:acme:error:$1" "$RESP_BODY"
}

unhandled_response() {
    echo "unhandled response while $1" >& 2
    echo >& 2

    cat "$RESP_HEADER" "$RESP_BODY" >& 2

    echo >& 2

    exit 1
}

show_error() {
    if [ -n "$1" ]; then
        echo "error while $1" >& 2
    fi

    ERR_TYPE="`tr -d '\r\n' < "$RESP_BODY" | sed -e 's/.*"type": *"\([^"]*\)".*/\1/'`"
    ERR_DETAILS="`tr -d '\r\n' < "$RESP_BODY" | sed -e 's/.*"detail": *"\([^"]*\)".*/\1/'`"


    echo "  $ERR_DETAILS ($ERR_TYPE)" >& 2
}

header_field_value() {
    grep -i -e "^$1:.*$2" "$RESP_HEADER" | sed -e 's/^[^:]*: *//' | tr -d '\r\n'
}

fetch_next_link() {
    header_field_value Link ';rel="next"' | sed -s 's/^.*<\(.*\)>.*$/\1/'
}

fetch_alternate_link() {
    header_field_value Link ';rel="alternate"' | sed -s 's/^.*<\(.*\)>.*$/\1/'
}

fetch_location() {
    header_field_value Location
}

# retrieve the nonce from the response header of the actual request for the forthcomming POST request

extract_nonce() {
    new_nonce="`header_field_value Replay-Nonce`"
    if [ -n "$new_nonce" ] ;then
        # Log if we had unnecesseraily multiple nonces, but use always the latest nonce
        [ -n "$NONCE" ] && log "droping unused nonce: $NONCE"
        NONCE="$new_nonce"
        dbgmsg "           new nonce: $NONCE"
    else
        dbgmsg "no new nonce"
    fi
}

retry_after() {
    header_field_value Retry-After
}

sleep_retryafter() {
    RETRY_AFTER="`retry_after`"
    if printf '%s' "$RETRY_AFTER" | egrep -s -q -e '^[1-9][0-9]*$' ;then
        if [ "$RETRY_AFTER" -gt 61 ] ;then
            log "Too big Retry-After header field value: $RETRY_AFTER"
            RETRY_AFTER=61
        fi
        [[ "$RETRY_AFTER" -eq 1 ]] && pluriel="" || pluriel="s"
        log "sleeping $RETRY_AFTER second$pluriel"
        sleep $RETRY_AFTER
    else
        log "Could not retrieve expected Retry-After header field value: $RETRY_AFTER"
        sleep 1
    fi
}

server_overload() {
    if check_http_status 503 && check_acme_error rateLimited ;then
        log "busy server rate limit condition"
        sleep_retryafter
        return 0
    else
        return 1
    fi
}

server_request() {
    dbgmsg "server_request: $1   $2"
    if [ "$USE_WGET" != yes ] ;then
        if [ -n "$2" ] ;then
            curl $CURLEXTRAFLAG -s $IPV_OPTION -A "$USER_AGENT" -D "$RESP_HEADER" -o "$RESP_BODY" -H "Content-type: application/jose+json" -d "$2" "$1"
        else
            curl $CURLEXTRAFLAG -s $IPV_OPTION -A "$USER_AGENT" -D "$RESP_HEADER" -o "$RESP_BODY" "$1"
        fi
        handle_curl_exit $? "$1"
    else
        if [ -n "$2" ] ;then
            wget $WGETEXTRAFLAG -q $IPV_OPTION -U "$USER_AGENT" --retry-connrefused --save-headers $WGETCOEFLAG -O "$RESP_HEABOD" --header="Content-type: application/jose+json" --post-data="$2" "$1" > "$WGET_OUT" 2>& 1
        else
            wget $WGETEXTRAFLAG -q $IPV_OPTION -U "$USER_AGENT" --retry-connrefused --save-headers $WGETCOEFLAG -O "$RESP_HEABOD" "$1" > "$WGET_OUT" 2>& 1
        fi
        handle_wget_exit $? "$1"
    fi
    fetch_http_status
}

request_acme_server() {
    while : ;do
        server_request "$1" "$2"
        extract_nonce
        server_overload || return
    done
}

# generate the PROTECTED variable, which contains a nonce retrieved from the
# server in the Replay-Nonce header

gen_protected(){
    if [ -z "$NONCE" ]; then
        dbgmsg "fetch new nonce"
        send_get_req "$NEWNONCEURL"
        [ -n "$NONCE" ] || err_exit "could not fetch new nonce"
    fi

    printf '%s' '{"alg":"RS256",'"$ACCOUNT_ID"',"nonce":"'"$NONCE"'","url":"'"$1"'"}'
}

# generate the signature for the request

gen_signature() {
    printf '%s' "$1" |
    openssl dgst -sha256 -binary -sign "$ACCOUNT_KEY" 2> "$OPENSSL_ERR"
    handle_openssl_exit "$?" "signing request"
}

# helper functions to create the json web key object

key_get_modulus(){
    openssl rsa -in "$1" -modulus -noout > "$OPENSSL_OUT" 2> "$OPENSSL_ERR"
    handle_openssl_exit $? "extracting account key modulus"

    sed -e 's/^Modulus=//' < "$OPENSSL_OUT" \
        | hex2bin \
        | base64url
}

key_get_exponent(){
    openssl rsa -in "$1" -text -noout > "$OPENSSL_OUT" 2> "$OPENSSL_ERR"
    handle_openssl_exit $? "extracting account key exponent"

    sed -e '/^publicExponent: / !d; s/^publicExponent: [0-9]* \{1,\}(\(.*\)).*$/\1/;s/^0x\([0-9a-fA-F]\)\(\([0-9a-fA-F][0-9a-fA-F]\)*\)$/0x0\1\2/;s/^0x\(\([0-9a-fA-F][0-9a-fA-F]\)*\)$/\1/' \
        < "$OPENSSL_OUT" \
        | hex2bin \
        | base64url
}

# make a request to the specified URI
# the payload is signed by the ACCOUNT_KEY
# the response header is stored in the file $RESP_HEADER, the body in the file $RESP_BODY

send_req_no_kid(){
    URI="$1"

    PAYLOAD="`printf '%s' "$2" | base64url`"
    while : ;do
        PROTECTED="`gen_protected "$URI" | base64url`"
        SIGNATURE="`gen_signature $PROTECTED.$PAYLOAD | base64url`"

        DATA='{"protected":"'"$PROTECTED"'","payload":"'"$PAYLOAD"'","signature":"'"$SIGNATURE"'"}'

        # Use only once a nonce
        NONCE=""

        request_acme_server "$URI" "$DATA"

        if ! check_http_status 400; then
            return
        elif ! check_acme_error badNonce ;then
            return
        fi
        if [ -z "$BAD_NONCE_MSG" ] ;then
            BAD_NONCE_MSG=yes
            echo "badNonce warning: other than extrem load on the ACME server," >& 2
            echo "this is mostly due to multiple client egress IP addresses," >& 2
            echo "including working IPv4 and IPv6 addresses on dual family systems." >& 2
            echo "In that case as a workaround please try to restrict the egress" >& 2
            echo "IP address with the -4 or -6 command line option on the script." >& 2
            echo "This message is just a warning, continuing safely." >& 2
        fi
        # Bad nonce condition. Here we do not sleep to be nice, just loop immediately.
        # The error cannot be on the client side, since it is guaranted that we used the latest available nonce.
    done
}

send_req(){
    URI="$1"

    [ -z "$KID" ] && register_account_key retrieve_kid

    send_req_no_kid "$1" "$2"
}

send_get_req(){
    request_acme_server "$1"
}

pwncheck(){
    server_request "https://v1.pwnedkeys.com/$1"
    if check_http_status 404; then
      log "pwnedkeys.com claims: $2 is not compromised"
      return 0
    elif check_http_status 200; then
      echo "pwnedkeys.com claims: $2 is compromised, fingerprint: $1" >& 2
      return 1
    fi
    unhandled_response "pwncheck"
}

pkey_hex_digest(){
    openssl dgst -sha256 -hex "$1" > "$OPENSSL_OUT" 2> "$OPENSSL_ERR"
    handle_openssl_exit $? "public key DER hexdigest"
    sed -e 's/^.*= *//' "$OPENSSL_OUT"
}

pwnedkey_req_check(){
    [ "$PWNEDKEY_CHECK" = no ] && return
    openssl req -in "$1" -noout -pubkey > "$OPENSSL_OUT" 2> "$OPENSSL_ERR"
    handle_openssl_exit $? "extracting request public key"
    cp "$OPENSSL_OUT" "$OPENSSL_IN"
    openssl rsa -in "$OPENSSL_IN" -pubin -outform der -pubout > "$OPENSSL_OUT" 2> "$OPENSSL_ERR"
    handle_openssl_exit $? "public key to DER"
    cp "$OPENSSL_OUT" "$OPENSSL_IN"
    pwncheck "`pkey_hex_digest "$OPENSSL_IN"`" "$2"
}

pwnedkey_key_check(){
    [ "$PWNEDKEY_CHECK" = no ] && return
    openssl rsa -in "$1" -outform der -pubout > "$OPENSSL_OUT" 2> "$OPENSSL_ERR"
    handle_openssl_exit $? "public key to DER"
    cp "$OPENSSL_OUT" "$OPENSSL_IN"
    pwncheck "`pkey_hex_digest "$OPENSSL_IN"`" "$2"
}

# account key handling

load_account_key(){
    [ -n "$ACCOUNT_KEY" ] || err_exit "no account key specified"
    [ -r "$ACCOUNT_KEY" ] || err_exit "could not read account key"

    openssl rsa -in "$ACCOUNT_KEY" -noout > "$OPENSSL_OUT" 2> "$OPENSSL_ERR"
    handle_openssl_exit $? "opening account key"

    ACCOUNT_JWK='{"e":"'"`key_get_exponent $ACCOUNT_KEY`"'","kty":"RSA","n":"'"`key_get_modulus $ACCOUNT_KEY`"'"}'
    ACCOUNT_ID='"jwk":'"$ACCOUNT_JWK"
    ACCOUNT_THUMB="`printf '%s' "$ACCOUNT_JWK" | openssl dgst -sha256 -binary | base64url`"

    if [ -z "$1" ] ;then
        if [ "$ACCOUNT_KEY" = "$SERVER_KEY" ] ;then
           # We should allow revoking with compromised certificate key too
           pwnedkey_key_check "$ACCOUNT_KEY" "server key as account key" || log "revoking certificate with compromised key"
        else
           pwnedkey_key_check "$ACCOUNT_KEY" "account key" || exit
        fi
    fi
}

get_one_url(){
    if ! egrep -s -q -e '"'"$1"'"' "$RESP_BODY" ;then
        cat "$RESP_BODY" >& 2
        err_exit "Cannot retrieve URL for $1 ACME protocol function from the directory $CADIR" 1
    fi
    tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/.*"'"$1"'":"\([^"]*\)".*/\1/'
}

get_urls(){
    if [ "$USE_WGET" = yes ] ;then
        WGETCOEFLAG='--content-on-error'
        wget --help | egrep -s -q -e "$WGETCOEFLAG" || WGETCOEFLAG=''
    fi

    send_get_req "$CADIR"
    if ! check_http_status 200 ;then
        unhandled_response "fetching directory URLs"
    fi

    NEWACCOUNTURL="`get_one_url newAccount`"
    REVOKECERTURL="`get_one_url revokeCert`"
     KEYCHANGEURL="`get_one_url keyChange`"
      NEWNONCEURL="`get_one_url newNonce`"
      NEWORDERURL="`get_one_url newOrder`"
}

orders_url() {
    tr -d ' \r\n' < "$RESP_BODY" | sed -e '/"orders":"/ !d; s/.*"orders":"\([^"]*\)".*/\1/'
}

orders_list() {
    tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/^.*"orders":\[\([^]]*\)\].*$/\1/' | tr -d '"' | tr ',' ' '
}

register_account_key(){

    [ -n "$NEWACCOUNTURL" ] || get_urls
    if [ -n "$ACCOUNT_EMAIL" ] ;then
      NEW_REG='{"termsOfServiceAgreed":true,"contact":["mailto:'"$ACCOUNT_EMAIL"'"]}'
    else
      NEW_REG='{"onlyReturnExisting":true}'
    fi
    send_req_no_kid "$NEWACCOUNTURL" "$NEW_REG"

    if check_http_status 200; then
        [ "$1" = "retrieve_kid" ] || err_exit "account already registered"
        KID="`fetch_location`"
        ACCOUNT_ID='"kid":"'"$KID"'"'
        ORDERS_URL="`orders_url`"
        return
    elif check_http_status 201; then
        KID="`fetch_location`"
        ACCOUNT_ID='"kid":"'"$KID"'"'
        ORDERS_URL="`orders_url`"
        return
    elif check_http_status 409; then
        [ "$1" = "nodie" ] || err_exit "account already exists"
    elif check_http_status 400 && check_acme_error accountDoesNotExist ;then
        show_error "fetching account information"
        exit 1
    else
        unhandled_response "registering account"
    fi
}

clrpenda() {
    ORDERS_LIST=""
    while [ -n "$ORDERS_URL" ]; do
        send_req "$ORDERS_URL" ""
        if check_http_status 200; then
            ORDERS_LIST="$ORDERS_LIST `orders_list`"
        else
            unhandled_response "retrieving orders list"
        fi
        ORDERS_URL="`fetch_next_link`"
    done

    DOMAIN_AUTHZ_LIST=""
    set -- $ORDERS_LIST

    for ORDER do
        send_req "$ORDER" ""
        if check_http_status 200; then
            ORDER_STATUS="`order_status`"
            if [ "$ORDER_STATUS" = pending ] ;then
                DOMAIN_AUTHZ_LIST="$DOMAIN_AUTHZ_LIST `domain_authz_list`"
            fi
        else
            unhandled_response "retrieving order"
        fi
    done

    # All domain should have that challenge type, even wildcard one
    CHALLENGE_TYPE=dns-01

    set -- $DOMAIN_AUTHZ_LIST

    for DOMAIN_AUTHZ do
        send_req "$DOMAIN_AUTHZ" ""
        if check_http_status 200; then
            DOMAIN="`authz_domain`"
            AUTHZ_STATUS="`authz_status`"
            if [ "$AUTHZ_STATUS" = pending ] ;then
                DOMAIN_URI="`authz_domain_uri`"
                log "retrieve challenge for $DOMAIN"
                request_domain_verification
            fi
        else
            unhandled_response "retrieve challenge for URL: $DOMAIN_AUTHZ"
        fi
    done
}

delete_account_key(){
    log "delete account"

    REG='{"resource":"reg","delete":"true"}'
    send_req "$REGISTRATION_URI" "$REG"

    if check_http_status 200; then
        return
    else
        unhandled_response "deleting account"
    fi
}

check_server_domain() {
    if [ "$2" = true ] ;then
        SERVER_DOMAIN="*.$1"
    else
        SERVER_DOMAIN="$1"
    fi
    SERVER_DOMAIN_LOWER="`tolower $SERVER_DOMAIN`"

    set -- $DOMAINS

    for REQ_DOMAIN do
        if [ "$SERVER_DOMAIN_LOWER" = "`tolower $REQ_DOMAIN`" ] ;then
            return
        fi
    done
    err_exit "ACME server requested authorization for a rogue domain: $SERVER_DOMAIN" 1
}

authz_status() {
    tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/.*"status":"\([^"]*\)".*/\1/'
}

authz_domain() {
    tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/.*"identifier":{"type":"dns","value":"\([^"]*\)"}.*/\1/'
}

wildcard_domain() {
    tr -d ' \r\n' < "$RESP_BODY" | sed -e '/"wildcard":/ !d; s/^.*"wildcard":\([a-z]*\).*$/\1/'
}

authz_domain_token() {
    tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/.*{\([^}]*"type":"'"$CHALLENGE_TYPE"'"[^}]*\)}.*/\1/; s/.*"token":"\([^"]*\)".*/\1/'
}

authz_domain_uri() {
    tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/.*{\([^}]*"type":"'"$CHALLENGE_TYPE"'"[^}]*\)}.*/\1/; s/.*"url":"\([^"]*\)".*/\1/'
}

request_challenge_domain(){

    send_req "$DOMAIN_AUTHZ" ""

    if check_http_status 200; then
        DOMAIN="`authz_domain`"
        AUTHZ_STATUS="`authz_status`"
        case "$AUTHZ_STATUS" in
            valid)
                log "authorization is valid for $DOMAIN"
                ;;
            pending)
                check_server_domain "$DOMAIN" "`wildcard_domain`"
                DOMAIN_TOKEN="`authz_domain_token`"
                DOMAIN_URI="`authz_domain_uri`"
                DOMAIN_DATA="$DOMAIN_DATA $DOMAIN $DOMAIN_URI $DOMAIN_TOKEN $DOMAIN_AUTHZ"
                log "retrieve challenge for $DOMAIN"
                ;;
            *)
                echo authorization status: "$AUTHZ_STATUS" >& 2
                unhandled_response "checking authorization status for domain $DOMAIN"
                ;;
        esac
    elif check_http_status 400; then
        # account not registred?
        show_error "retrieve challenge for URL: $DOMAIN_AUTHZ"
        exit 1
    elif check_http_status 403; then
        # account not registred?
        show_error "retrieve challenge for URL: $DOMAIN_AUTHZ"
        exit 1
    else
        unhandled_response "retrieve challenge for URL: $DOMAIN_AUTHZ"
    fi
}

domain_authz_list() {
    tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/^.*"authorizations":\[\([^]]*\)\].*$/\1/' | tr -d '"' | tr ',' ' '
}

finalize() {
    tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/^.*"finalize":"\([^"]*\).*$/\1/'
}

request_challenge(){
    log "creating new order"

    set -- $DOMAINS
    for DOMAIN do
         [ -n "$DOMAIN_ORDERS" ] && DOMAIN_ORDERS="$DOMAIN_ORDERS,"
         DOMAIN_ORDERS="$DOMAIN_ORDERS"'{"type":"dns","value":"'"$DOMAIN"'"}'
    done

    [ -n "$NEWORDERURL" ] || get_urls
    NEW_ORDER='{"identifiers":['"$DOMAIN_ORDERS"']}'
    send_req "$NEWORDERURL" "$NEW_ORDER"
    if check_http_status 201; then
        DOMAIN_AUTHZ_LIST="`domain_authz_list`"
        FINALIZE="`finalize`"
        CURRENT_ORDER="`fetch_location`"
    else
        unhandled_response "requesting new order for $DOMAINS"
    fi
    set -- $DOMAIN_AUTHZ_LIST
    for DOMAIN_AUTHZ do
        request_challenge_domain
    done

}

domain_commit() {
    if [ -n "$PUSH_TOKEN" ] && [ -n "$PUSH_TOKEN_COMMIT" ]; then
        log "calling $PUSH_TOKEN commit"
        $PUSH_TOKEN commit || err_exit "$PUSH_TOKEN could not commit"
        # We cannot know how long the execution of an external command will take.
        # Safer to force fetching a new nonce to avoid fatal badNonce error due to nonce validity timeout.
        NONCE=""
    fi
}

domain_dns_challenge() {
    DNS_CHALLENGE="`printf '%s' "$DOMAIN_TOKEN.$ACCOUNT_THUMB" | openssl dgst -sha256 -binary | base64url`"
    if [ -n "$PUSH_TOKEN" ]; then
        $PUSH_TOKEN "$1" _acme-challenge."$DOMAIN" "$DNS_CHALLENGE" || err_exit "Could not $1 $CHALLENGE_TYPE type challenge token with value $DNS_CHALLENGE for domain $DOMAIN via $PUSH_TOKEN"
    else
        printf 'update %s _acme-challenge.%s. 300 IN TXT "%s"\n\n' "$1" "$DOMAIN" "$DNS_CHALLENGE" |
            nsupdate || err_exit "Could not $1 $CHALLENGE_TYPE type challenge token with value $DNS_CHALLENGE for domain $DOMAIN via nsupdate"
    fi
}

push_domain_response() {
    log "push response for $DOMAIN"

    # do something with DOMAIN, DOMAIN_TOKEN and DOMAIN_RESPONSE
    # echo "$DOMAIN_RESPONSE" > "/writeable/location/$DOMAIN/$DOMAIN_TOKEN"

    if [ "$CHALLENGE_TYPE" = "http-01" ]; then
        if [ -n "$WEBDIR" ]; then
            TOKEN_DIR="`printf "%s" $WEBDIR | sed -e 's/\$DOMAIN/'"$DOMAIN"'/g; s/${DOMAIN}/'"$DOMAIN"'/g'`"
            SAVED_UMASK="`umask`"
            umask 0022
            printf "%s\n" "$DOMAIN_TOKEN.$ACCOUNT_THUMB" > "$TOKEN_DIR/$DOMAIN_TOKEN" || exit 1
            umask "$SAVED_UMASK"
        elif [ -n "$PUSH_TOKEN" ]; then
            $PUSH_TOKEN install "$DOMAIN" "$DOMAIN_TOKEN" "$ACCOUNT_THUMB" || err_exit "could not install token for $DOMAIN"
        fi
    elif [ "$CHALLENGE_TYPE" = "dns-01" ]; then
        domain_dns_challenge "add"
    else
        echo "unsupported challenge type for install token: $CHALLENGE_TYPE" >& 2; exit 1
    fi

    return
}

remove_domain_response() {
    log "remove response for $DOMAIN"

    # do something with DOMAIN and DOMAIN_TOKEN
    # rm "/writeable/location/$DOMAIN/$DOMAIN_TOKEN"

    if [ "$CHALLENGE_TYPE" = "http-01" ]; then
        if [ -n "$WEBDIR" ]; then
            TOKEN_DIR="`printf "%s" $WEBDIR | sed -e 's/\$DOMAIN/'"$DOMAIN"'/g; s/${DOMAIN}/'"$DOMAIN"'/g'`"
            rm -f "$TOKEN_DIR/$DOMAIN_TOKEN"
        elif [ -n "$PUSH_TOKEN" ]; then
            $PUSH_TOKEN remove "$DOMAIN" "$DOMAIN_TOKEN" "$ACCOUNT_THUMB" || exit 1
        fi
    elif [ "$CHALLENGE_TYPE" = "dns-01" ]; then
        domain_dns_challenge "delete"
    else
        echo "unsupported challenge type for remove token: $CHALLENGE_TYPE" >& 2; exit 1
    fi

    return
}

push_response() {
    set -- $DOMAIN_DATA
    while [ -n "$1" ]; do
        DOMAIN="$1"
        DOMAIN_URI="$2"
        DOMAIN_TOKEN="$3"
        DOMAIN_AUTHZ="$4"

        shift 4
    
        push_domain_response
    done
    domain_commit
}

request_domain_verification() {
    log request verification of $DOMAIN

    send_req $DOMAIN_URI '{}'
    dbgmsg "Retry-After value in request_domain_verification: `retry_after`"

    if check_http_status 200; then
        return
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
        DOMAIN_AUTHZ="$4"
    
        shift 4

        request_domain_verification
    done
}

domain_status() {
    tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/.*"type":"'"$CHALLENGE_TYPE"'",[^{}]*"status":"\([^"]*\)".*/\1/'
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
            DOMAIN_AUTHZ="$4"
        
            shift 4
        
            log check verification of $DOMAIN

            send_req "$DOMAIN_AUTHZ" ""
            dbgmsg "Retry-After value in check_verification: `retry_after`"
        
            if check_http_status 200; then
                DOMAIN_STATUS="`domain_status`"
                case "$DOMAIN_STATUS" in
                    valid)
                        log $DOMAIN is valid
                        remove_domain_response
                        ;;
                    invalid)
                        echo $DOMAIN: invalid >& 2
                        show_error
                        remove_domain_response

                        ALL_VALID=false
                        ;;
                    pending)
                        log $DOMAIN is pending
                        DOMAIN_DATA="$DOMAIN_DATA $DOMAIN $DOMAIN_URI $DOMAIN_TOKEN $DOMAIN_AUTHZ"
                        ;;
                    *)
                        unhandled_response "checking verification status of $DOMAIN: $DOMAIN_STATUS"
                        ;;
                esac
            else
                unhandled_response "checking verification status of $DOMAIN"
            fi
        done
    done
    domain_commit

    $ALL_VALID || exit 1

    log checking order
    while : ;do
        send_req "$CURRENT_ORDER" ""
        if check_http_status 200; then
            ORDER_STATUS="`order_status`"
            case "$ORDER_STATUS" in
                ready)
                    log order is ready
                    break
                    ;;
                pending)
                    echo order: "$ORDER_STATUS" >& 2
                    sleep 1
                    continue
                    ;;
                *)
                    unhandled_response "checking verification status of order"
                    ;;
            esac
        else
            unhandled_response "requesting order status verification"
        fi
    done
}

# this function generates the csr from the private server key and list of domains

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

    pwnedkey_key_check "$SERVER_KEY" "server key" || exit
}

subject_domain() {
    sed -n '/Subject:/ {s/^.*CN=//; s/[,/ 	].*$//; p}' "$OPENSSL_OUT"
}

san_domains() {
    sed -n '/X509v3 Subject Alternative Name:/ { n; s/^[	 ]*DNS[	 ]*:[	 ]*//; s/[	 ]*,[	 ]*DNS[	 ]*:[	 ]*/ /g; p; q; }' "$OPENSSL_OUT"
}

csr_extract_domains() {
    log "extract domains from certificate signing request"

    if echo "$CADIR" | egrep -i -s -q -e '\.buypass\.(com|no)/' -e '\.letsencrypt\.org/' ;then
        # Known ACME servers supporting commonName in the Subject of the CSR
        Subject_commonName_support=yes
    else
        # ACME server(s) do not supporting commonName in the Subject of the CSR
        # Typically pebble's case, see https://github.com/letsencrypt/pebble/issues/304
        Subject_commonName_support=no
    fi

    openssl req -in "$TMP_SERVER_CSR" -noout -text \
        > "$OPENSSL_OUT" \
        2> "$OPENSSL_ERR"
    handle_openssl_exit $? "reading certificate signing request"

    ALTDOMAINS="`san_domains`"
    SUBJDOMAIN="`subject_domain`"

    if [ "$Subject_commonName_support" = yes ] ;then
        DOMAINS="$SUBJDOMAIN $ALTDOMAINS"
    else
        DOMAINS="$ALTDOMAINS"
    fi

    pwnedkey_req_check "$TMP_SERVER_CSR" "certificate signing request key" || exit
}

certificate_extract_domains() {
    log "extract domains from certificate"

    openssl x509 -in "$SERVER_CERT" -noout -text \
        > "$OPENSSL_OUT" \
        2> "$OPENSSL_ERR"
    handle_openssl_exit $? "reading certificate"

    DOMAINS="`san_domains`"
    if [ -z "$DOMAINS" ]; then
        DOMAINS="`subject_domain`"
    fi
}

new_cert() {
    sed -e 's/-----BEGIN\( NEW\)\{0,1\} CERTIFICATE REQUEST-----/{"csr":"/; s/-----END\( NEW\)\{0,1\} CERTIFICATE REQUEST-----/"}/;s/+/-/g;s!/!_!g;s/=//g' "$TMP_SERVER_CSR" | tr -d ' \t\r\n'
}

order_status() {
    tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/.*"status":"\([^"]*\)".*/\1/'
}

certificate_url() {
    tr -d ' \r\n' < "$RESP_BODY" | sed -e 's/.*"certificate":"\([^"]*\)".*/\1/'
}

request_certificate(){
    log finalize order

    NEW_CERT="`new_cert`"
    send_req "$FINALIZE" "$NEW_CERT"
    while : ;do
    
        if check_http_status 200; then
            ORDER_STATUS="`order_status`"
            case "$ORDER_STATUS" in
                valid)
                    log order is valid
                    CERTIFICATE="`certificate_url`"
                    break
                    ;;
                processing)
                    log order: "$ORDER_STATUS"
                    sleep 1
                    send_req "$CURRENT_ORDER" ""
                    continue
                    ;;
                invalid|pending|ready)
                    echo order: "$ORDER_STATUS" >& 2
                    exit 1
                    ;;
                *)
                    unhandled_response "checking finalization status of order"
                    ;;
            esac
        else
            unhandled_response "requesting order finalization"
        fi
    done
    log request certificate
    CUR_CHAIN=0
    while [ -n "$CERTIFICATE" ] ;do
        send_req "$CERTIFICATE" ""
        if check_http_status 200; then
            if [ "$CUR_CHAIN" = "$SIGNING_CHAIN_SELECTION" ] ;then
                if [ -n "$SERVER_FULL_CHAIN" ] ;then
                    tr -d '\r' < "$RESP_BODY"               | sed -e '/^$/d' > "$SERVER_FULL_CHAIN"
                fi
                tr -d '\r' < "$RESP_BODY" |
                sed -e '1,/^-----END CERTIFICATE-----$/ !d' | sed -e '/^$/d' > "$SERVER_CERT"
                tr -d '\r' < "$RESP_BODY" |
                sed -e '1,/^-----END CERTIFICATE-----$/d'   | sed -e '/^$/d' > "$SERVER_SIGNING_CHAIN"
                break
            else
                CERTIFICATE="`fetch_alternate_link`"
                CUR_CHAIN="`expr $CUR_CHAIN + 1`"
                if [ -z "$CERTIFICATE" ] ;then
                    err_exit "No such alternate chain: $SIGNING_CHAIN_SELECTION" 1
                fi
            fi
        else
            unhandled_response "retrieveing certificate"
        fi
    done
}

old_cert() {
    sed -e 's/-----BEGIN CERTIFICATE-----/{"certificate":"/; s/-----END CERTIFICATE-----/"}/;s/+/-/g;s!/!_!g;s/=//g' "$SERVER_CERT" | tr -d ' \t\r\n'
}

revoke_certificate(){
    log revoke certificate

    [ -n "$REVOKECERTURL" ] || get_urls
    OLD_CERT="`old_cert`"
    if [ "$ACCOUNT_KEY" = "$SERVER_KEY" ] ;then
        send_req_no_kid "$REVOKECERTURL" "$OLD_CERT"
        if check_http_status 400; then
            show_error "revoking certificate via server key"
            exit 1
        elif check_http_status 200; then
            log certificate is revoked via server key
            exit 0
        else
            unhandled_response "revoking certificate"
        fi
    else
        send_req "$REVOKECERTURL" "$OLD_CERT"
        if check_http_status 403 || check_http_status 401; then
            if check_acme_error unauthorized ;then
                return 1
            else
                unhandled_response "revoking certificate"
            fi
        elif check_http_status 400; then
            show_error "revoking certificate via account key"
            exit 1
        elif check_http_status 200; then
            log certificate is revoked via account key
        else
            unhandled_response "revoking certificate"
        fi
    fi
}

usage() {
    cat << EOT
$PROGNAME register [-p] -a account_key -e email
$PROGNAME delete -a account_key
$PROGNAME clrpenda -a account_key
$PROGNAME thumbprint -a account_key
$PROGNAME revoke {-a account_key|-k server_key} -c signed_crt
$PROGNAME sign -a account_key -k server_key (chain_options) -c signed_crt domain ...
$PROGNAME sign -a account_key -r server_csr (chain_options) -c signed_crt

    -a account_key    the private key
    -e email          the email address assigned to the account key during
                      the registration
    -k server_key     the private key of the server certificate
    -r server_csr     a certificate signing request, which includes the
                      domains, use e.g. gen-csr.sh to create one
    -c signed_crt     the location where to store the signed certificate
                      or retrieve for revocation

  Options for sign operation:
    -t selection      signing chain selection (number only, default: 0)
    -s signing_crt    the location, where the intermediate signing
                      certificate(s) should be stored
                      default location: {signed_crt}_chain
    -f full_chain     the location, where the signed certificate with the
                      intermediate signing certificate(s) should be stored

  ACME server options:
    -D URL            ACME server directory URL
    -4                the connection to the server should use IPv4
    -6                the connection to the server should use IPv6

  generic flags:
    -h                this help page
    -q                quiet operation
    -v                increase verbosity

  revoke and sign:
    -l challenge_type can be http-01 (default) or dns-01
    -w webdir         the directory, where the response should be stored
                      \$DOMAIN will be replaced by the actual domain
                      the directory will not be created
    -P exec           the command to call to install the token on a remote
                      server
    -C                the command to call to install the token on a remote
                      server needs the commit feature
  clrpenda:           clear pending authorizations for the given account
EOT
}

# Here starts the program

PROGNAME="`basename $0`"

required_commands

# temporary files to store input/output of curl or openssl

trap 'rm -f "$RESP_HEABOD" "$WGET_OUT" "$RESP_HEADER" "$RESP_BODY" "$OPENSSL_CONFIG" "$OPENSSL_IN" "$OPENSSL_OUT" "$OPENSSL_ERR" "$TMP_SERVER_CSR"' 0 1 2 3 13 15

# file to store header and body of http response
RESP_HEABOD="`mktemp -t le.$$.resp-heabod.XXXXXX`"
# file to store the output of the wget
WGET_OUT="`mktemp -t le.$$.resp-out.XXXXXX`"
# file to store header of http request
RESP_HEADER="`mktemp -t le.$$.resp-header.XXXXXX`"
# file to store body of http request
RESP_BODY="`mktemp -t le.$$.resp-body.XXXXXX`"
# tmp config for openssl for addional domains
OPENSSL_CONFIG="`mktemp -t le.$$.openssl.cnf.XXXXXX`"
# file to store openssl output
OPENSSL_IN="`mktemp -t le.$$.openssl.in.XXXXXX`"
OPENSSL_OUT="`mktemp -t le.$$.openssl.out.XXXXXX`"
OPENSSL_ERR="`mktemp -t le.$$.openssl.err.XXXXXX`"
# file to store the CSR
TMP_SERVER_CSR="`mktemp -t le.$$.server.csr.XXXXXX`"

echo 'x\0040x' | egrep -s -q -e 'x x' && ECHOESCFLAG='' || ECHOESCFLAG='-e'

[ $# -gt 0 ] || err_exit "no action given"

ACTION="$1"
shift

SHOW_THUMBPRINT=0

case "$ACTION" in
    clrpenda)
        while getopts :hqvD:46a: name; do case "$name" in
            h) usage; exit 1;;
            q) LOGLEVEL=0;;
            v) LOGLEVEL="`expr $LOGLEVEL + 1`";;
            D) CADIR="$OPTARG";;
            4) IPV_OPTION="-4";;
            6) IPV_OPTION="-6";;
            a) ACCOUNT_KEY="$OPTARG";;
            ?|:) echo "invalid arguments" >& 2; exit 1;;
        esac; done;;
    delete)
        while getopts :hqvD:46a: name; do case "$name" in
            h) usage; exit 1;;
            q) LOGLEVEL=0;;
            v) LOGLEVEL="`expr $LOGLEVEL + 1`";;
            D) CADIR="$OPTARG";;
            4) IPV_OPTION="-4";;
            6) IPV_OPTION="-6";;
            a) ACCOUNT_KEY="$OPTARG";;
            ?|:) echo "invalid arguments" >& 2; exit 1;;
        esac; done;;
    register)
        while getopts :hqvD:46a:e:p name; do case "$name" in
            h) usage; exit 1;;
            q) LOGLEVEL=0;;
            v) LOGLEVEL="`expr $LOGLEVEL + 1`";;
            D) CADIR="$OPTARG";;
            4) IPV_OPTION="-4";;
            6) IPV_OPTION="-6";;
            p) SHOW_THUMBPRINT=1;;
            a) ACCOUNT_KEY="$OPTARG";;
            e) ACCOUNT_EMAIL="$OPTARG";;
            ?|:) echo "invalid arguments" >& 2; exit 1;;
        esac; done;;
    thumbprint)
        while getopts :hqva: name; do case "$name" in
            h) usage; exit 1;;
            q) LOGLEVEL=0;;
            v) LOGLEVEL="`expr $LOGLEVEL + 1`";;
            a) ACCOUNT_KEY="$OPTARG";;
            ?|:) echo "invalid arguments" >& 2; exit 1;;
        esac; done;;
    revoke)
        while getopts :hqvD:46Ca:k:c:w:P:l: name; do case "$name" in
            h) usage; exit 1;;
            q) LOGLEVEL=0;;
            v) LOGLEVEL="`expr $LOGLEVEL + 1`";;
            D) CADIR="$OPTARG";;
            4) IPV_OPTION="-4";;
            6) IPV_OPTION="-6";;
            C) PUSH_TOKEN_COMMIT=1;;
            a) ACCOUNT_KEY="$OPTARG";;
            k) SERVER_KEY="$OPTARG";;
            c) SERVER_CERT="$OPTARG";;
            w) WEBDIR="$OPTARG";;
            P) PUSH_TOKEN="$OPTARG";;
            l) CHALLENGE_TYPE="$OPTARG";;
            ?|:) echo "invalid arguments" >& 2; exit 1;;
        esac; done;;
    sign)
        while getopts :hqvD:46Ca:k:r:f:s:c:w:P:l:t: name; do case "$name" in
            h) usage; exit 1;;
            q) LOGLEVEL=0;;
            v) LOGLEVEL="`expr $LOGLEVEL + 1`";;
            D) CADIR="$OPTARG";;
            4) IPV_OPTION="-4";;
            6) IPV_OPTION="-6";;
            C) PUSH_TOKEN_COMMIT=1;;
            a) ACCOUNT_KEY="$OPTARG";;
            k)
                if [ -n "$SERVER_CSR" ]; then
                    echo "server key and server certificate signing request are mutual exclusive" >& 2
                    exit 1
                fi
                SERVER_KEY="$OPTARG"
                ACTION=sign-key
                ;;
            r)
                if [ -n "$SERVER_KEY" ]; then
                    echo "server key and server certificate signing request are mutual exclusive" >& 2
                    exit 1
                fi
                SERVER_CSR="$OPTARG"
                ACTION=sign-csr
                ;;
            f) SERVER_FULL_CHAIN="$OPTARG";;
            s) SERVER_SIGNING_CHAIN="$OPTARG";;
            c) SERVER_CERT="$OPTARG";;
            w) WEBDIR="$OPTARG";;
            P) PUSH_TOKEN="$OPTARG";;
            l) CHALLENGE_TYPE="$OPTARG";;
            t) SIGNING_CHAIN_SELECTION="$OPTARG";;
            ?|:) echo "invalid arguments" >& 2; exit 1;;
        esac; done;;
    -h|--help|-?)
        usage
        exit 1
        ;;
    *)
        err_exit "invalid action: $ACTION" 1 ;;
esac

shift $(($OPTIND - 1))

case "$CHALLENGE_TYPE" in
  http-01)
    DOMAIN_EXTRA_PAT=''
    ;;
  dns-01)
    DOMAIN_EXTRA_PAT='\(\*\.\)\{0,1\}'
    ;;
  *)
    echo "unsupported challenge type: $CHALLENGE_TYPE" >& 2; exit 1
    ;;
esac

printf '%s\n' "$SIGNING_CHAIN_SELECTION" | egrep -s -q -e '^[0-9]+$' ||
    err_exit "Unsupported signing chain selection" 1

case "$ACTION" in
    clrpenda)
        load_account_key
        register_account_key retrieve_kid
        clrpenda
        exit;;

    delete)
        load_account_key
        register_account_key nodie
        REGISTRATION_URI="`fetch_location`"
        delete_account_key
        exit 0;;

    register)
        load_account_key
        [ -z "$ACCOUNT_EMAIL" ] && echo "account email address not given" >& 2 && exit 1
        log "register account"
        register_account_key
        [ $SHOW_THUMBPRINT -eq 1 ] && printf "account thumbprint: %s\n" "$ACCOUNT_THUMB"
        exit 0;;

    thumbprint)
        load_account_key no_pwnd_check
        printf "account thumbprint: %s\n" "$ACCOUNT_THUMB"
        exit 0;;

    revoke)
        [ -n "$SERVER_CERT" ] || err_exit "no certificate file given to revoke"
        [ -z "$ACCOUNT_KEY" -a -z "$SERVER_KEY" ] && echo "either account key or server key must be given" >& 2 && exit 1
        [ -n "$ACCOUNT_KEY" ] || { log "using server key as account key" ; ACCOUNT_KEY="$SERVER_KEY" ; }
        load_account_key
        revoke_certificate && exit 0
        certificate_extract_domains;;

    sign) err_exit "neither server key nor server csr given" 1 ;;

    sign-key)
        load_account_key
        [ -r "$SERVER_KEY" ] || err_exit "could not read server key"
        [ -n "$SERVER_CERT" ] || err_exit "no output file given"

        [ "$#" -gt 0 ] || err_exit "domains needed"
        DOMAINS=$*
        gen_csr_with_private_key
        ;;

    sign-csr)
        load_account_key
        [ -r "$SERVER_CSR" ] || err_exit "could not read certificate signing request"
        [ -n "$SERVER_CERT" ] || err_exit "no output file given"

        [ "$#" -eq 0 ] || err_exit "no domains needed"

        # load domains from csr
        openssl req -in "$SERVER_CSR" > "$TMP_SERVER_CSR" 2> "$OPENSSL_ERR"
        handle_openssl_exit "$?" "copying csr"
        csr_extract_domains
        ;;

    *)
        err_exit "invalid action: $ACTION" 1 ;;
esac

[ -n "$WEBDIR" ] && [ "$CHALLENGE_TYPE" = "dns-01" ] &&
    err_exit "webdir option and dns-01 challenge type are mutual exclusive" 1

if [ "$CHALLENGE_TYPE" = "http-01" ] ;then
    [ -n "$WEBDIR" ] && [ -n "$PUSH_TOKEN" ] &&
        err_exit "webdir option and command to install the token are mutual exclusive" 1
    [ -z "$WEBDIR" ] && [ -z "$PUSH_TOKEN" ] &&
        err_exit "either webdir option or command to install the token must be specified" 1
fi

[ -z "$PUSH_TOKEN" ] && [ -n "$PUSH_TOKEN_COMMIT" ] &&
    err_exit "commit feature without command to install the token makes no sense" 1

if [ -z "$SERVER_SIGNING_CHAIN" ] ;then
    SERVER_SIGNING_CHAIN="$SERVER_CERT"_chain
fi

request_challenge
push_response
request_verification
check_verification
if [ "$ACTION" = "revoke" ] ;then
  revoke_certificate || { show_error "revoking certificate via account key" ; exit 1 ; }
else
  request_certificate
fi
