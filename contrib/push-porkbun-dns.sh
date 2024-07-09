#!/bin/sh
# The API keys need to be in the apikey-porkbun.txt file,
# just by themselves with no prefix
# Note: assumes domain.ext format, you'll need to change the
# logic to get SUBDOMAIN for .co.uk and similar domains
DNSENTRY=$2
SUBDOMAIN=${DNSENTRY%.*.*}
DOMAIN=${DNSENTRY#$SUBDOMAIN.}

if [ ! -r apikey-porkbun.txt ] ; then
  echo "missing apikey file"
  exit 1
fi

AUTHDATA='"apikey": "'"$(grep ^pk apikey-porkbun.txt)"'",
"secretapikey": "'"$(grep ^sk apikey-porkbun.txt)"'"'

if [ "$SUBDOMAIN" = "${SUBDOMAIN#_acme-challenge}" ]; then
  # sanity check to avoid disasters
  echo "Not starting with _acme-challenge: $DNSENTRY - aborting"
  exit 1
fi

# Try to delete for all commands, in particular for "add".
# This avoids a failure when the entry already exists.
# Not the most clean way (there is also an edit command
# that could be used), but this is simplest
curl -X POST "https://porkbun.com/api/json/v3/dns/deleteByNameType/$DOMAIN/TXT/$SUBDOMAIN" --json @- <<EOF
{
$AUTHDATA
}
EOF
if [ "$1" = "add" ] ; then
curl -X POST "https://porkbun.com/api/json/v3/dns/create/$DOMAIN" --json @- <<EOF
{
$AUTHDATA,
"name": "$SUBDOMAIN",
"type": "TXT",
"content": "$3",
"ttl": 600
}
EOF
# unfortunately it takes a while before the entry is visible.
# just wait 10 seconds for now, there are certainly more robust/
# faster ways
sleep 10
fi
