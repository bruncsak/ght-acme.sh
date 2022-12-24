#!/bin/sh
# Example push script using the IONOS DNS API.
# This is very quick-and-dirty and could be polished a lot,
# but should be sufficient to get anyone started.
# Patches to improve welcome.
COMMAND='{ "disabled": true, "content": "null" }'
if [ "$1" = "add" ] ; then
  COMMAND='{ "disabled": false, "content": "'$3'" }'
fi
# Note: this script is only able to update existing entries
# to reduce the risk of making a mess and to make it simpler
# so you must create all _acme-challenge DNS entries before using it
URL="https://api.hosting.ionos.com/dns/v1/zones/<insert you zone ID>/records/<insert your _acme-challenge entry ID>"
# add a condition on to make URL depend on $2 to support multiple domains

# header.txt should contain your API key
# Could also use the -H @header.txt syntax,
# then header.txt only consists of
# X-API-Key: publicprefix.encryptionkey
curl -X PUT "$URL" -K header.txt -H 'accept: application/json' -H 'Content-Type: application/json' -d "$COMMAND"
