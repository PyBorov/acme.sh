#!/usr/bin/env sh

# ps.kz DNS API
# Author: PyBorov
# Repository: https://github.com/PyBorov/certbot-dns-pskz
#
# Usage:
#   export PSKZ_Token="secret.accountId.userId"
#   acme.sh --issue --dns dns_pskz -d example.kz -d '*.example.kz'
#
# The token is generated in the ps.kz console and is bound to a single
# ps.kz account at creation time. If your zones are spread across
# multiple accounts you need one token (and one acme.sh account conf /
# invocation) per account.

PSKZ_API="https://console.ps.kz/dns/graphql"

########  Public functions #####################

# Usage: dns_pskz_add   _acme-challenge.www.domain.com   "XKrxpRBosdIKFzxW_CT3KLZNf6q0HG9i01zxXp5CPBs"
dns_pskz_add() {
  fulldomain=$1
  txtvalue=$2

  PSKZ_Token="${PSKZ_Token:-$(_readaccountconf_mutable PSKZ_Token)}"
  if [ -z "$PSKZ_Token" ]; then
    PSKZ_Token=""
    _err "You didn't specify the ps.kz API token yet."
    _err "Please create one in the ps.kz console and export it as PSKZ_Token."
    return 1
  fi
  _saveaccountconf_mutable PSKZ_Token "$PSKZ_Token"

  _info "Using ps.kz api"
  _debug fulldomain "$fulldomain"
  _debug txtvalue "$txtvalue"

  if ! _pskz_find_zone "$fulldomain"; then
    _err "Unable to find a ps.kz zone matching $fulldomain with this token."
    return 1
  fi
  _debug _pskz_zone "$_pskz_zone"

  _info "Adding TXT record"
  data="{\"query\":\"mutation CreateDNSRecord(\$zoneName: String!, \$recordData: RecordCreateInput!) { dns { record { create(zoneName: \$zoneName, createData: \$recordData) { name } } } }\",\"variables\":{\"zoneName\":\"$_pskz_zone\",\"recordData\":{\"name\":\"${fulldomain}.\",\"type\":\"TXT\",\"value\":\"$txtvalue\",\"ttl\":60}}}"

  export _H1="Content-Type: application/json"
  export _H2="X-User-Token: $PSKZ_Token"
  response="$(_post "$data" "$PSKZ_API" "" "POST")"
  _debug2 response "$response"

  if _contains "$response" "\"errors\""; then
    _err "ps.kz API returned an error while creating the TXT record: $response"
    return 1
  fi

  return 0
}

# Usage: dns_pskz_rm   _acme-challenge.www.domain.com   "XKrxpRBosdIKFzxW_CT3KLZNf6q0HG9i01zxXp5CPBs"
dns_pskz_rm() {
  fulldomain=$1
  txtvalue=$2

  PSKZ_Token="${PSKZ_Token:-$(_readaccountconf_mutable PSKZ_Token)}"
  if [ -z "$PSKZ_Token" ]; then
    _err "You didn't specify the ps.kz API token yet."
    return 1
  fi

  if ! _pskz_find_zone "$fulldomain"; then
    _info "Unable to resolve a ps.kz zone for $fulldomain, nothing to clean up."
    return 0
  fi

  export _H1="Content-Type: application/json"
  export _H2="X-User-Token: $PSKZ_Token"

  lookup_data="{\"query\":\"query GetZoneRecords(\$domainName: String!) { dns { zone(name: \$domainName) { records { id name type value } } } }\",\"variables\":{\"domainName\":\"$_pskz_zone\"}}"
  lookup_response="$(_post "$lookup_data" "$PSKZ_API" "" "POST")"
  _debug2 lookup_response "$lookup_response"

  record_id=$(_pskz_extract_record_id "$lookup_response" "${fulldomain}." "$txtvalue")

  if [ -z "$record_id" ]; then
    _info "TXT record for $fulldomain not found during cleanup, nothing to do."
    return 0
  fi

  delete_data="{\"query\":\"mutation DeleteDnsRecord(\$zoneName: String!, \$recordId: String!) { dns { record { delete(zoneName: \$zoneName, recordId: \$recordId) { id } } } }\",\"variables\":{\"zoneName\":\"$_pskz_zone\",\"recordId\":\"$record_id\"}}"
  _post "$delete_data" "$PSKZ_API" "" "POST" >/dev/null

  return 0
}

####################  Private functions below ##################################

# _pskz_find_zone fulldomain
# Walks up the label hierarchy of $1 (e.g. _acme-challenge.wiki.example.kz
# -> wiki.example.kz -> example.kz -> kz) until it finds a zone this
# token has access to. Sets $_pskz_zone (with the trailing dot, as
# returned by the API) on success.
_pskz_find_zone() {
  candidate="$1"

  while true; do
    export _H1="Content-Type: application/json"
    export _H2="X-User-Token: $PSKZ_Token"
    query="{\"query\":\"query(\$s: String){ dns { zones(searchName: \$s, perPage: 20) { items { name } } } }\",\"variables\":{\"s\":\"$candidate\"}}"

    response="$(_post "$query" "$PSKZ_API" "" "POST")"
    _debug2 _pskz_find_zone_response "$response"

    if _contains "$response" "\"name\":\"${candidate}.\""; then
      _pskz_zone="${candidate}."
      return 0
    fi

    case "$candidate" in
      *.*) candidate="${candidate#*.}" ;;
      *) return 1 ;;
    esac
  done
}

# _pskz_extract_record_id response fulldomain_dot txtvalue
# Crude single-pass JSON scan (no jq dependency, per acme.sh convention):
# finds the record object containing both the expected "name" and
# "value", and returns its "id". This is a best-effort parser suitable
# for the flat, single-line JSON ps.kz's API returns; it is not a
# general-purpose JSON parser.
_pskz_extract_record_id() {
  _resp="$1"
  _name="$2"
  _value="$3"

  # Split the records array on "},{" boundaries so each chunk is one
  # record object, then grep for the one matching both name and value.
  echo "$_resp" \
    | sed 's/},{/}\n{/g' \
    | grep "\"name\":\"$_name\"" \
    | grep "\"value\":\"$_value\"" \
    | _egrep_o '"id":"[^"]*"' \
    | head -n 1 \
    | cut -d'"' -f4
}
