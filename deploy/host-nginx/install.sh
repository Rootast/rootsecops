#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "$script_dir/../.." && pwd)"
env_file="${1:-$project_dir/.env}"

if [[ ! -f "$env_file" ]]; then
  echo "Environment file not found: $env_file" >&2
  exit 1
fi
env_file="$(cd "$(dirname "$env_file")" && pwd)/$(basename "$env_file")"

if [[ $EUID -ne 0 ]]; then
  exec sudo "$0" "$env_file"
fi

env_value() {
  local key="$1"
  local value
  value="$(sed -n "s/^${key}=//p" "$env_file" | tail -n 1 | tr -d '\r')"
  if [[ ${#value} -ge 2 ]]; then
    if [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]] || \
       [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
      value="${value:1:${#value}-2}"
    fi
  fi
  printf '%s' "$value"
}

FRONT_DOMAIN="$(env_value FRONT_DOMAIN)"
API_DOMAIN="$(env_value API_DOMAIN)"
FRONTEND_PORT="$(env_value FRONTEND_PORT)"
BACKEND_PORT="$(env_value BACKEND_PORT)"
CLIENT_MAX_BODY_SIZE="$(env_value CLIENT_MAX_BODY_SIZE)"
TLS_CERT_DAYS="$(env_value TLS_CERT_DAYS)"

: "${FRONT_DOMAIN:?FRONT_DOMAIN is required in .env}"
: "${API_DOMAIN:?API_DOMAIN is required in .env}"

FRONTEND_PORT="${FRONTEND_PORT:-3000}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
CLIENT_MAX_BODY_SIZE="${CLIENT_MAX_BODY_SIZE:-100m}"
TLS_CERT_DAYS="${TLS_CERT_DAYS:-365}"

for domain in "$FRONT_DOMAIN" "$API_DOMAIN"; do
  if [[ ! "$domain" =~ ^[A-Za-z0-9.-]+$ ]]; then
    echo "Invalid domain: $domain" >&2
    exit 1
  fi
done
for port in "$FRONTEND_PORT" "$BACKEND_PORT"; do
  if [[ ! "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
    echo "Invalid local proxy port: $port" >&2
    exit 1
  fi
done
if [[ ! "$CLIENT_MAX_BODY_SIZE" =~ ^[0-9]+[kKmMgG]?$ ]]; then
  echo "Invalid CLIENT_MAX_BODY_SIZE: $CLIENT_MAX_BODY_SIZE" >&2
  exit 1
fi
if [[ ! "$TLS_CERT_DAYS" =~ ^[0-9]+$ ]] || ((TLS_CERT_DAYS < 1)); then
  echo "Invalid TLS_CERT_DAYS: $TLS_CERT_DAYS" >&2
  exit 1
fi

cert_dir=/etc/nginx/ssl/rootsecops
cert_file="$cert_dir/tls.crt"
key_file="$cert_dir/tls.key"
domain_file="$cert_dir/domains"
domain_pair="$FRONT_DOMAIN,$API_DOMAIN"
install -d -m 0755 "$cert_dir" /etc/nginx/sites-available /etc/nginx/sites-enabled

stored_domains=""
[[ -f "$domain_file" ]] && stored_domains="$(<"$domain_file")"
if [[ ! -s "$cert_file" || ! -s "$key_file" || "$stored_domains" != "$domain_pair" ]]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes \
    -days "$TLS_CERT_DAYS" \
    -keyout "$key_file" \
    -out "$cert_file" \
    -subj "/CN=$FRONT_DOMAIN" \
    -addext "subjectAltName=DNS:$FRONT_DOMAIN,DNS:$API_DOMAIN"
  chmod 0600 "$key_file"
  chmod 0644 "$cert_file"
  printf '%s' "$domain_pair" > "$domain_file"
fi

destination=/etc/nginx/sites-available/rootsecops.conf
sed \
  -e "s|__FRONT_DOMAIN__|$FRONT_DOMAIN|g" \
  -e "s|__API_DOMAIN__|$API_DOMAIN|g" \
  -e "s|__FRONTEND_PORT__|$FRONTEND_PORT|g" \
  -e "s|__BACKEND_PORT__|$BACKEND_PORT|g" \
  -e "s|__CLIENT_MAX_BODY_SIZE__|$CLIENT_MAX_BODY_SIZE|g" \
  "$script_dir/rootsecops.conf.template" > "$destination"

ln -sfn "$destination" /etc/nginx/sites-enabled/rootsecops.conf
nginx -t
systemctl reload nginx

echo "Nginx virtual hosts are active:"
echo "  UI:  https://$FRONT_DOMAIN"
echo "  API: https://$API_DOMAIN"
echo "Certificate: $cert_file"
