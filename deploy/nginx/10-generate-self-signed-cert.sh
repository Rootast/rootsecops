#!/bin/sh
set -eu

front_domain="${FRONT_DOMAIN:?FRONT_DOMAIN is required}"
api_domain="${API_DOMAIN:?API_DOMAIN is required}"
cert_days="${TLS_CERT_DAYS:-365}"
cert_dir=/etc/nginx/certs
cert_file="$cert_dir/tls.crt"
key_file="$cert_dir/tls.key"
domain_file="$cert_dir/.domain"

case "$front_domain" in
  *[!A-Za-z0-9._-]*|'')
    echo "FRONT_DOMAIN contains unsupported characters: $front_domain" >&2
    exit 1
    ;;
esac
case "$api_domain" in
  *[!A-Za-z0-9._-]*|'')
    echo "API_DOMAIN contains unsupported characters: $api_domain" >&2
    exit 1
    ;;
esac

mkdir -p "$cert_dir"
stored_domain=""
if [ -f "$domain_file" ]; then
  stored_domain="$(cat "$domain_file")"
fi

domain_pair="$front_domain,$api_domain"
if [ ! -s "$cert_file" ] || [ ! -s "$key_file" ] || [ "$stored_domain" != "$domain_pair" ]; then
  echo "Generating self-signed TLS certificate for $front_domain and $api_domain"
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes \
    -days "$cert_days" \
    -keyout "$key_file" \
    -out "$cert_file" \
    -subj "/CN=$front_domain" \
    -addext "subjectAltName=DNS:$front_domain,DNS:$api_domain,DNS:localhost,IP:127.0.0.1"
  chmod 0600 "$key_file"
  chmod 0644 "$cert_file"
  printf '%s' "$domain_pair" > "$domain_file"
fi
