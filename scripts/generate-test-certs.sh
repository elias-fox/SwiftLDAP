#!/usr/bin/env bash
#
# Generates self-signed TLS certificates for the OpenLDAP test container.
# Output: .certs/{ca.crt, ca.key, server.crt, server.key}
#
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")/.." && pwd)/.certs"
mkdir -p "$CERT_DIR"

# Skip if certs already exist and are not expired
if [ -f "$CERT_DIR/server.crt" ] && openssl x509 -checkend 86400 -noout -in "$CERT_DIR/server.crt" 2>/dev/null; then
    echo "Certificates already exist and are valid. Skipping generation."
    exit 0
fi

echo "Generating test TLS certificates in $CERT_DIR ..."

# Generate CA
openssl req -x509 -newkey rsa:2048 \
    -keyout "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -days 365 -nodes \
    -subj '/CN=SwiftLDAP Test CA' \
    2>/dev/null

# Generate server key + CSR
openssl req -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" \
    -nodes \
    -subj '/CN=localhost' \
    2>/dev/null

# Sign the server cert with the CA, including SANs for localhost
openssl x509 -req \
    -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/server.crt" \
    -days 365 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") \
    2>/dev/null

# Clean up intermediate files
rm -f "$CERT_DIR/server.csr" "$CERT_DIR/ca.srl"

# Ensure certs are readable by the container's non-root user
chmod 644 "$CERT_DIR"/*

echo "Certificates generated successfully."
