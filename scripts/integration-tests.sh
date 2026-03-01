#!/usr/bin/env bash
#
# Runs the SwiftLDAP integration tests against a Dockerized OpenLDAP server.
#
# Usage:
#   ./scripts/integration-tests.sh          # run integration tests
#   ./scripts/integration-tests.sh --keep   # don't tear down after tests
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KEEP_RUNNING=false

if [[ "${1:-}" == "--keep" ]]; then
    KEEP_RUNNING=true
fi

cd "$PROJECT_DIR"

# Step 1: Generate TLS certificates
echo "==> Generating TLS certificates..."
bash "$SCRIPT_DIR/generate-test-certs.sh"

# Step 2: Start OpenLDAP
echo "==> Starting OpenLDAP container..."
docker compose up -d --wait

cleanup() {
    if [ "$KEEP_RUNNING" = false ]; then
        echo "==> Tearing down OpenLDAP container..."
        docker compose down -v
    else
        echo "==> Container left running (--keep). Stop with: docker compose down -v"
    fi
}
trap cleanup EXIT

# Step 3: Run integration tests
echo "==> Running integration tests..."
LDAP_INTEGRATION_TESTS=1 swift test --filter IntegrationTests

echo "==> Integration tests passed."
