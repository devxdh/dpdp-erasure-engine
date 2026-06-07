#!/usr/bin/env bash
set -euo pipefail

# DPDP Erasure Engine & Compliance Worker Bootstrap Script
# Implements a single-command setup for evaluation and production deployment.

echo "💼 DPDP Erasure Engine: Bootstrapping Stack..."

# 1. Check for Docker and Docker Compose
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is required to run this stack." >&2
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo "❌ Error: Docker Compose (V2) is required." >&2
    exit 1
fi

COMPOSE_FILE="docker-compose.yml"
if [ "${1:-}" == "--prod" ]; then
    COMPOSE_FILE="docker-compose.prod.yml"
    echo "🚀 Using Production Compose Config (Pulling Pre-built Images)..."
fi

# 2. Start PostgreSQL
echo "🐘 Starting PostgreSQL database..."
docker compose -f "$COMPOSE_FILE" up -d postgres

# 3. Wait for PostgreSQL Health
echo "⏳ Waiting for PostgreSQL to be healthy..."
until [ "$(docker inspect --format='{{json .State.Health.Status}}' "$(docker compose -f "$COMPOSE_FILE" ps -q postgres)")" == "\"healthy\"" ]; do
    sleep 1
done
echo "🐘 PostgreSQL is healthy and ready!"

# 4. Generate Signing Keys if not present
if [ ! -f "coe-private.key" ] || [ ! -f "coe-public.pem" ]; then
    echo "🔑 Generating cryptographic signing keys..."
    # Generate Ed25519 keypair using a temporary worker container to keep host filesystem clean of tools
    docker compose -f "$COMPOSE_FILE" run --rm --no-deps --entrypoint /usr/local/bin/bun worker run apps/worker/src/modules/cli/index.ts keygen
fi

# Move keys to appropriate locations if needed
if [ -f "apps/worker/coe-private.key" ]; then
    mv apps/worker/coe-private.key .
    mv apps/worker/coe-public.pem .
fi

# 5. Run Introspection to Generate Manifest
echo "🔍 Running offline database introspection..."
# Run introspect against database to compile the FK DAG and generate draft compliance.worker.yml
docker compose -f "$COMPOSE_FILE" run --rm \
  -e DATABASE_URL=postgres://dpdp:dpdp@postgres:5432/dpdp_local \
  --entrypoint /usr/local/bin/bun worker run apps/worker/src/modules/cli/index.ts introspect \
  -u postgres://dpdp:dpdp@postgres:5432/dpdp_local \
  -r mock_app.users \
  -s mock_app \
  -o /tmp/compliance.worker.yml

# Move configuration out of container volume
docker compose -f "$COMPOSE_FILE" cp "$(docker compose -f "$COMPOSE_FILE" ps -q postgres)":/tmp/compliance.worker.yml ./deploy/local/generated/compliance.worker.yml || true

# Fallback: copy standard template if copy fails
if [ ! -f "./deploy/local/generated/compliance.worker.yml" ]; then
    echo "⚠️  Introspector copy failed. Falling back to local template config..."
    mkdir -p ./deploy/local/generated
    cp ./deploy/local/compliance.worker.template.yml ./deploy/local/generated/compliance.worker.yml
fi

# 6. Apply Cryptographic Signature
echo "✍️  Applying cryptographic signature to the compliance manifest..."
docker compose -f "$COMPOSE_FILE" run --rm \
  -v "$(pwd)/deploy/local/generated:/app/deploy/local/generated" \
  -v "$(pwd)/coe-private.key:/app/coe-private.key" \
  --entrypoint /usr/local/bin/bun worker run apps/worker/src/modules/cli/index.ts sign \
  -c /app/deploy/local/generated/compliance.worker.yml \
  -k /app/coe-private.key

# 7. Spin up API and Worker Services
echo "🚀 Booting API and Worker services..."
docker compose -f "$COMPOSE_FILE" up -d api worker

echo "✅ Stack successfully bootstrapped!"
echo "📡 Control Plane API is listening at: http://localhost:13000"
echo "📊 Worker Metrics are exposed at: http://localhost:19464"
echo "📜 View logs with: docker compose -f $COMPOSE_FILE logs -f"
