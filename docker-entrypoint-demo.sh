#!/usr/bin/env bash
set -euo pipefail

# Standalone entrypoint for the devxdh/dpdp-erasure-engine:demo container.
# Starts local Postgres, seeds mock database, auto-generates keys/signatures, and boots services.

echo "🐘 Initializing Postgres..."
if [ ! -d "/var/lib/postgresql/data" ]; then
  mkdir -p /var/lib/postgresql/data
  chown -R postgres:postgres /var/lib/postgresql/data
fi

# Run initdb if empty
if [ ! -d "/var/lib/postgresql/data/base" ]; then
  su - postgres -c "/usr/lib/postgresql/*/bin/initdb -D /var/lib/postgresql/data"
fi

echo "🐘 Starting Postgres server..."
su - postgres -c "/usr/lib/postgresql/*/bin/pg_ctl -D /var/lib/postgresql/data -l /tmp/postgres.log start"

# Wait for Postgres
until su - postgres -c "pg_isready" &>/dev/null; do
  echo "⏳ Waiting for Postgres..."
  sleep 1
done

# Provision user & database
su - postgres -c "psql -c \"CREATE USER dpdp WITH PASSWORD 'dpdp' SUPERUSER;\"" || true
su - postgres -c "psql -c \"CREATE DATABASE dpdp_local OWNER dpdp;\"" || true

# Seed enterprise and compliance engine databases
echo "🌱 Initializing databases and seeding mock data..."
# Run the migration schemas
cd /app

# Generate signing keys
echo "🔑 Generating Ed25519 signing keypair..."
bun run apps/worker/src/modules/cli/index.ts keygen

# Run database schema introspection
echo "🔍 Introspecting PostgreSQL schema..."
bun run apps/worker/src/modules/cli/index.ts introspect \
  -u postgres://dpdp:dpdp@127.0.0.1:5432/dpdp_local \
  -r mock_app.users \
  -s mock_app \
  -o /app/compliance.worker.yml

# Cryptographically sign the manifest configuration
echo "✍️  Signing compliance manifest..."
bun run apps/worker/src/modules/cli/index.ts sign \
  -c /app/compliance.worker.yml \
  -k /app/coe-private.key

# Launch Hono API Control Plane and Compliance Worker Data Plane
echo "🚀 Booting services..."
export NODE_ENV=production
export DATABASE_URL=postgres://dpdp:dpdp@127.0.0.1:5432/dpdp_local
export DB_URL=postgres://dpdp:dpdp@127.0.0.1:5432/dpdp_local
export API_CONTROL_SCHEMA=dpdp_control
export WORKER_CLIENT_NAME=worker-1
export WORKER_SHARED_SECRET=worker-secret
export WORKER_REQUEST_SIGNING_SECRET=request-signing-secret
export ADMIN_API_TOKEN=admin-secret
export SHADOW_BURN_IN_REQUIRED=false

export API_CLIENT_ID=worker-1
export API_WORKER_TOKEN=worker-secret
export API_REQUEST_SIGNING_SECRET=request-signing-secret
export API_SYNC_URL=http://127.0.0.1:3000/api/v1/worker/sync
export API_BASE_URL=http://127.0.0.1:3000/api/v1/worker/tasks
export API_OUTBOX_URL=http://127.0.0.1:3000/api/v1/worker/outbox
export MAILER_WEBHOOK_URL=http://127.0.0.1:3000/ready
export SKIP_SCHEMA_CHECK=true
export METRICS_PORT=9464
export DPDP_MASTER_KEY=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
export DPDP_HMAC_KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

# Start services
bun run --cwd apps/api src/index.ts &
bun run --cwd apps/worker src/index.ts &

# Keep container alive by waiting for background processes
wait -n
