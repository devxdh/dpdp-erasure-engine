# Deployment and Configuration Reference Guide

This reference guide provides operational instructions for deploying, configuring, and securing the **DPDP Erasure Engine** (Control Plane API and Compliance Worker) in production.

---

## 1. API Key Bootstrapping & Multi-Tenancy

The Control Plane API enforces token-based authorization for all administrative and operational endpoints. To make setup easy, the engine features an automatic **zero-configuration bootstrapping flow** on its first startup.

### 1.1 The Bootstrap Flow (First Run)
1. **Define the Token:** When starting the API container, configure the `ADMIN_API_TOKEN` environment variable (e.g. `ADMIN_API_TOKEN=your-super-secret-bootstrap-token`).
2. **Bootstrapping Trigger:** Send your first HTTP request containing `Authorization: Bearer your-super-secret-bootstrap-token` to any protected API endpoint (e.g., `GET /api/v1/admin/clients`).
3. **Database Insertion:** The auth middleware detects the token is missing from the database, hashes it using SHA-256, and automatically registers a new organization called `'bootstrap'` and a key labeled `'bootstrap-admin'` with wildcard scopes (`['*']`).
4. **Subsequent Calls:** For all future calls, the engine validates the hash against the database without running the bootstrap process again.

### 1.2 Managing Multi-Tenancy
Once the bootstrap key is active, you can use it to provision separate organizations (tenants) and scoped API keys:

* **Create a New Organization:**
  ```text
  curl -X POST http://localhost:3000/api/v1/admin/organizations \
    -H "Authorization: Bearer your-super-secret-bootstrap-token" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Acme-Production",
      "owner_email": "privacy@acme.com",
      "certificate_archive_retention_days": 365
    }'
  ```
  **Response:**
  ```json
  {
    "organization": { "id": "org_uuid_12345", "name": "Acme-Production" },
    "api_key": "avk_c5f9b...", 
    "api_key_id": "key_uuid_67890",
    "scopes": ["*"]
  }
  ```
  > [!IMPORTANT]
  > The returned `api_key` prefixed with `avk_` is only returned once during creation. The engine hashes it using SHA-256 before saving it to the database, so the plaintext value can never be recovered if lost.

* **Create a Scoped Key:**
  To limit access for specific service integrations, create a scoped key under an organization's context:
  ```text
  curl -X POST http://localhost:3000/api/v1/org/api-keys \
    -H "Authorization: Bearer avk_c5f9b..." \
    -H "Content-Type: application/json" \
    -d '{
      "label": "zendesk-integration",
      "scopes": ["erasure:write"]
    }'
  ```

---

## 2. Environment Variables Reference

### 2.1 API Control Plane (`apps/api`)

| Variable | Description | Default | Production Note |
| :--- | :--- | :--- | :--- |
| `NODE_ENV` | Environment mode (`production`, `development`, `test`). | `development` | Must be `production`. |
| `ALLOW_LOCAL_DEV` | Bypasses production safety checks if set to `true`. | `false` | Must be `false` in production. |
| `PORT` | HTTP Port the API server listens on. | `3000` | Configure according to your cluster setup. |
| `DATABASE_URL` | Postgres connection string for the Control Plane database. | `postgres://...` | Cannot point to localhost in production. |
| `API_CONTROL_SCHEMA` | Schema name for control tables. | `dpdp_control` | Ensure database user has schema privileges. |
| `ADMIN_API_TOKEN` | Initial plaintext token used for API bootstrapping. | `admin-secret` | **Must be changed** in production. |
| `ADMIN_API_TOKEN_FILE` | File path containing the admin token. | *None* | Used for Docker/K8s secret mounting. |
| `WORKER_SHARED_SECRET` | Shared secret to authorize worker connections. | `worker-secret` | **Must be changed** in production. |
| `WORKER_REQUEST_SIGNING_SECRET`| Secret used to sign outgoing worker request commands. | *None* | **Required** in production. |
| `WORKER_REQUEST_SIGNING_MAX_SKEW_MS`| Allowed clock skew in milliseconds for signed requests. | `60000` | Helps prevent request replay attacks. |
| `SHADOW_BURN_IN_REQUIRED` | Requires shadow runs before allowing live execution. | `true` | Recommended to prevent configuration errors. |
| `SHADOW_REQUIRED_SUCCESSES`| Number of successful shadow runs required to burn-in. | `100` | Can be adjusted based on request volumes. |
| `PUBLIC_RATE_LIMIT_WINDOW_MS`| Rate limit window in milliseconds. | `60000` | |
| `PUBLIC_RATE_LIMIT_MAX_REQUESTS`| Max requests permitted inside the rate-limiting window. | `60` | |
| `COE_KEY_ID` | Key identifier for the Certificate of Erasure signature. | `control-plane-ed25519-v1` | |
| `COE_PRIVATE_KEY_PKCS8_BASE64`| Base64 Ed25519 private key for signing certificates. | *None* | **Required** in production. |
| `COE_PUBLIC_KEY_SPKI_BASE64` | Base64 Ed25519 public key for verifying certificates. | *None* | **Required** in production. |
| `ARCHIVE_S3_ENABLED` | Enables cold archiving of deleted audit files to AWS S3.| `false` | |
| `ARCHIVE_S3_BUCKET` | Destination S3 bucket name. | *None* | Required if archiving is enabled. |
| `ARCHIVE_S3_REGION` | AWS Region for the S3 bucket. | *None* | Required if archiving is enabled. |
| `ARCHIVE_S3_ACCESS_KEY_ID` | AWS IAM Access Key ID for bucket operations. | *None* | Required if archiving is enabled. |
| `ARCHIVE_S3_SECRET_ACCESS_KEY`| AWS IAM Secret Access Key for bucket operations. | *None* | Required if archiving is enabled. |
| `ARCHIVE_INTERVAL_MS` | Frequency of running S3 archive uploads. | `3600000` (1hr) | |

---

### 2.2 Compliance Worker (`apps/worker`)

| Variable | Description | Default | Production Note |
| :--- | :--- | :--- | :--- |
| `DB_URL` | Postgres connection string for the target application database. | `postgres://...` | Database containing tables to redact. |
| `SKIP_SCHEMA_CHECK` | Bypasses verification of schema drift hashes. | `false` | **Do not set to true** in production. |
| `API_CLIENT_ID` | ID mapping the worker to the control plane. | `worker-1` | Matches `WORKER_CLIENT_NAME` in API. |
| `API_WORKER_TOKEN` | Bearer token used to authenticate calls to the API. | `worker-secret` | Must match `WORKER_SHARED_SECRET`. |
| `API_REQUEST_SIGNING_SECRET`| Secret used to verify request signatures from the API. | *None* | Must match `WORKER_REQUEST_SIGNING_SECRET`. |
| `API_OUTBOX_URL` | API endpoint to fetch scheduled outbox tasks. | `http://.../outbox` | |
| `API_SYNC_URL` | API endpoint to synchronize config changes. | `http://.../sync` | |
| `API_BASE_URL` | Base API URL to acknowledge task completions. | `http://.../tasks` | |
| `MAILER_WEBHOOK_URL` | External Webhook URL to call when tasks complete/fail. | *None* | Used to alert users or notification systems. |
| `METRICS_PORT` | Port to expose Prometheus metrics scrape endpoint. | `9466` | |
| `LOG_LEVEL` | Logging level (`debug`, `info`, `warn`, `error`). | `info` | Use `debug` only for troubleshooting. |
| `DPDP_CONFIG_SIGNING_PUBLIC_KEY_SPKI_BASE64`| Public key used to verify the signed YAML manifest. | *None* | Prevents loading unauthorized manifests. |

---

## 3. Production Key Management (KMS / Secrets Providers)

The Compliance Worker requires two key assets to perform its cryptographic duties:
1. **`DPDP_MASTER_KEY`**: A 32-byte key used to encrypt PII before copying it into the vault.
2. **`DPDP_HMAC_KEY`**: A 32-byte key used to generate keyed HMACs for lookup values.

In production, keeping these key values in plaintext environment variables is insecure. The engine supports loading these keys dynamically at boot time using external KMS and Secret Managers.

To use an external provider, configure the `security` section in your `compliance.worker.yml` manifest file:

### 3.1 AWS KMS (Key Management Service)
The worker calls AWS KMS to decrypt a pre-encrypted base64 ciphertext blob of your key.

```yaml
security:
  notification_lease_seconds: 120
  master_key_source:
    provider: "aws_kms"
    region: "ap-south-1"                                      # AWS region
    ciphertext_blob_base64: "AQICAHj1xG8S..."                  # The encrypted key material
    access_key_id_env: "AWS_ACCESS_KEY_ID"                    # Env var holding AWS credentials
    secret_access_key_env: "AWS_SECRET_ACCESS_KEY"
    session_token_env: "AWS_SESSION_TOKEN"                    # Optional session token
    # endpoint: "https://kms.ap-south-1.amazonaws.com"        # Optional custom KMS endpoint
```

### 3.2 GCP Secret Manager
The worker fetches the secret directly from GCP Secret Manager via Google HTTP APIs using either a Google Metadata Access Token or a provided access token.

```yaml
security:
  notification_lease_seconds: 120
  master_key_source:
    provider: "gcp_secret_manager"
    secret_version: "projects/my-gcp-project/secrets/dpdp-master-key/versions/1"
    access_token_env: "GCP_ACCESS_TOKEN"                     # Optional. If omitted, uses local Instance Metadata token.
    metadata_token_url: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

### 3.3 HashiCorp Vault (KV v2 Engine)
The worker retrieves the key from a Vault KV v2 mount point.

```yaml
security:
  notification_lease_seconds: 120
  master_key_source:
    provider: "hashicorp_vault"
    address: "https://vault.internal.net:8200"                # Vault Address
    token_env: "VAULT_TOKEN"                                  # Env var containing Vault Auth Token
    mount: "secret"                                           # KV Mount point
    path: "dpdp/keys"                                         # KV Path
    field: "master_key"                                       # Field key containing the 32-byte secret
    namespace_env: "VAULT_NAMESPACE"                          # Optional Vault Namespace Env
```

### 3.4 File Mounts
For Kubernetes deployments, keys can be mounted as raw files into the container.

```yaml
security:
  notification_lease_seconds: 120
  master_key_source:
    provider: "file"
    path: "/var/run/secrets/dpdp/master-key.txt"              # Absolute path to secret file
```

---

## 4. Next Steps: Integrations

Once your DPDP Erasure Engine is deployed, running, and its cryptographic keys are bootstrapped, you need to connect it to your ecosystem so it can receive erasure requests.

Please read the **[Integration and Help Guide](./integration-and-help-guide.md)** to learn how to:
- Send authenticated `POST` requests from your internal backend or user dashboard.
- Set up **Secure Signed Webhooks** for external Governance, Risk, and Compliance (GRC) tools like **OneTrust**, **Zendesk**, and **Jira**.
- Dynamically route outbound success/failure webhooks back to your systems.
