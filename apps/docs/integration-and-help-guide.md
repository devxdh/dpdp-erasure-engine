# Integration and Help Guide

This guide is designed for developers and operators who want to integrate the **DPDP Erasure Engine** directly into their existing product ecosystem. 

Whether you are building a custom internal portal or connecting the engine to third-party privacy vendors like OneTrust, Zendesk, or Jira, this guide will explain the required API hooks and webhook setups.

## 1. System Integration Overview

The DPDP Erasure Engine operates as a decoupled microservice. It exposes a **Control Plane API** that listens for erasure requests and emits **Webhooks** when the state of an erasure request changes.

To integrate this into your system, you need to implement two connection points:
1.  **Inbound:** Your system (or a third party) sends an HTTP `POST` to the Erasure Engine API to start a deletion task.
2.  **Outbound (Webhook):** The Erasure Engine sends an HTTP `POST` back to your system (or a third party) to report when the data is successfully masked, vaulted, or finally shredded.

---

## 2. Basic Inbound Setup (Your App -> Erasure Engine)

If you have an internal "Privacy Dashboard" built into your app, you simply need to make an HTTP call to the API Control Plane when a user clicks "Delete My Account".

**Endpoint:** `POST /api/v1/erasure-requests`

**Payload:**
```json
{
  "subject_opaque_id": "user_id_12345",   // The primary key of the user in your database
  "idempotency_key": "req-998877",        // Unique UUID to prevent double-processing
  "trigger_source": "USER_DASHBOARD",
  "legal_framework": "DPDP_2023",
  "cooldown_days": 30,                    // Days to vault before permanent shredding
  "webhook_url": "https://your-app.com/callback" // Optional: dynamically route outbound success/failure webhooks for this specific request
}
```

*Note:* You must authenticate this request using the `Authorization: Bearer <API_KEY>` header. For details on generating this key, see the [Deployment and Configuration Reference](./deployment-and-configuration-reference.md).

---

## 3. Integrating with Third-Party Vendors

Many companies do not handle privacy requests manually; they use platforms like OneTrust (Privacy Management), Zendesk (Customer Support), or Jira (Internal Task Tracking).

The Erasure Engine is designed to easily bridge with these platforms.

### 3.1 Integrating with OneTrust

OneTrust provides a Privacy Rights Automation (DSAR) module. When a user submits a deletion request via a OneTrust web form, OneTrust needs to trigger the Erasure Engine.

**Step-by-Step Setup:**
1.  **In OneTrust:** Go to Integration > Workflows. Create a new "Webhooks" trigger.
2.  **Configure Inbound Request:** Set the target URL to your Erasure Engine's GRC endpoint (e.g., `https://erasure.yourcompany.com/api/v1/integrations/onetrust/webhooks`).
3.  **Map the Payload:** Map the OneTrust `Subject ID` to the engine's `external_subject_id`.
4.  **Security Headers (Required):** The Control Plane will strictly reject unsigned GRC webhooks. You must configure OneTrust to sign the request.
    *   Set header `Authorization: Bearer <YOUR_API_KEY>`
    *   Set header `x-grc-timestamp: <CURRENT_TIMESTAMP_MS>`
    *   Set header `x-grc-signature: <HMAC_SHA256_HEX>` (computed using your API Key as the secret, signing the string `${timestamp}\n${rawBody}`).
5.  **Configure Outbound Webhook:** You must tell the Erasure Engine to notify OneTrust when the job finishes. Pass the dynamic `webhook_url` in the payload so the Engine can automatically resolve the DSAR ticket in OneTrust.

### 3.2 Integrating with Zendesk

If privacy requests come in via support tickets, you can trigger erasures directly from Zendesk Support.

**Step-by-Step Setup:**
1.  **In Zendesk:** Navigate to the Admin Center > Apps and integrations > Webhooks.
2.  **Create Webhook:** Name it "DPDP Erasure Trigger" and point it to the Erasure Engine API.
3.  **Create a Trigger:** Create a Zendesk Trigger that fires when a ticket is tagged with `privacy_deletion_request` and the status changes to `Solved`.
4.  **Action:** The trigger action should be "Notify Active Webhook" pointing to your new webhook. Pass the Zendesk User ID in the JSON body payload.

### 3.3 Integrating with Jira (Engineering Handoff)

For highly sensitive environments, you might want an engineering manager to manually approve the deletion in Jira before the engine fires.

**Step-by-Step Setup:**
1.  **In Jira:** Set up an Automation Rule (Project Settings > Automation).
2.  **Trigger:** "When Issue Transitioned" -> To Status "Approved for Erasure".
3.  **Action:** "Send Webhook". Point this webhook to the Erasure Engine API.
4.  **Payload:** Map the Jira custom field `Target User ID` to the `subject_opaque_id` in the webhook payload.

*Bonus:* You can also configure the Erasure Engine to send its **Shadow Mode Report** back to Jira by formatting the engine's outbound webhook to hit Jira's "Add Comment" API, dumping the dry-run report directly into the Jira ticket for the engineer to review.

---

## 4. Webhooks & Outbound Communication

To receive updates from the Erasure Engine (such as when the cool-down period ends and data is shredded), configure the webhook environment variables when booting the container:

```bash
docker run -e MAILER_WEBHOOK_URL=https://your-app.com/webhooks/erasure-status ...
```

The engine will send a `POST` request to this URL with the following structure:

```json
{
  "task_id": "tsk_88192A",
  "subject_opaque_id": "user_id_12345",
  "status": "SHREDDED",
  "timestamp": "2026-06-07T14:00:00Z"
}
```

Your main application can listen for this webhook to update the user's status in your own dashboard or send them a final confirmation email.
