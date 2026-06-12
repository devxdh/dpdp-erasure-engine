# Compliance Introspector Report

## Summary

- Root table: `public.users`
- Generated at: `2026-06-12T05:19:07.235Z`
- Schema hash: `ea9e816d30fcee6bd4f322f1fb769e853c2e7ee5b19263aaa54f5ef80189212c`
- DAG targets: 15
- Tables with PII: 8
- PII columns: 9
- High-confidence findings: 6
- Review-required findings: 3
- Potential logical links: 20

## PII Findings

| Table | Column | Type | Confidence | Metadata | Content | Signatures |
| --- | --- | --- | ---: | ---: | ---: | --- |
| `public.legacy_crm_notes` `agent_notes` `text` 0.950 0.000 1.000 email, indian_mobile |
| `public.marketing_campaign_clicks` `target_email` `character varying` 0.950 0.920 1.000 email |
| `public.users` `email` `character varying` 0.950 0.920 1.000 email |
| `public.users` `phone_number` `character varying` 0.920 0.920 1.000 indian_mobile |
| `public.support_tickets` `description` `text` 0.900 0.000 1.000 indian_mobile |
| `public.ticket_messages` `message_body` `text` 0.900 0.000 1.000 indian_mobile |
| `public.audit_logs` `ip_address` `inet` 0.820 0.820 1.000 ipv4 |
| `public.user_devices` `last_ip_address` `inet` 0.820 0.820 0.000 metadata |
| `public.user_addresses` `pincode` `character varying` 0.780 0.620 1.000 indian_pin_code |

## Potential Logical Links

- `public.users.customer_id` <-> `public.abandoned_carts.customer_id`: Table exposes customer_id which conceptually maps to the root entity.
- `public.users.actor_id` <-> `public.audit_logs.actor_id`: Table exposes actor_id which conceptually maps to the root entity.
- `public.kyc_documents.user_id` <-> `public.orders.user_id`: Both tables expose user_id but no physical foreign key was found.
- `public.kyc_documents.user_id` <-> `public.support_tickets.user_id`: Both tables expose user_id but no physical foreign key was found.
- `public.kyc_documents.user_id` <-> `public.user_addresses.user_id`: Both tables expose user_id but no physical foreign key was found.
- `public.kyc_documents.user_id` <-> `public.user_devices.user_id`: Both tables expose user_id but no physical foreign key was found.
- `public.kyc_documents.user_id` <-> `public.user_preferences.user_id`: Both tables expose user_id but no physical foreign key was found.
- `public.orders.user_id` <-> `public.support_tickets.user_id`: Both tables expose user_id but no physical foreign key was found.
- `public.orders.user_id` <-> `public.user_addresses.user_id`: Both tables expose user_id but no physical foreign key was found.
- `public.orders.user_id` <-> `public.user_devices.user_id`: Both tables expose user_id but no physical foreign key was found.
- `public.orders.user_id` <-> `public.user_preferences.user_id`: Both tables expose user_id but no physical foreign key was found.
- `public.support_tickets.user_id` <-> `public.user_addresses.user_id`: Both tables expose user_id but no physical foreign key was found.
- `public.support_tickets.user_id` <-> `public.user_devices.user_id`: Both tables expose user_id but no physical foreign key was found.
- `public.support_tickets.user_id` <-> `public.user_preferences.user_id`: Both tables expose user_id but no physical foreign key was found.
- `public.user_addresses.user_id` <-> `public.user_devices.user_id`: Both tables expose user_id but no physical foreign key was found.
- `public.user_addresses.user_id` <-> `public.user_preferences.user_id`: Both tables expose user_id but no physical foreign key was found.
- `public.user_devices.user_id` <-> `public.user_preferences.user_id`: Both tables expose user_id but no physical foreign key was found.
- `public.users.client_id` <-> `public.legacy_crm_notes.client_id`: Table exposes client_id which conceptually maps to the root entity.
- `public.users.target_email` <-> `public.marketing_campaign_clicks.target_email`: Table exposes target_email which conceptually maps to the root entity.
- `public.users.user_uuid` <-> `public.third_party_telemetry.user_uuid`: Table exposes user_uuid which conceptually maps to the root entity.

## Next Steps

- Review every PII column and potential logical link with the application owner.
- Copy reviewed targets into compliance.worker.yml and complete legal_attestation.
- Run compliance-worker check-integrity before allowing live worker boot.
- Sign the reviewed manifest with compliance-worker sign after DPO approval.
