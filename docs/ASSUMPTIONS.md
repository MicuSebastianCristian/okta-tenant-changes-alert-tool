# DCC Policy Drift – Assumptions & Design Decisions

This document tracks assumptions made during the initial implementation. Please review and amend as required.

## Snapshot Storage
* Stored locally in `snapshots/` directory as JSON files.
* Future: switch to S3, Azure Blob, or Okta Workflows table.

## Baseline Selection
* MVP picks **oldest** snapshot file as baseline.
* A `promote` command is stubbed for manual baseline promotion; will tag snapshot in metadata or via filename suffix.

## Alert Channels
* SMTP, Slack Incoming Webhook, and Teams Webhook supported via environment variables.
* If multiple channels configured, alerts are sent to all.

## Severity Mapping
* All policy drift types default to `HIGH` until we refine mapping.
* Any MFA-less successful login is `HIGH` severity.

## Scheduling
* Uses APScheduler background scheduler running in current process.
* Runs every 30 minutes; timestamp for MFA-less check is `now - 30m`.

## Authentication / Tokens
* Requires environment variables `OKTA_TOKEN` and `OKTA_ORG_URL`.
* Token scopes: `okta.policies.read okta.apps.read okta.logs.read`.

## Rate-Limit Handling
* On HTTP 429, up to 3 retries with exponential back-off (1s, 2s, 4s).
* Raises error after 3 failed retries.

## Diff Algorithm
* Identifies added, deleted, modified objects by `id` field.
* DeepDiff library used for change details; excludes `snapshotId`, `takenAt`.

## Open Questions
1. How should multiple environments/tenants be managed? (single config vs. multiple configs)
2. Baseline governance – who approves and how to track approvals?
3. Custom severity mapping rules needed?
4. Long-term storage retention policy for snapshots.
5. Additional alert channels (ServiceNow, PagerDuty). 

## Tenants & Machine-to-Machine Auth
* **Multiple tenants** are defined in `tenants.yaml`; each record holds `name`, `org_url`, `client_id`, `client_secret`.
* Each tenant obtains an OAuth 2.0 Service App (Client Credentials) token via `/oauth2/v1/token`.
* Token caching: in-memory per-process; refreshes 60 s before expiry. 