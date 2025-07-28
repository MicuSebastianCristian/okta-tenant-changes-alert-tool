# Test Steps – Multi-Tenant & Token Flow

These steps help verify the new machine-to-machine, multi-tenant implementation.

## 1. Prepare tenants.yaml

Create `tenants.yaml` in project root:
```yaml
tenants:
  - name: acme
    org_url: https://acme.okta.com
    client_id: <CLIENT_ID>
    client_secret: <CLIENT_SECRET>
  - name: beta
    org_url: https://beta.okta.com
    client_id: <CLIENT_ID>
    client_secret: <CLIENT_SECRET>
```
Each service app must have scopes `okta.policies.read okta.apps.read okta.logs.read`.

## 2. Set Environment Variables (optional overrides)
```bash
export SNAPSHOT_DIR=./snapshots          # default already
export TENANTS_FILE=./tenants.yaml       # default already
# SMTP / Slack env vars if you want alerts
```

## 3. Install / Update Dependencies
```bash
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 4. Run Snapshot for One Tenant
```bash
python cli.py snapshot --tenant acme
```
Expect output:
```
[acme] Snapshot stored: snapshots/acme/<uuid>.json
```

## 5. Run Snapshot for All Tenants
```bash
python cli.py snapshot
```
Should create separate sub-directories under `snapshots/` per tenant.

## 6. Single Detection Cycle
```bash
python cli.py run-once
```
Observe console logs; any drift or MFA-less anomalies will trigger alerts (check e-mail / Slack if configured).

## 7. Start Scheduler
```bash
python cli.py schedule
```
CLI will run continuous 30-minute cycles; watch logs for each tenant.

## 8. Token Expiry Test (Optional)
1. Note current time and token `exp` (enable debug logging in `.tenant` if needed).
2. Leave scheduler running past token expiry (~1h).
3. Confirm token refresh log message and continued successful API calls.

If any step fails, capture stack trace and raise the issue for follow-up. 