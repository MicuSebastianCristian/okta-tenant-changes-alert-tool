# DCC Policy Drift CLI

The CLI provides several commands to snapshot an Okta tenant, detect drift, and manage baselines.

## Global options

Most commands accept these common options (can also be set via env vars):

| Option | Env var | Description |
|--------|---------|-------------|
| `--token TEXT` | `OKTA_TOKEN` | SSWS API token with `okta.policies.read okta.apps.read okta.logs.read` scopes (if omitted, CLI will prompt) |
| `--org-url TEXT` | `OKTA_ORG_URL` | Base URL of the Okta org (e.g. `https://dev-123456.okta.com`) (prompted if omitted) |

Example of setting env vars once per shell:
```powershell
$env:OKTA_TOKEN  = "00_st8N-sRDvZ6x9apI9lQPc96qor8ooZEzUqvVcHt"
$env:OKTA_ORG_URL = "https://demo-demo-intragen.okta.com"
```

---

## Commands

### 1. snapshot
Take a snapshot of the tenant’s policies, rules, apps, and IdPs.

```bash
python cli.py snapshot [--name <friendly-name>] [OPTIONS]
```

* `--name` — optional custom filename (spaces are converted to `_`).
* Stores the JSON under `snapshots/<org_id>/`.
* Prints `[SUCCESS] Snapshot stored: ...`.

### 2. run-once
Run a *single* detection cycle:
1. Load baseline (either `baseline.json` or the oldest snapshot).
2. Take a new snapshot.
3. Compute diff, evaluate findings, send alerts.

```bash
python cli.py run-once [OPTIONS]
```

### 3. schedule
Start the background scheduler.

```
python cli.py schedule [--minutes <n> | --interval <n>] [--token ...] [--org-url ...] [--slack-url ...]
```

* If you omit `--minutes/--interval` the CLI will **prompt** for the interval (in minutes). Default = 30 min.
* `--interval` is an alias of `--minutes`.
* Credentials: all commands (including `schedule`) prompt for any missing `OKTA_TOKEN` / `OKTA_ORG_URL`. You can still provide them via `--token` / `--org-url`.
* Slack: if you don't supply `--slack-url` (and `SLACK_WEBHOOK_URL` env var is not set) you'll be asked whether you want to send alerts to Slack. Choose **Yes** to enter the webhook URL, or **No** to run without Slack notifications.

Stop the scheduler any time with `Ctrl+C`.

### 4. list-snapshots
List all snapshots for the org with their filesystem timestamp (UTC).

```bash
python cli.py list-snapshots [OPTIONS]
```

Example output:
```first_baseline                     2025-07-11T10:06:42
cee342d5-55c2-4c...                2025-07-11T11:30:12
```

### 5. promote
Promote a snapshot to be the new baseline. It copies the chosen file to `baseline.json` in the snapshot directory.

```bash
python cli.py promote <snapshot_name> [OPTIONS]
```

Example:
```bash
python cli.py promote first_baseline
[SUCCESS] Promoted first_baseline as baseline.
```

---

## How drift evaluation works

1. **compute_diff** compares baseline vs current by object `id` and categorises additions, deletions, and modifications (field-level via DeepDiff).
2. **evaluate_diff** uses the **EnhancedDriftEvaluator** to detect specific high-severity drift scenarios like application deletion, policy creation/deletion, and the addition of SMS as an authentication factor. If no specific high-severity drift is detected, it falls back to a generic *Policy Drift* finding.
3. **evaluate_mfa_less** detects successful logins without MFA in the last 30 minutes using the System-Log API.
4. **AlertDispatcher** sends each finding to e-mail / Slack / Teams if configured. You can control which alerts are sent to Slack with the `SLACK_HIGH_SEVERITY_ONLY` environment variable. If set to `true` (the default), only HIGH severity alerts will be sent to Slack.

Adjust severities or add custom rules by editing `dcc_policy_drift/evaluator.py`.

