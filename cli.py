from __future__ import annotations

import json
import typer

from dcc_policy_drift.alerts import AlertDispatcher
from dcc_policy_drift.config import settings
from dcc_policy_drift.diff import compute_diff
from dcc_policy_drift.evaluator import evaluate_diff, evaluate_mfa_less
from dcc_policy_drift.okta_client import OktaClient
from dcc_policy_drift.snapshot import store_snapshot, take_snapshot, extract_org_id
from dcc_policy_drift.scheduler import start_scheduler
import os
from typing import Tuple
from pathlib import Path

from dcc_policy_drift.baseline import get_baseline_path


app = typer.Typer(help="DCC Policy Drift CLI (single-tenant, SSWS token)")

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

def _ensure_credentials(token: str | None, org_url: str | None) -> Tuple[str, str]:
    """Return (token, org_url) ensuring both values are present, prompting the user if not.

    Priority: function arg > env var > settings > prompt.
    """
    from dcc_policy_drift.config import settings as _settings

    token_final = (
        token
        or os.getenv("OKTA_TOKEN")
        or _settings.okta_token
    )
    org_final = (
        org_url
        or os.getenv("OKTA_ORG_URL")
        or _settings.okta_org_url
    )

    if not token_final:
        token_final = typer.prompt("Enter Okta API Token")
    if not org_final:
        org_final = typer.prompt("Enter Okta Org URL (e.g. https://dev-123.okta.com)")

    # Persist to env and settings for the rest of the process
    os.environ["OKTA_TOKEN"] = token_final
    os.environ["OKTA_ORG_URL"] = org_final
    _settings.okta_token = token_final
    _settings.okta_org_url = org_final

    return token_final, org_final


def _build_client(token: str | None, org_url: str | None) -> OktaClient:
    token_final, org_final = _ensure_credentials(token, org_url)
    return OktaClient(org_final, token_final)


# -----------------------------------------------------------------------------
# Optional Slack wiring helper (shared by all commands)
# -----------------------------------------------------------------------------


def _apply_slack_url(slack_url: str | None) -> None:
    """If a Slack webhook URL is provided, set it for this run."""

    if not slack_url:
        return

    import os

    os.environ["SLACK_WEBHOOK_URL"] = slack_url

    # Update settings singleton so that AlertDispatcher picks the new value
    from dcc_policy_drift.config import settings as _settings

    _settings.slack_webhook_url = slack_url

# -----------------------------------------------------------------------------
# Commands
# -----------------------------------------------------------------------------


@app.command()
def snapshot(
    token: str | None = typer.Option(None, help="Okta API token", envvar="OKTA_TOKEN"),
    org_url: str | None = typer.Option(None, help="Okta org base URL", envvar="OKTA_ORG_URL"),
    name: str | None = typer.Option(None, help="Optional custom name for the snapshot file"),
    slack_url: str | None = typer.Option(
        None,
        help="Slack Incoming Webhook URL used to post alert payloads (optional)",
        envvar="SLACK_WEBHOOK_URL",
    ),
):
    """Take snapshot and immediately evaluate drift / anomalies like run-once."""
    _apply_slack_url(slack_url)
    client = _build_client(token, org_url)
    typer.echo("[INFO] Fetching Okta policies, rules, apps, and IdPs...")
    snap = take_snapshot(client)
    dir_path = settings.snapshot_dir / extract_org_id(client.base_url)
    path = store_snapshot(
        snap,
        directory=dir_path,
        name=name,
    )
    typer.secho(f"[SUCCESS] Snapshot stored: {path}", fg=typer.colors.GREEN)

    # ------------------------------------------------------------------
    # Diff against baseline (oldest snapshot or baseline.json) + MFA-less
    # ------------------------------------------------------------------

    # Determine baseline (baseline.json preferred)
    baseline_path = get_baseline_path(dir_path)

    baseline = None
    if baseline_path and baseline_path != path:
        import json as _json, pathlib as _pl

        baseline = _json.loads(_pl.Path(baseline_path).read_text())

    findings = []
    if baseline:
        diff_result = compute_diff(baseline, snap)
        findings += evaluate_diff(diff_result)

    # MFA-less check similar to run_once
    from datetime import datetime, timedelta, timezone

    typer.echo("[INFO] Checking for MFA-less logins in last 30 minutes...")
    last_ts = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    findings += evaluate_mfa_less(client, last_ts)

    # Console summary
    slack_present = slack_url or os.getenv("SLACK_WEBHOOK_URL")
    if findings:
        summary: dict[str, int] = {}
        for f in findings:
            summary[f.category] = summary.get(f.category, 0) + len(f.details)

        typer.secho("[ALERT] Findings detected:", fg=typer.colors.YELLOW, bold=True)
        for cat, count in summary.items():
            typer.secho(f"  • {cat}: {count}", fg=typer.colors.YELLOW)
        if slack_present:
            typer.echo("Full details will be sent to Slack.")
    else:
        typer.secho("[OK] No drift or anomalies detected.", fg=typer.colors.GREEN)

    # Dispatch alerts with snapshot name
    dispatcher = AlertDispatcher()
    snap_name = path.stem
    for f in findings:
        dispatcher.dispatch(f.to_payload(org_url or settings.okta_org_url, snap_name))

    typer.secho("[SUCCESS] Snapshot evaluation complete.", fg=typer.colors.GREEN)


@app.command()
def run_once(
    token: str | None = typer.Option(None, help="Okta API token", envvar="OKTA_TOKEN"),
    org_url: str | None = typer.Option(None, help="Okta org base URL", envvar="OKTA_ORG_URL"),
    slack_url: str | None = typer.Option(
        None,
        help="Slack Incoming Webhook URL used to post full alert payloads",
        envvar="SLACK_WEBHOOK_URL",
    ),
):
    """Run a single detection cycle (snapshot + diff + MFA-less check)."""
    _apply_slack_url(slack_url)
    client = _build_client(token, org_url)
    from dcc_policy_drift.snapshot import extract_org_id

    org_id = extract_org_id(client.base_url)
    snap_dir = settings.snapshot_dir / org_id
    snap_dir.mkdir(parents=True, exist_ok=True)

    # Baseline selection with baseline.json preference
    baseline_path = get_baseline_path(snap_dir)
    baseline = None
    if baseline_path:
        import pathlib

        baseline = json.loads(pathlib.Path(baseline_path).read_text())

    typer.echo("[INFO] Taking new snapshot...")
    current = take_snapshot(client)
    snap_path = store_snapshot(current, directory=snap_dir)
    current_snap_name = snap_path.stem
    typer.echo("[INFO] Snapshot complete. Comparing with baseline...")

    findings = []
    if baseline:
        diff_result = compute_diff(baseline, current)
        findings += evaluate_diff(diff_result)

    from datetime import datetime, timedelta, timezone

    typer.echo("[INFO] Checking for MFA-less logins in last 30 minutes...")
    last_ts = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    findings += evaluate_mfa_less(client, last_ts)

    # ------------------------------------------------------------------
    # Console summary + Slack configuration
    # ------------------------------------------------------------------
    slack_present = slack_url or os.getenv("SLACK_WEBHOOK_URL")
    if findings:
        summary: dict[str, int] = {}
        for f in findings:
            summary[f.category] = summary.get(f.category, 0) + len(f.details)

        typer.secho("[ALERT] Findings detected:", fg=typer.colors.YELLOW, bold=True)
        for cat, count in summary.items():
            typer.secho(f"  • {cat}: {count}", fg=typer.colors.YELLOW)
        if slack_present:
            typer.echo("Full details will be sent to Slack.")
    else:
        typer.secho("[OK] No drift or anomalies detected.", fg=typer.colors.GREEN)

    dispatcher = AlertDispatcher()
    for f in findings:
        dispatcher.dispatch(f.to_payload(org_url or settings.okta_org_url, current_snap_name))
    typer.secho("[SUCCESS] Detection cycle complete.", fg=typer.colors.GREEN)


@app.command()
def schedule(
    minutes: int | None = typer.Option(
        None,
        "--minutes",
        "--interval",
        help="Interval in minutes between cycles",
    ),
    token: str | None = typer.Option(None, help="Okta API token", envvar="OKTA_TOKEN"),
    org_url: str | None = typer.Option(None, help="Okta org base URL", envvar="OKTA_ORG_URL"),
    slack_url: str | None = typer.Option(
        None,
        help="Slack Incoming Webhook URL used to post alert payloads",
        envvar="SLACK_WEBHOOK_URL",
    ),
):
    """Start background scheduler. If --minutes is omitted you'll be prompted."""

    if minutes is None:
        minutes = typer.prompt("Enter scheduler interval in minutes", type=int)
        if minutes <= 0:
            raise typer.BadParameter("Minutes must be positive")

    # ------------------------------------------------------------------
    # Slack webhook interactive prompt (optional)
    # ------------------------------------------------------------------

    slack_env = os.getenv("SLACK_WEBHOOK_URL")
    if not slack_url and not slack_env:
        if typer.confirm("Would you like to send alerts to Slack?", default=False):
            slack_url = typer.prompt("Enter Slack Incoming Webhook URL")

    # Apply slack URL (from option, env, or prompt)
    _apply_slack_url(slack_url)

    # allow passing token/org via option instead of env vars

    if not token and not os.getenv("OKTA_TOKEN"):
        token = typer.prompt("Enter Okta API Token")
    if not org_url and not os.getenv("OKTA_ORG_URL"):
        org_url = typer.prompt("Enter Okta Org URL (e.g. https://dev-123.okta.com)")

    # finally set them for this process
    os.environ["OKTA_TOKEN"] = token or os.getenv("OKTA_TOKEN", "")
    os.environ["OKTA_ORG_URL"] = org_url or os.getenv("OKTA_ORG_URL", "")

    from dcc_policy_drift.config import settings as _settings
    _settings.okta_token = os.environ["OKTA_TOKEN"]
    _settings.okta_org_url = os.environ["OKTA_ORG_URL"]

    typer.echo(f"[INFO] Scheduler will run every {minutes} minute(s)...")
    start_scheduler(minutes * 60)


@app.command("list-snapshots")
# Optional slack URL not necessary for listing but accept for consistency
def list_snapshots(
    org_url: str | None = typer.Option(None, help="Okta org base URL", envvar="OKTA_ORG_URL"),
    slack_url: str | None = typer.Option(
        None,
        help="Slack Incoming Webhook URL (ignored, for CLI consistency)",
        envvar="SLACK_WEBHOOK_URL",
    ),
):
    """List existing snapshots for the tenant with timestamp."""
    _apply_slack_url(slack_url)
    _, org_url_final = _ensure_credentials(None, org_url)
    from datetime import datetime

    org_id = extract_org_id(org_url_final)
    snap_dir = settings.snapshot_dir / org_id
    if not snap_dir.exists():
        typer.echo("No snapshots found for this org.")
        raise typer.Exit()
    rows = []
    for p in sorted(snap_dir.glob("*.json")):
        taken = datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds")
        rows.append((p.stem, taken))
    for name, ts in rows:
        typer.echo(f"{name:40} {ts}")


@app.command()
def promote(
    snapshot_name: str = typer.Argument(..., help="Snapshot file name (without .json) to promote as baseline"),
    org_url: str | None = typer.Option(None, help="Okta org base URL", envvar="OKTA_ORG_URL"),
    slack_url: str | None = typer.Option(
        None,
        help="Slack Incoming Webhook URL used to post alert payloads",
        envvar="SLACK_WEBHOOK_URL",
    ),
):
    """Promote a snapshot as the new baseline (creates/overwrites baseline.json)."""
    _apply_slack_url(slack_url)
    _, org_url_final = _ensure_credentials(None, org_url)
    org_id = extract_org_id(org_url_final)
    snap_dir = settings.snapshot_dir / org_id
    target_path = snap_dir / f"{snapshot_name}.json"
    if not target_path.exists():
        typer.echo("Snapshot not found: " + str(target_path))
        raise typer.Exit(code=1)
    import shutil, os, uuid

    baseline_path = snap_dir / "baseline.json"
    if target_path == baseline_path:
        typer.secho("[INFO] Target snapshot is already the baseline.", fg=typer.colors.BLUE)
        raise typer.Exit()

    # Copy to a temporary file first, then atomically replace
    tmp_path = baseline_path.with_suffix(".tmp_" + uuid.uuid4().hex)
    shutil.copy2(target_path, tmp_path)
    os.replace(tmp_path, baseline_path)  # atomic on same filesystem
    typer.secho(f"[SUCCESS] Promoted {snapshot_name} as baseline.", fg=typer.colors.GREEN)


if __name__ == "__main__":
    app() 