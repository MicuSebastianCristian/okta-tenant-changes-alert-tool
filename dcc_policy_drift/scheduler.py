from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone, date
import os
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler

from .alerts import AlertDispatcher
from .config import settings
from .diff import compute_diff
from .evaluator import DriftEvaluator, evaluate_mfa_less
from .snapshot import store_snapshot, take_snapshot, extract_org_id
from .baseline import get_baseline_path
from .okta_client import OktaClient

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Single-tenant processing helpers
# -----------------------------------------------------------------------------


def _build_client() -> OktaClient:
    token = os.getenv("OKTA_TOKEN") or settings.okta_token
    org = os.getenv("OKTA_ORG_URL") or settings.okta_org_url
    if not token or not org:
        raise RuntimeError(
            "OKTA_ORG_URL and OKTA_TOKEN must be set (env vars or .env) for scheduler to run."
        )
    return OktaClient(org, token)


def _process() -> None:
    client = _build_client()
    org_id = extract_org_id(client.base_url)

    snap_dir = settings.snapshot_dir / org_id
    snap_dir.mkdir(parents=True, exist_ok=True)

    # Prefer baseline.json
    baseline_path = get_baseline_path(snap_dir)
    baseline = None
    if baseline_path:
        import json, pathlib

        baseline = json.loads(pathlib.Path(baseline_path).read_text())

    now = datetime.now(timezone.utc)
    date_part = now.strftime("%Y-%m-%d_%H%M%S")
    # Determine next counter within the same second (unlikely but for safety)
    existing_same_ts = sorted(snap_dir.glob(f"scheduler_*_{date_part}.json"))
    counter = len(existing_same_ts) + 1
    snapshot_name = f"scheduler_{counter:02d}_{date_part}"

    current = take_snapshot(client)
    store_snapshot(current, directory=snap_dir, name=snapshot_name)
    logger.info("Snapshot saved as %s", snapshot_name)

    findings = []
    if baseline:
        diff_result = compute_diff(baseline, current)
        evaluator = DriftEvaluator()
        findings += evaluator.evaluate_drift(diff_result, baseline, current)

    last_ts = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    findings += evaluate_mfa_less(client, last_ts)

    # ---------------- Console summary ----------------
    if findings:
        summary: dict[str, int] = {}
        for f in findings:
            summary[f.category] = summary.get(f.category, 0) + len(f.details)

        print("[ALERT] Findings detected this cycle:")
        for cat, count in summary.items():
            print(f"  • {cat}: {count}")

        if os.getenv("SLACK_WEBHOOK_URL"):
            print("Full details have been sent to Slack.")
    else:
        print("[OK] No drift or anomalies detected this cycle.")

    # Only send HIGH severity alerts to Slack
    dispatcher = AlertDispatcher(
        slack_high_severity_only=settings.slack_high_severity_only
    )
    for f in findings:
        dispatcher.dispatch(f.to_payload(settings.okta_org_url, snapshot_name))


# -----------------------------------------------------------------------------
# Scheduler public API
# -----------------------------------------------------------------------------


def _cycle() -> None:
    try:
        _process()
    except Exception as exc:
        logger.exception("Scheduler cycle failed: %s", exc)


def start_scheduler(interval_seconds: int = 1800) -> None:
    scheduler = BackgroundScheduler()
    scheduler.add_job(_cycle, "interval", seconds=interval_seconds, next_run_time=datetime.now())
    scheduler.start()
    logger.info("Scheduler started. Press Ctrl+C to exit.")

    try:
        import time

        while True:
            time.sleep(5)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown() 