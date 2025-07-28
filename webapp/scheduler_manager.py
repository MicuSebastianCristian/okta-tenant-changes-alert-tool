from __future__ import annotations

"""Utility for starting/stopping per-tenant schedulers inside the web UI.

Each tenant gets its own APScheduler instance that periodically executes
`dcc_policy_drift.scheduler._process` with the appropriate environment
variables set for that tenant (token/org/slack).

The manager keeps the reference to running schedulers so that they can
be stopped from the UI.
"""

from typing import Dict, Any
import os
import threading

from apscheduler.schedulers.background import BackgroundScheduler

# We re-use the private _process function to execute one monitoring cycle.
from dcc_policy_drift.scheduler import _process as _run_cycle  # type: ignore


def _build_cycle_fn(tenant: Dict[str, Any]):
    """Return a callable that executes one monitoring cycle for a tenant."""

    def _cycle():
        from dcc_policy_drift.config import settings as _settings

        os.environ["OKTA_TOKEN"] = tenant["token"]
        os.environ["OKTA_ORG_URL"] = tenant["org_url"]
        _settings.okta_token = tenant["token"]
        _settings.okta_org_url = tenant["org_url"]

        if tenant.get("slack_url"):
            os.environ["SLACK_WEBHOOK_URL"] = tenant["slack_url"]
            _settings.slack_webhook_url = tenant["slack_url"]
        else:
            os.environ.pop("SLACK_WEBHOOK_URL", None)
            _settings.slack_webhook_url = None

        try:
            _run_cycle()
        except Exception as exc:  # noqa: BLE001
            import logging

            logging.getLogger(__name__).exception("Scheduler cycle failed: %s", exc)

    return _cycle


class SchedulerManager:
    """Keeps track of per-tenant BackgroundScheduler instances."""

    def __init__(self):
        self._schedulers: Dict[str, BackgroundScheduler] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self, tenant: Dict[str, Any], interval_minutes: int = 30) -> None:
        tenant_id = tenant["id"]
        with self._lock:
            if tenant_id in self._schedulers:
                raise ValueError("Scheduler already running for this tenant.")
            sched = BackgroundScheduler()
            from datetime import datetime

            sched.add_job(
                _build_cycle_fn(tenant),
                "interval",
                minutes=interval_minutes,
                next_run_time=datetime.now(),  # run immediately
                max_instances=1,
                coalesce=True,
            )
            sched.start()
            self._schedulers[tenant_id] = sched

    def stop(self, tenant_id: str):
        with self._lock:
            sched = self._schedulers.pop(tenant_id, None)
            if sched:
                sched.shutdown(wait=False)

    def is_running(self, tenant_id: str) -> bool:
        with self._lock:
            return tenant_id in self._schedulers 