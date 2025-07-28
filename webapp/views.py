from __future__ import annotations

import json
from pathlib import Path
import logging
logger = logging.getLogger(__name__)

from flask import Blueprint, current_app, render_template, request, redirect, url_for, flash, abort, session

from dcc_policy_drift.okta_client import OktaClient
from dcc_policy_drift.snapshot import take_snapshot, store_snapshot, extract_org_id
from dcc_policy_drift.config import settings
from dcc_policy_drift.diff import compute_diff
from datetime import datetime, timedelta, timezone
from dcc_policy_drift.logs import LogsAnalyzer

bp = Blueprint("main", __name__)

PAGINATION_SIZE = 10

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _store():
    return current_app.config["TENANT_STORE"]


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@bp.route("/", methods=["GET", "POST"])
def index():
    store = _store()

    if request.method == "POST":
        try:
            store.add(
                name=request.form["name"],
                environment=request.form["environment"],
                org_url=request.form["org_url"],
                token=request.form["token"],
                slack_url=request.form.get("slack_url") or None,
                slack_high_severity_only=request.form.get("slack_high_severity_only") == "true",
            )
            flash("Tenant added successfully", "success")
        except ValueError as exc:
            flash(str(exc), "danger")
        return redirect(url_for("main.index"))

    return render_template("index.html", tenants=store.list())


@bp.route("/tenant/<tenant_id>")
def tenant_detail(tenant_id: str):
    store = _store()
    tenant = store.get(tenant_id)
    if not tenant:
        abort(404)

    page = request.args.get("page", 1, type=int)

    manager = current_app.config["SCHEDULER_MANAGER"]

    snap_dir = settings.snapshot_dir / tenant_id
    all_snapshots = sorted([p.stem for p in snap_dir.glob("*.json")], reverse=True) if snap_dir.exists() else []

    start_index = (page - 1) * PAGINATION_SIZE
    end_index = start_index + PAGINATION_SIZE
    snapshots_page = all_snapshots[start_index:end_index]

    total_pages = (len(all_snapshots) + PAGINATION_SIZE - 1) // PAGINATION_SIZE

    scheduler_running = manager.is_running(tenant_id)

    # Only include configuration-drift related alerting rules (exclude user-activity log rules)
    from dcc_policy_drift.rules import RULES as _RULES  # inline import to avoid circular deps

    CONFIG_RULE_IDS = [
        "POLICY_DRIFT",
        "APPLICATION_DELETION",
        "POLICY_CREATED",
        "POLICY_DELETED",
        "SMS_FACTOR_ADDED",
        "SMS_AUTH_RULE_ADDED",
    ]
    config_rules = {rid: _RULES[rid] for rid in CONFIG_RULE_IDS if rid in _RULES}

    return render_template(
        "tenant.html",
        tenant=tenant,
        snapshots=snapshots_page,
        scheduler_running=scheduler_running,
        page=page,
        total_pages=total_pages,
        RULES=config_rules,
    )


# ---------------- Edit & Delete routes ----------------


@bp.route("/tenant/<tenant_id>/edit", methods=["GET", "POST"])
def edit_tenant(tenant_id: str):
    store = _store()
    tenant = store.get(tenant_id)
    if not tenant:
        abort(404)

    if request.method == "POST":
        # Special sub-action: update rule severities form inside tenant page
        if request.form.get("action") == "update_severities":
            from dcc_policy_drift.rules import RULES as _RULES
            sev_map = {
                rid: request.form.get(f"severity_{rid}", _RULES[rid]["default_severity"])
                for rid in _RULES
            }
            store.update(tenant_id, rule_severities=sev_map)
            flash("Alerting rule severities updated", "success")
            next_page = request.form.get("next")
            if next_page == "logs":
                return redirect(url_for("main.tenant_logs", tenant_id=tenant_id))
            return redirect(url_for("main.tenant_detail", tenant_id=tenant_id))
        store.update(
            tenant_id,
            name=request.form["name"],
            env=request.form["environment"],
            org_url=request.form["org_url"],
            token=request.form["token"],
            slack_url=request.form.get("slack_url"),
            slack_high_severity_only=request.form.get("slack_high_severity_only") == "true",
            # rule_severities left unchanged in standard edit flow
        )
        flash("Tenant updated", "success")
        return redirect(url_for("main.tenant_detail", tenant_id=tenant_id))

    return render_template("edit_tenant.html", tenant=tenant)


# ---------------- Rule severity quick toggle ----------------


@bp.route("/tenant/<tenant_id>/rule/<rule_id>/severity/cycle", methods=["POST"])
def change_rule_severity(tenant_id: str, rule_id: str):
    store = _store()
    tenant = store.get(tenant_id)
    if not tenant:
        abort(404)

    # Compute next severity
    current = tenant.get("rule_severities", {}).get(rule_id, "low").lower()
    cycle = {"low": "medium", "medium": "high", "high": "low"}
    next_sev = cycle.get(current, "low")

    sev_map = tenant.get("rule_severities", {})
    sev_map[rule_id] = next_sev
    store.update(tenant_id, rule_severities=sev_map)

    # Where to redirect back (logs or tenant page)
    next_page = request.args.get("next")
    if next_page == "logs":
        return redirect(url_for("main.tenant_logs", tenant_id=tenant_id))
    return redirect(url_for("main.tenant_detail", tenant_id=tenant_id))


@bp.route("/tenant/<tenant_id>/delete", methods=["POST"])
def delete_tenant(tenant_id: str):
    store = _store()
    tenant = store.get(tenant_id)
    if not tenant:
        abort(404)

    # Stop scheduler if running
    manager = current_app.config["SCHEDULER_MANAGER"]
    if manager.is_running(tenant_id):
        manager.stop(tenant_id)

    store.delete(tenant_id)
    flash("Tenant deleted", "info")
    return redirect(url_for("main.index"))


@bp.route("/tenant/<tenant_id>/snapshot/delete/<snap_name>", methods=["POST"])
def delete_snapshot(tenant_id: str, snap_name: str):
    store = _store()
    tenant = store.get(tenant_id)
    if not tenant:
        abort(404)

    snap_dir = settings.snapshot_dir / tenant_id
    snap_path = snap_dir / f"{snap_name}.json"

    if snap_path.exists():
        if "baseline" in snap_name:
            flash("Cannot delete baseline snapshot.", "danger")
        else:
            snap_path.unlink()
            flash(f"Snapshot '{snap_name}' deleted.", "success")
    else:
        flash(f"Snapshot '{snap_name}' not found.", "danger")

    return redirect(url_for("main.tenant_detail", tenant_id=tenant_id))


@bp.route("/tenant/<tenant_id>/snapshot", methods=["POST"])
def take_tenant_snapshot(tenant_id: str):
    store = _store()
    tenant = store.get(tenant_id)
    if not tenant:
        abort(404)

    import os
    from dcc_policy_drift.config import settings as _settings

    if tenant.get("slack_url"):
        os.environ["SLACK_WEBHOOK_URL"] = tenant["slack_url"]
        _settings.slack_webhook_url = tenant["slack_url"]
    else:
        os.environ.pop("SLACK_WEBHOOK_URL", None)
        _settings.slack_webhook_url = None

    client = OktaClient(tenant["org_url"], tenant["token"])

    try:
        snap = take_snapshot(client)
    except Exception as exc:  # noqa: BLE001
        import logging, traceback

        logging.getLogger(__name__).error("Snapshot failed: %s", exc)
        logging.getLogger(__name__).debug(traceback.format_exc())
        flash(f"Snapshot failed – {exc}", "danger")
        return redirect(url_for("main.tenant_detail", tenant_id=tenant_id))

    dir_path = settings.snapshot_dir / extract_org_id(client.base_url)
    snap_path = store_snapshot(snap, directory=dir_path)

    # Evaluate diff & MFA-less similar to CLI snapshot command
    from dcc_policy_drift.baseline import get_baseline_path
    from dcc_policy_drift.diff import compute_diff
    from dcc_policy_drift.evaluator import DriftEvaluator, evaluate_mfa_less
    from datetime import datetime, timedelta, timezone

    baseline_path = get_baseline_path(dir_path)
    baseline = None
    if baseline_path and baseline_path != snap_path:
        import json as _json, pathlib as _pl
        baseline = _json.loads(_pl.Path(baseline_path).read_text())

    findings = []
    if baseline:
        diff_result = compute_diff(baseline, snap)
        evaluator = DriftEvaluator()
        findings += evaluator.evaluate_drift(diff_result, baseline, snap, tenant.get("rule_severities"))

    last_ts = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    findings += evaluate_mfa_less(client, last_ts, tenant.get("rule_severities"))

    if findings:
        summary: dict[str, int] = {}
        for f in findings:
            summary[f.category] = summary.get(f.category, 0) + len(f.details)
        summary_str = ", ".join(f"{cat}: {count}" for cat, count in summary.items())
        # Send to Slack
        from dcc_policy_drift.alerts import AlertDispatcher

        dispatcher = AlertDispatcher(
            slack_high_severity_only=tenant.get("slack_high_severity_only", True)
        )
        for f in findings:
            dispatcher.dispatch(f.to_payload(tenant["org_url"], snap_path.stem))

        flash(f"Snapshot saved as {snap_path.stem}. Findings detected – {summary_str}", "warning")
    else:
        flash(f"Snapshot saved as {snap_path.stem}. No drift or anomalies detected.", "success")

    # Redirect to snapshot detail page for full view
    return redirect(url_for("main.snapshot_detail", tenant_id=tenant_id, snap_name=snap_path.stem))


@bp.route("/compare", methods=["GET", "POST"])
def compare():
    store = _store()
    tenants = store.list()

    snapshots_map = {}
    for t in tenants:
        snap_dir = settings.snapshot_dir / t["id"]
        if snap_dir.exists():
            snapshots_map[t["id"]] = sorted(
                [{"name": p.stem, "path": str(p)} for p in snap_dir.glob("*.json")],
                key=lambda x: x["name"],
                reverse=True
            )

    diff_result = None
    snapshot_a_path, snapshot_b_path = None, None
    if request.method == "POST":
        snapshot_a_path = request.form.get("snapshot_a")
        snapshot_b_path = request.form.get("snapshot_b")

        if snapshot_a_path and snapshot_b_path:
            path1 = Path(snapshot_a_path)
            path2 = Path(snapshot_b_path)
            if not path1.exists() or not path2.exists():
                flash("Snapshot file not found", "danger")
                return redirect(url_for("main.compare"))
            snap1 = json.loads(path1.read_text())
            snap2 = json.loads(path2.read_text())
            diff_result = compute_diff(snap1, snap2).changes
        else:
            flash("Please select two snapshots to compare", "warning")

    return render_template(
        "compare.html",
        tenants=tenants,
        snapshots_map=snapshots_map,
        snapshot_a_path=snapshot_a_path,
        snapshot_b_path=snapshot_b_path,
        differences=diff_result,
    )


# ---------------- Scheduler routes ----------------


@bp.route("/tenant/<tenant_id>/scheduler/start", methods=["POST"])
def start_scheduler(tenant_id: str):
    store = _store()
    tenant = store.get(tenant_id)
    if not tenant:
        abort(404)

    interval = int(request.form.get("interval", 30))  # minutes
    manager = current_app.config["SCHEDULER_MANAGER"]
    try:
        manager.start(tenant, interval_minutes=interval)
        flash(f"Scheduler started (every {interval} min)", "success")
    except ValueError as exc:
        flash(str(exc), "warning")
    return redirect(url_for("main.tenant_detail", tenant_id=tenant_id))


@bp.route("/tenant/<tenant_id>/scheduler/stop", methods=["POST"])
def stop_scheduler(tenant_id: str):
    manager = current_app.config["SCHEDULER_MANAGER"]
    if manager.is_running(tenant_id):
        manager.stop(tenant_id)
        flash("Scheduler stopped", "info")
    else:
        flash("Scheduler not running", "warning")
    return redirect(url_for("main.tenant_detail", tenant_id=tenant_id))


# ---------------- Snapshot detail & promote ----------------


@bp.route("/tenant/<tenant_id>/snapshot/<snap_name>")
def snapshot_detail(tenant_id: str, snap_name: str):
    store = _store()
    tenant = store.get(tenant_id)
    if not tenant:
        abort(404)

    snap_dir = settings.snapshot_dir / tenant_id
    snap_path = snap_dir / f"{snap_name}.json"
    if not snap_path.exists():
        abort(404)

    import json as _json, pathlib as _pl
    current = _json.loads(snap_path.read_text())

    # Baseline
    from dcc_policy_drift.baseline import get_baseline_path
    baseline_path = get_baseline_path(snap_dir)
    baseline = None
    if baseline_path and baseline_path != snap_path:
        baseline = _json.loads(baseline_path.read_text())

    diff_changes = []
    if baseline:
        from dcc_policy_drift.diff import compute_diff

        diff_changes = compute_diff(baseline, current).changes

    return render_template(
        "snapshot_detail.html",
        tenant=tenant,
        snap_name=snap_name,
        diff=diff_changes,
        baseline_name=baseline_path.stem if baseline_path else None,
        snapshot_json=current,
    )


@bp.route("/tenant/<tenant_id>/snapshot/<snap_name>/promote", methods=["POST"])
def promote_snapshot(tenant_id: str, snap_name: str):
    store = _store()
    tenant = store.get(tenant_id)
    if not tenant:
        abort(404)

    snap_dir = settings.snapshot_dir / tenant_id
    target_path = snap_dir / f"{snap_name}.json"
    if not target_path.exists():
        abort(404)

    from shutil import copy2
    import os, uuid

    baseline_path = snap_dir / "baseline.json"
    tmp_path = baseline_path.with_suffix(".tmp_" + uuid.uuid4().hex)
    copy2(target_path, tmp_path)
    os.replace(tmp_path, baseline_path)

    flash(f"Promoted {snap_name} as new baseline", "success")
    return redirect(url_for("main.snapshot_detail", tenant_id=tenant_id, snap_name=snap_name))


@bp.route("/tenant/<tenant_id>/logs")
def tenant_logs(tenant_id: str):
    store = _store()
    tenant = store.get(tenant_id)
    if not tenant:
        abort(404)

    client = OktaClient(tenant["org_url"], tenant["token"])

    # Time window - last 24h unless ?hours param provided
    hours = request.args.get("hours", 24, type=int)
    since_ts = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    # Fetch events
    source = request.args.get("source")
    session_key = f"csv_events_{tenant_id}"
    if source == "csv" and session_key in current_app.config:
        events = current_app.config[session_key]
        next_after = None
    else:
        # No log events when not using CSV sources
        events = []
        next_after = None

    # MFA-required apps config
    mfa_required_set = set(tenant.get("mfa_required_apps", []))

    # Users without factors set – check only users present in events
    users_without_mfa: set[str] = set()
    if events:
        unique_user_ids = {
            ev.get("actor", {}).get("id") for ev in events if ev.get("actor", {}).get("type") == "User"
        }
        unique_user_ids = list(unique_user_ids)[:100]
        headers = {"Authorization": f"SSWS {client.token}", "Accept": "application/json"}
        import requests
        for uid in unique_user_ids:
            if not uid:
                continue
            try:
                resp = requests.get(f"{client.base_url}/api/v1/users/{uid}/factors", headers=headers, timeout=15)
                resp.raise_for_status()
                factors = resp.json()
                if not factors:
                    email = next(
                        (ev.get("actor", {}).get("alternateId") for ev in events if ev.get("actor", {}).get("id") == uid),
                        uid,
                    )
                    users_without_mfa.add(email)
            except Exception as exc:  # noqa: BLE001
                logger.info("Factor fetch failed for %s: %s", uid, exc)

    findings_objs = []
    if events:
        analyzer = LogsAnalyzer(mfa_required_set)
        findings_objs = analyzer.analyze(events, users_without_mfa, tenant.get("rule_severities"))

    # ---------------- Pagination ----------------
    events_per_page = 200
    findings_per_page = 100

    ev_page = request.args.get("ev_page", 1, type=int)
    fd_page = request.args.get("fd_page", 1, type=int)

    ev_total_pages = (len(events) + events_per_page - 1) // events_per_page or 1
    fd_total_pages = (len(findings_objs) + findings_per_page - 1) // findings_per_page or 1

    # ------------- Filtering -----------------
    user_q = request.args.get("user_filter", "").lower()
    app_q = request.args.get("app_filter", "").lower()
    severity_q = request.args.get("severity_filter", "").lower()

    if user_q:
        events = [e for e in events if user_q in (e.get("actor", {}).get("alternateId", "").lower())]
    if app_q:
        events = [e for e in events if app_q in (e.get("target", [{}])[0].get("displayName", "").lower())]

    # Re-run analyzer filtering after event filter
    if events:
        analyzer = LogsAnalyzer(mfa_required_set)
        findings_objs = analyzer.analyze(events, users_without_mfa, tenant.get("rule_severities"))
    else:
        findings_objs = []

    if user_q:
        findings_objs = [f for f in findings_objs if user_q in f.user.lower()]
    if app_q:
        findings_objs = [f for f in findings_objs if app_q in f.app.lower()]

    if severity_q in {"high", "medium", "low"}:
        findings_objs = [f for f in findings_objs if f.severity.lower() == severity_q]

    events_page = events[(ev_page - 1) * events_per_page : ev_page * events_per_page]
    findings_page = findings_objs[(fd_page - 1) * findings_per_page : fd_page * findings_per_page]

    findings = [
        {
            "time": f.time,
            "user": f.user,
            "app": f.app,
            "issue": f.issue,
            "severity": f.severity,
            "raw": f.raw,
        }
        for f in findings_objs
    ]

    # Get apps list for toggle UI
    try:
        apps_list = client.list_apps()
    except Exception as exc:
        apps_list = []
        flash(f"Could not fetch apps list – {exc}", "warning")

    return render_template(
        "logs.html",
        tenant=tenant,
        events=[
            {
                "time": e.get("published"),
                "user": e.get("actor", {}).get("alternateId"),
                "app": e.get("target", [{}])[0].get("displayName", "Unknown"),
                "mfa": "Yes" if e.get("authenticationContext", {}).get("authenticationStep") == 2 else "No",
                "raw": e,
            }
            for e in events_page
        ],
        findings=findings_page,
        apps=apps_list,
        mfa_required=mfa_required_set,
        hours=hours,
        next_after=next_after,
        ev_page=ev_page,
        ev_total_pages=ev_total_pages,
        fd_page=fd_page,
        fd_total_pages=fd_total_pages,
        user_filter=user_q,
        app_filter=app_q,
        source=source,
        RULES=__import__('dcc_policy_drift.rules', fromlist=['RULES']).RULES,
    )

@bp.route("/tenant/<tenant_id>/logs/upload", methods=["POST"])
def upload_logs_csv(tenant_id: str):
    store = _store()
    tenant = store.get(tenant_id)
    if not tenant:
        abort(404)

    file = request.files.get("csv_file")
    if not file or not file.filename.endswith(".csv"):
        flash("Please upload a CSV file", "warning")
        return redirect(url_for("main.tenant_logs", tenant_id=tenant_id))

    from dcc_policy_drift.logs import csv_to_events

    events = csv_to_events(file)
    mfa_required_set = set(tenant.get("mfa_required_apps", []))

    analyzer = LogsAnalyzer(mfa_required_set)
    findings_objs = analyzer.analyze(events, None, tenant.get("rule_severities"))

    flash(f"Imported {len(events)} events from CSV – {len(findings_objs)} findings detected", "success")
    # Store events in session for display (simple cache)
    session_key = f"csv_events_{tenant_id}"
    current_app.config[session_key] = events
    return redirect(url_for("main.tenant_logs", tenant_id=tenant_id, source="csv"))


@bp.route("/tenant/<tenant_id>/logs/toggle_mfa/<app_id>", methods=["POST"])
def toggle_app_mfa(tenant_id: str, app_id: str):
    store = _store()
    tenant = store.get(tenant_id)
    if not tenant:
        abort(404)
    required_now = app_id in tenant.get("mfa_required_apps", [])
    store.set_mfa_required(tenant_id, app_id, not required_now)
    flash("App MFA requirement updated", "success")
    return redirect(url_for("main.tenant_logs", tenant_id=tenant_id))


# -----------------------------------------------------------------------------
# Template filters
# -----------------------------------------------------------------------------

@bp.app_template_filter("pretty_json")
def pretty_json(value):
    """Return safe JSON string with indentation, converting unknown objects with str()."""
    import json
    from markupsafe import Markup

    try:
        json_str = json.dumps(value, indent=2, default=str)
    except Exception:
        # Fallback: rough string representation
        json_str = str(value)
    return Markup(json_str)


# ---------------- Error handlers ----------------


@bp.app_errorhandler(404)
def not_found_error(error):
    return render_template("404.html"), 404 