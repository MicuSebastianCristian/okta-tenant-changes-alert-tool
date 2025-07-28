from __future__ import annotations

from flask import Flask
from pathlib import Path

from .tenant_store import TenantStore
from dcc_policy_drift.config import settings


def create_app() -> Flask:
    """Application factory for the Okta Policy Drift web UI."""
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    # NOTE: For demo purposes we use a hard-coded secret key. Replace in production.
    app.secret_key = "okta_policy_drift_demo_secret"

    # Initialise tenant store backed by YAML file
    store_path = Path(settings.tenants_file)
    store_path.parent.mkdir(parents=True, exist_ok=True)
    app.config["TENANT_STORE"] = TenantStore(store_path)

    # Scheduler manager shared across requests
    from .scheduler_manager import SchedulerManager

    app.config["SCHEDULER_MANAGER"] = SchedulerManager()

    # Register routes
    from .views import bp as main_bp  # local import to avoid circular deps

    app.register_blueprint(main_bp)

    return app 