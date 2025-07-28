from __future__ import annotations

import logging
import time
from typing import Any, Generator, List
from urllib.parse import urljoin

import requests
from requests import Response

# Remove Tenant import and dynamic token retrieval

logger = logging.getLogger(__name__)

USER_AGENT = "DCC-Policy-Drift/0.1"

# Allow at most ~120 requests per minute (2 rps). We use 0.6 s spacing for safety.
MIN_INTERVAL: float = 0.6


class OktaClient:
    """Minimal Okta API wrapper supporting required endpoints with pagination and 429 handling.

    Authentication is done using a *static* SSWS API token.
    """

    def __init__(self, org_url: str, token: str):
        self.base_url = org_url.rstrip("/")
        self.token = token
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
                "Authorization": f"SSWS {token}",
            }
        )
        self._last_request_ts: float = 0.0

    # --------------- Public high-level methods ---------------
    def get_sign_on_policies(self) -> List[dict[str, Any]]:
        params = {"type": "OKTA_SIGN_ON", "limit": 200, "expand": "rules"}
        return list(self._paged_get("/api/v1/policies", params=params))

    def get_mfa_policies(self) -> List[dict[str, Any]]:
        params = {"type": "MFA_ENROLL", "limit": 200, "expand": "rules"}
        return list(self._paged_get("/api/v1/policies", params=params))

    def get_session_policies(self) -> List[dict[str, Any]]:
        """Return session policies controlling token/session lifetimes."""
        params = {"type": "SESSION", "limit": 200, "expand": "rules"}
        try:
            return list(self._paged_get("/api/v1/policies", params=params))
        except Exception as exc:
            # Some orgs return 400 for unsupported type. Log and fallback.
            logger.info("Session policies not available via Management API: %s", exc)
            return []

    def get_access_policies(self) -> List[dict[str, Any]]:
        """Return application access policies (type ACCESS_POLICY) if supported."""
        params = {"type": "ACCESS_POLICY", "limit": 200, "expand": "rules"}
        try:
            return list(self._paged_get("/api/v1/policies", params=params))
        except Exception as exc:
            logger.info("Access policies not accessible via Management API: %s", exc)
            return []

    # Legacy helper kept for compatibility (no longer used in snapshot flow)
    def get_policy_rules(self, policy_id: str) -> List[dict[str, Any]]:
        path = f"/api/v1/policies/{policy_id}/rules"
        return list(self._paged_get(path, params={"limit": 200}))

    def get_apps(self) -> List[dict[str, Any]]:
        return list(self._paged_get("/api/v1/apps", params={"limit": 200, "filter": "status eq \"ACTIVE\""}))

    def get_idps(self) -> List[dict[str, Any]]:
        return list(self._paged_get("/api/v1/idps"))

    def get_mfa_less_logins(self, since_ts: str) -> List[dict[str, Any]]:
        params = {
            "since": since_ts,
            "limit": 1000,
            "filter": "eventType eq \"user.session.start\" and debugContext.debugData.factors eq \"NONE\"",
        }
        # Call once (no pagination) to avoid rate-limit exhaustion
        resp = self._rate_limited_request("GET", urljoin(self.base_url, "/api/v1/logs"), params=params)
        return resp.json() if resp.status_code == 200 else []

    def fetch_logs(self, since: str | None = None, filter_expr: str | None = None, limit: int = 200) -> list[dict]:
        """Fetch *up to* ``limit`` System Log events matching filter.

        Uses the internal rate-limited request helper and stops when the desired
        number of events is collected **or** after the first page that exceeds
        the limit. This keeps UI interactions snappy and avoids 429 responses.
        """
        url = f"{self.base_url}/api/v1/logs"
        params: dict[str, str] = {"limit": str(min(limit, 1000))}
        if since:
            params["since"] = since
        if filter_expr:
            params["filter"] = filter_expr

        events: list[dict] = []
        next_url: str | None = url
        first = True
        while next_url and len(events) < limit and first:
            resp = self._rate_limited_request(
                "GET", next_url, params=params if first else None
            )
            if resp.status_code == 429:
                # Hit rate limit – stop and return what we have.
                logger.warning("Rate limited when fetching logs; returning %d events", len(events))
                break
            resp.raise_for_status()
            batch = resp.json()
            events.extend(batch)

            # Only fetch one page for interactive UI to stay fast.
            first = False

            # Prepare for potential next page (background jobs can loop fully).
            link = resp.headers.get("Link", "")
            next_link = None
            for part in link.split(","):
                if "rel=\"next\"" in part:
                    next_link = part[part.find("<") + 1 : part.find(">")]
                    break
            next_url = next_link
        return events[:limit]

    def fetch_logs_page(self, *, since: str | None = None, filter_expr: str | None = None, after: str | None = None, limit: int = 200) -> tuple[list[dict], str | None]:
        """Fetch **one** page of system logs and return (events, next_after_token)."""
        params: dict[str, str] = {"limit": str(min(limit, 1000))}
        if since:
            params["since"] = since
        if filter_expr:
            params["filter"] = filter_expr
        if after:
            params["after"] = after

        url = f"{self.base_url}/api/v1/logs"
        resp = self._rate_limited_request("GET", url, params=params)
        if resp.status_code == 429:
            logger.warning("Rate limited when fetching logs page")
            return [], None
        resp.raise_for_status()
        events = resp.json()

        # Parse next after token
        next_after: str | None = None
        link = resp.headers.get("Link", "")
        for part in link.split(","):
            if "rel=\"next\"" in part:
                next_url = part[part.find("<") + 1 : part.find(">")]
                import urllib.parse as _up
                qs = _up.urlparse(next_url).query
                next_after = _up.parse_qs(qs).get("after", [None])[0]
                break
        return events, next_after

    def download_logs_csv(self, since: str, until: str, query: str | None = None) -> list[dict]:
        """Download CSV export of system log via Management API and return parsed events list."""
        url = f"{self.base_url}/api/v1/logs"
        params = {"since": since, "until": until, "limit": "1000"}
        if query:
            params["q"] = query
        headers = {"Accept": "text/csv"}
        resp = self._rate_limited_request("GET", url, params=params, headers=headers)
        resp.raise_for_status()
        import io, csv
        data = resp.text
        from .logs import csv_to_events
        events = csv_to_events(io.BytesIO(data.encode()))
        return events

    # --------------- Generic policy fetch ---------------

    def get_policies(self, policy_type: str) -> List[dict[str, Any]]:
        """Return list of policies of a given *policy_type*.

        If the tenant does not support this type, Okta usually responds with
        HTTP 400. We catch that and return an empty list so the snapshot flow
        continues gracefully.
        """

        params = {"type": policy_type, "limit": 200, "expand": "rules"}
        try:
            return list(self._paged_get("/api/v1/policies", params=params))
        except Exception as exc:  # pragma: no cover
            logger.info("Policy type %s not accessible via Management API: %s", policy_type, exc)
            return []

    # ---------------- Additional helper APIs ----------------
    def list_apps(self, limit: int = 200) -> list[dict]:
        """Return list of all applications (id + label)."""
        import requests

        url = f"{self.base_url}/api/v1/apps"
        params = {"limit": str(limit)}
        headers = {"Authorization": f"SSWS {self.token}", "Accept": "application/json"}
        apps: list[dict] = []
        while url:
            resp = requests.get(url, headers=headers, params=params if "?" not in url else None, timeout=30)
            resp.raise_for_status()
            batch = resp.json()
            apps.extend(batch)
            link = resp.headers.get("Link", "")
            next_url = None
            for part in link.split(","):
                if "rel=\"next\"" in part:
                    next_url = part[part.find("<") + 1 : part.find(">")]
                    break
            url = next_url
            params = None
        return [{"id": a["id"], "name": a.get("label", a.get("name", "Unnamed"))} for a in apps]

    def list_users_without_mfa(self, limit_per_page: int = 200) -> set[str]:
        """Return a set of user emails that have no enrolled MFA factors."""
        import requests

        users: list[dict] = []
        url = f"{self.base_url}/api/v1/users"
        params = {"limit": str(limit_per_page)}
        headers = {"Authorization": f"SSWS {self.token}", "Accept": "application/json"}
        while url:
            resp = requests.get(url, headers=headers, params=params if "?" not in url else None, timeout=30)
            resp.raise_for_status()
            batch = resp.json()
            users.extend(batch)
            link = resp.headers.get("Link", "")
            next_url = None
            for part in link.split(","):
                if "rel=\"next\"" in part:
                    next_url = part[part.find("<") + 1 : part.find(">")]
                    break
            url = next_url
            params = None

        no_factor_users: set[str] = set()
        for u in users:
            user_id = u["id"]
            email = u.get("profile", {}).get("email", user_id)
            factors_resp = requests.get(
                f"{self.base_url}/api/v1/users/{user_id}/factors",
                headers=headers,
                timeout=30,
            )
            factors_resp.raise_for_status()
            factors = factors_resp.json()
            if not factors:
                no_factor_users.add(email)
        return no_factor_users

    # --------------- Internal helpers ---------------
    def _paged_get(self, path: str, *, params: dict[str, Any] | None = None) -> Generator[dict[str, Any], None, None]:
        url = urljoin(self.base_url, path)
        while url:
            resp = self._request_with_backoff("GET", url, params=params)
            data = resp.json()
            if isinstance(data, list):
                for item in data:
                    yield item
            else:
                yield data
            url = self._parse_next_link(resp)
            params = None  # subsequent pages continue via next link

    # Management endpoints (policies, apps, idps) – limited retries with small
    # back-off, plus global rate-limit pacing.
    def _request_with_backoff(self, method: str, url: str, **kwargs) -> Response:
        retries = 0
        backoff = 1
        while True:
            resp = self._rate_limited_request(method, url, **kwargs)
            if resp.status_code != 429:
                resp.raise_for_status()
                return resp
            # 429 with Retry-After header – adhere if present
            retry_after = int(resp.headers.get("Retry-After", backoff))
            time.sleep(retry_after)
            retries += 1
            if retries > 2:
                logger.error("Exceeded retry count for %s", url)
                raise RuntimeError("Too many 429 responses from Okta API")
            backoff *= 2

    # Generic single call with global pacing
    def _rate_limited_request(self, method: str, url: str, **kwargs) -> Response:
        # ensure at most ~1/MIN_INTERVAL requests per second overall
        elapsed = time.time() - self._last_request_ts
        if elapsed < MIN_INTERVAL:
            time.sleep(MIN_INTERVAL - elapsed)
        resp: Response = self.session.request(method, url, timeout=30, **kwargs)
        self._last_request_ts = time.time()
        return resp

    @staticmethod
    def _parse_next_link(resp: Response) -> str | None:
        link_header = resp.headers.get("Link")
        if not link_header:
            return None
        for part in link_header.split(","):
            if "rel=\"next\"" in part:
                url_part = part.split(";")[0].strip(" <>\t\n")
                return url_part
        return None 