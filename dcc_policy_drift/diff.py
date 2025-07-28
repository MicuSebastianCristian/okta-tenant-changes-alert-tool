from __future__ import annotations

import json
from typing import Any, List, Tuple, Hashable

from deepdiff import DeepDiff  # type: ignore

DEFAULT_EXCLUDE = {"takenAt", "snapshotId"}


class DiffResult:
    def __init__(self, changes: List[dict[str, Any]]):
        self.changes = changes

    def is_empty(self) -> bool:
        return len(self.changes) == 0

    def to_json(self) -> str:
        return json.dumps(self.changes, indent=2)


def compute_diff(base_snapshot: dict[str, Any], current_snapshot: dict[str, Any]) -> DiffResult:
    """Return list of change dicts with action/add/del/edit."""
    diffs: List[dict[str, Any]] = []

    def _rule_key(obj: dict[str, Any]) -> Hashable:  # composite key for rules
        return (obj.get("policyId"), obj.get("name"))

    for key in ("policies", "policyRules", "apps", "idps"):
        if key == "policyRules":
            base_items = {_rule_key(item): item for item in base_snapshot.get(key, [])}
            curr_items = {_rule_key(item): item for item in current_snapshot.get(key, [])}
        else:
            base_items = {item["id"]: item for item in base_snapshot.get(key, [])}
            curr_items = {item["id"]: item for item in current_snapshot.get(key, [])}

        added_keys = curr_items.keys() - base_items.keys()
        removed_keys = base_items.keys() - curr_items.keys()
        common_keys = base_items.keys() & curr_items.keys()

        def _id_for(item_key):
            # Resolve back to real Okta id for consistent payloads
            if key == "policyRules":
                return curr_items.get(item_key, base_items.get(item_key, {})).get("id")
            return item_key  # id key itself

        for ak in added_keys:
            diffs.append({"action": "added", "object": key[:-1], "id": _id_for(ak)})
        for rk in removed_keys:
            diffs.append({"action": "deleted", "object": key[:-1], "id": _id_for(rk)})
        for ck in common_keys:
            ddiff: DeepDiff | dict[str, Any] = DeepDiff(base_items[ck], curr_items[ck], exclude_paths=DEFAULT_EXCLUDE, ignore_order=True)
            if ddiff:
                diffs.append({"action": "modified", "object": key[:-1], "id": _id_for(ck), "changes": ddiff.to_dict() if hasattr(ddiff, "to_dict") else ddiff})
    return DiffResult(diffs) 