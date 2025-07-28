from __future__ import annotations

from pathlib import Path
from typing import Optional


def get_baseline_path(snap_dir: Path) -> Optional[Path]:
    """Return baseline.json if it exists, else the oldest snapshot.

    Args:
        snap_dir: Directory containing snapshot JSON files.

    Returns:
        Path to baseline file or None if directory is empty.
    """
    baseline_file = snap_dir / "baseline.json"
    if baseline_file.exists():
        return baseline_file

    snapshots = sorted(
        [p for p in snap_dir.glob("*.json") if p.name != "baseline.json"],
        key=lambda p: p.stat().st_mtime,
    )
    return snapshots[0] if snapshots else None 