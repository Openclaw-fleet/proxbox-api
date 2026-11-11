"""Operator-owned inventory boundaries, independent of remote plugin settings."""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path

from netbox_sdk.client import normalize_request_path

from proxbox_api.exception import ProxboxException


@lru_cache(maxsize=1)
def _read_policy_file(filename: str) -> tuple[str, ...]:
    try:
        path = Path(filename)
        if not path.is_absolute():
            raise ValueError("Policy path must be absolute")
        policy = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(policy, dict) or set(policy) != {"read_only_paths"}:
            raise ValueError("Unknown or missing policy keys")
        paths = policy["read_only_paths"]
        if not isinstance(paths, list) or any(
            not isinstance(value, str)
            or re.fullmatch(r"/api/(?:[a-z][a-z0-9_-]*/)*", value) is None
            for value in paths
        ):
            raise ValueError("Expected canonical API collection paths")
        return tuple(paths)
    except (OSError, ValueError, UnicodeError):
        raise ProxboxException(
            message="Inventory ownership policy is unavailable or invalid",
            http_status_code=503,
        ) from None


def resource_is_read_only(path: str) -> bool:
    """Check a normalized REST path against the private, operator-selected file.

    Omission retains legacy behavior. A configured but invalid/unreadable file
    never falls back to unrestricted writes. Files are pinned on first use;
    restart the process after changing policy.
    """
    filename = os.environ.get("PROXBOX_INVENTORY_POLICY_FILE")
    if filename is None:
        return False
    path = normalize_request_path(path)
    return any(path.startswith(prefix) for prefix in _read_policy_file(filename))


def require_writable_resource(path: str) -> None:
    """Refuse direct mutations of resources owned outside this collector."""
    if resource_is_read_only(path):
        raise ProxboxException(
            message="Inventory ownership policy forbids writing this resource",
            http_status_code=403,
        )
