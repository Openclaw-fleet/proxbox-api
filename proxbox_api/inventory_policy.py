"""Operator-owned inventory boundaries, independent of remote plugin settings."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path

from proxbox_api.exception import ProxboxException


def _canonical_collection_path(value: object) -> bool:
    return (
        isinstance(value, str) and re.fullmatch(r"/api/(?:[a-z][a-z0-9_-]*/)*", value) is not None
    )


@lru_cache(maxsize=1)
def _read_policy_file(filename: str) -> dict:
    try:
        path = Path(filename)
        if not path.is_absolute():
            raise ValueError("Policy path must be absolute")
        policy = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(policy, dict)
            or "read_only_paths" not in policy
            or set(policy) - {"read_only_paths", "patch_fields"}
        ):
            raise ValueError("Unknown or missing policy keys")
        paths = policy["read_only_paths"]
        if not isinstance(paths, list) or any(
            not _canonical_collection_path(value) for value in paths
        ):
            raise ValueError("Expected canonical API collection paths")
        patch_fields = policy.get("patch_fields", {})
        if not isinstance(patch_fields, dict) or any(
            not _canonical_collection_path(prefix)
            or not isinstance(fields, list)
            or any(
                not isinstance(field, str) or re.fullmatch(r"[a-z][a-z0-9_]*", field) is None
                for field in fields
            )
            for prefix, fields in patch_fields.items()
        ):
            raise ValueError("Expected collection-to-field allowlists")
        return policy
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
    return any(path.startswith(prefix) for prefix in _read_policy_file(filename)["read_only_paths"])


def writable_patch_fields(path: str) -> frozenset[str] | None:
    """Intersect every matching field allowlist; absence retains legacy behavior."""
    filename = os.environ.get("PROXBOX_INVENTORY_POLICY_FILE")
    if filename is None:
        return None
    allowed = None
    for prefix, fields in _read_policy_file(filename).get("patch_fields", {}).items():
        if path.startswith(prefix):
            allowed = frozenset(fields) if allowed is None else allowed.intersection(fields)
    return allowed


def require_writable_patch(path: str, fields: Iterable[str]) -> None:
    """Reject direct mixed-ownership patches before sending any part of them."""
    require_writable_resource(path)
    allowed = writable_patch_fields(path)
    if allowed is not None and set(fields) - allowed:
        raise ProxboxException(
            message="Inventory ownership policy forbids updating these fields",
            http_status_code=403,
        )


def require_writable_resource(path: str) -> None:
    """Refuse direct mutations of resources owned outside this collector."""
    if resource_is_read_only(path):
        raise ProxboxException(
            message="Inventory ownership policy forbids writing this resource",
            http_status_code=403,
        )
