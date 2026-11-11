"""Diff-semantics canary for ``proxbox_api.services.netbox_writers``.

These tests pin the drift-detection contract of the new typed ``upsert_*``
helpers and the underlying ``rest_reconcile_async_with_status`` primitive
introduced for issue #357: GET → diff against the desired payload → PATCH
only when the diff is non-empty → report ``created`` / ``updated`` /
``unchanged``.

Mocks operate at the ``proxbox_api.netbox_rest`` boundary: ``rest_first_async``
returns the pre-existing record (or ``None``), ``rest_create_async`` records
POST traffic, and the fake record's ``save()`` records PATCH traffic. The
schema and current-record normalizer are exercised end-to-end through the
real ``NetBoxClusterTypeSyncState`` / ``NetBoxClusterSyncState`` models.
"""

from __future__ import annotations

from typing import Any

import pytest

from proxbox_api import netbox_rest
from proxbox_api.netbox_rest import (
    ReconcileResult,
    rest_reconcile_async_with_status,
)
from proxbox_api.proxmox_to_netbox.models import NetBoxClusterTypeSyncState
from proxbox_api.services.netbox_writers import (
    UpsertResult,
    upsert_cluster,
    upsert_cluster_type,
)

_PROXBOX_TAG: list[dict[str, object]] = [
    {"id": 5, "name": "Proxbox", "slug": "proxbox", "color": "ff5722"},
]


class _FakeRecord:
    """Stand-in for a NetBox record returned by ``rest_first_async``.

    Tracks PATCH traffic via ``.save()`` and field assignments via
    ``__setattr__``. ``serialize()`` returns the current payload so the
    reconcile primitive can normalize and diff against it.
    """

    def __init__(self, payload: dict[str, Any], record_id: int = 1) -> None:
        object.__setattr__(self, "_payload", dict(payload))
        object.__setattr__(self, "id", record_id)
        object.__setattr__(self, "save_calls", 0)
        object.__setattr__(self, "patched_fields", {})

    def serialize(self) -> dict[str, Any]:
        return {**self._payload, "id": self.id}

    def get(self, key: str, default: Any = None) -> Any:
        return self._payload.get(key, default)

    async def save(self) -> None:
        object.__setattr__(self, "save_calls", self.save_calls + 1)
        self._payload.update(self.patched_fields)

    def __setattr__(self, key: str, value: Any) -> None:
        if key in {"_payload", "id", "save_calls", "patched_fields"}:
            object.__setattr__(self, key, value)
            return
        self.patched_fields[key] = value


def _existing_cluster_type_payload(
    *, name: str = "Cluster", slug: str = "cluster"
) -> dict[str, Any]:
    return {
        "name": name,
        "slug": slug,
        "description": "Proxmox cluster mode",
        "tags": _PROXBOX_TAG,
    }


@pytest.fixture
def patch_rest(monkeypatch: pytest.MonkeyPatch):
    """Install fakes for the three REST seams used by the reconcile primitive.

    Returns a small handle exposing the captured POST traffic and the existing
    record holder so each test can configure the GET response.
    """
    holder: dict[str, _FakeRecord | None] = {"existing": None}
    posts: list[dict[str, Any]] = []

    async def _fake_first(_nb: object, _path: str, *, query: dict[str, Any]) -> Any:
        del query
        return holder["existing"]

    async def _fake_create(_nb: object, _path: str, payload: dict[str, Any], **_kw: Any) -> Any:
        posts.append(dict(payload))
        return _FakeRecord(payload, record_id=99)

    monkeypatch.setattr(netbox_rest, "rest_first_async", _fake_first)
    monkeypatch.setattr(netbox_rest, "rest_create_async", _fake_create)

    return {"holder": holder, "posts": posts}


@pytest.mark.asyncio
async def test_missing_record_emits_post_and_returns_created(patch_rest: dict[str, Any]) -> None:
    result = await upsert_cluster_type(object(), mode="cluster", tag_refs=_PROXBOX_TAG)

    assert isinstance(result, UpsertResult)
    assert result.status == "created"
    assert len(patch_rest["posts"]) == 1
    posted = patch_rest["posts"][0]
    assert posted["slug"] == "cluster"
    assert posted["name"] == "Cluster"


@pytest.mark.asyncio
async def test_unchanged_payload_emits_no_patch(patch_rest: dict[str, Any]) -> None:
    existing_payload = _existing_cluster_type_payload()
    existing = _FakeRecord(existing_payload, record_id=42)
    patch_rest["holder"]["existing"] = existing
    result = await upsert_cluster_type(object(), mode="cluster", tag_refs=_PROXBOX_TAG)

    assert result.status == "unchanged"
    assert existing.save_calls == 0
    assert patch_rest["posts"] == []


@pytest.mark.asyncio
async def test_real_diff_emits_single_patch_and_returns_updated(
    patch_rest: dict[str, Any],
) -> None:
    existing_payload = _existing_cluster_type_payload(name="Old Name")
    existing = _FakeRecord(existing_payload, record_id=42)
    patch_rest["holder"]["existing"] = existing

    result = await upsert_cluster_type(object(), mode="cluster", tag_refs=_PROXBOX_TAG)

    assert result.status == "updated"
    assert existing.save_calls == 1
    assert patch_rest["posts"] == []
    # The diff must include the changed name field.
    assert existing.patched_fields.get("name") == "Cluster"


@pytest.mark.asyncio
async def test_fk_diff_compares_id_only(patch_rest: dict[str, Any]) -> None:
    """FK comparison must pin to ``record.id`` / ``.pk``, never nested dicts.

    Existing record stores ``type`` as a nested dict (``{"id": 7, ...}``); the
    desired payload sends an int. After normalization both should compare as
    equal, producing an ``unchanged`` outcome.
    """
    existing_payload: dict[str, Any] = {
        "name": "pve-cluster",
        "type": {"id": 7, "name": "Cluster", "slug": "cluster", "url": "..."},
        "description": "Proxmox cluster cluster.",
        "tags": _PROXBOX_TAG,
    }
    existing = _FakeRecord(existing_payload, record_id=42)
    patch_rest["holder"]["existing"] = existing

    result = await upsert_cluster(
        object(),
        cluster_name="pve-cluster",
        cluster_type_id=7,
        mode="cluster",
        tag_refs=_PROXBOX_TAG,
    )

    assert result.status == "unchanged"
    assert existing.save_calls == 0


@pytest.mark.asyncio
async def test_status_enum_values_are_stable_strings() -> None:
    """Guard against accidental rename of the status enum.

    Sync orchestration, SSE summaries, and idempotency tests all string-match
    on these exact values. Changing them is a wire-breaking change.
    """
    valid = {"created", "updated", "unchanged"}
    # Build a result instance for each value to confirm the Literal accepts
    # them at runtime (Literal isn't enforced, but instantiation must work).
    for status in valid:
        result = ReconcileResult(record=_FakeRecord({}), status=status)  # type: ignore[arg-type]
        assert result.status == status
        upsert_result = UpsertResult(record=_FakeRecord({}), status=status)  # type: ignore[arg-type]
        assert upsert_result.status == status


@pytest.mark.asyncio
async def test_back_compat_rest_reconcile_async_still_returns_bare_record(
    patch_rest: dict[str, Any],
) -> None:
    """The legacy bare-record API must keep working after the refactor."""
    from proxbox_api.netbox_rest import rest_reconcile_async

    result = await rest_reconcile_async(
        object(),
        "/api/virtualization/cluster-types/",
        lookup={"slug": "cluster"},
        payload={
            "name": "Cluster",
            "slug": "cluster",
            "description": "Proxmox cluster mode",
            "tags": _PROXBOX_TAG,
        },
        schema=NetBoxClusterTypeSyncState,
        current_normalizer=lambda record: {
            "name": record.get("name"),
            "slug": record.get("slug"),
            "description": record.get("description"),
            "tags": record.get("tags"),
        },
    )

    # No ReconcileResult wrapper — must be the bare record.
    assert not isinstance(result, ReconcileResult)
    assert hasattr(result, "serialize")


@pytest.mark.asyncio
async def test_with_status_wrapper_returns_reconcile_result(
    patch_rest: dict[str, Any],
) -> None:
    """The new public sibling must return a ``ReconcileResult``."""
    result = await rest_reconcile_async_with_status(
        object(),
        "/api/virtualization/cluster-types/",
        lookup={"slug": "cluster"},
        payload={
            "name": "Cluster",
            "slug": "cluster",
            "description": "Proxmox cluster mode",
            "tags": _PROXBOX_TAG,
        },
        schema=NetBoxClusterTypeSyncState,
        current_normalizer=lambda record: {
            "name": record.get("name"),
            "slug": record.get("slug"),
            "description": record.get("description"),
            "tags": record.get("tags"),
        },
    )

    assert isinstance(result, ReconcileResult)
    assert result.status in {"created", "updated", "unchanged"}


@pytest.mark.asyncio
async def test_inventory_policy_preserves_prebound_supporting_objects(
    patch_rest, monkeypatch, tmp_path
):
    import json

    policy = tmp_path / "inventory-policy.json"
    policy.write_text(json.dumps({"read_only_paths": ["/api/virtualization/cluster-types/"]}))
    monkeypatch.setenv("PROXBOX_INVENTORY_POLICY_FILE", str(policy))
    existing = _FakeRecord(_existing_cluster_type_payload(name="Operator name"), record_id=42)
    patch_rest["holder"]["existing"] = existing

    result = await upsert_cluster_type(object(), mode="cluster", tag_refs=_PROXBOX_TAG)

    assert result.status == "unchanged"
    assert result.record.serialize()["name"] == "Operator name"
    assert result.record.id == 42
    assert existing.patched_fields == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation",
    [
        "create",
        "patch",
        "bulk_create",
        "bulk_patch",
        "delete_one",
        "delete_many",
        "record_save",
        "record_delete",
    ],
)
async def test_inventory_policy_denies_direct_mutations(operation, monkeypatch, tmp_path):
    import json

    from proxbox_api.exception import ProxboxException

    policy = tmp_path / "inventory-policy.json"
    policy.write_text(json.dumps({"read_only_paths": ["/api/dcim/sites/"]}))
    monkeypatch.setenv("PROXBOX_INVENTORY_POLICY_FILE", str(policy))
    api = object()
    path = "/api/dcim/sites/"
    row = netbox_rest.RestRecord(api, path, {"id": 42, "name": "Operator site"})
    row.name = "Source site"
    calls = {
        "create": lambda: netbox_rest.rest_create_async(api, path, {"name": "Source site"}),
        "patch": lambda: netbox_rest.rest_patch_async(api, path, 42, {"name": "Source site"}),
        "bulk_create": lambda: netbox_rest.rest_bulk_create_async(
            api, path, [{"name": "Source site"}]
        ),
        "bulk_patch": lambda: netbox_rest.rest_bulk_patch_async(
            api, path, [{"id": 42, "name": "Source site"}]
        ),
        "delete_one": lambda: netbox_rest.rest_bulk_delete_async(api, path, [42]),
        "delete_many": lambda: netbox_rest.rest_bulk_delete_async(api, path, [42, 43]),
        "record_save": row.save,
        "record_delete": row.delete,
    }
    with pytest.raises(ProxboxException, match="Inventory ownership policy"):
        await calls[operation]()


@pytest.fixture
def inventory_api():
    import json
    from types import SimpleNamespace

    from netbox_sdk.client import ApiResponse

    rows = [{"id": 42, "name": "Operator name", "slug": "existing"}]

    async def request(method, path, *, query=None, payload=None, **kwargs):
        if method == "GET":
            selected = [
                row
                for row in rows
                if all(
                    row.get(key) == value
                    for key, value in (query or {}).items()
                    if key not in {"limit", "offset"}
                )
            ]
            body = {"count": len(selected), "next": None, "results": selected}
        elif method == "POST":
            row = {"id": 43, **payload}
            rows.append(row)
            body = row
        else:
            raise AssertionError(f"Unexpected mutation {method} {path}")
        return ApiResponse(status=200, text=json.dumps(body))

    return SimpleNamespace(client=SimpleNamespace(request=request)), rows


@pytest.mark.asyncio
async def test_read_only_bulk_preserves_existing_and_reports_missing_models(
    inventory_api, monkeypatch, tmp_path
):
    import json

    api, rows = inventory_api
    policy = tmp_path / "inventory-policy.json"
    policy.write_text(json.dumps({"read_only_paths": ["/api/virtualization/cluster-types/"]}))
    monkeypatch.setenv("PROXBOX_INVENTORY_POLICY_FILE", str(policy))
    result = await netbox_rest.rest_bulk_reconcile_async(
        api,
        "/api/virtualization/cluster-types/",
        payloads=[{"name": "Source name", "slug": "existing"}, {"name": "New type", "slug": "new"}],
        lookup_fields=["slug"],
        schema=dict,
        current_normalizer=lambda row: row,
    )
    assert (result.created, result.updated, result.unchanged, result.failed) == (0, 0, 1, 1)
    assert [row.serialize() for row in result.records] == rows
    assert rows == [{"id": 42, "name": "Operator name", "slug": "existing"}]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path", ["/api/virtualization/virtual-machines/", "/api/dcim/site-groups/"]
)
async def test_inventory_policy_leaves_other_resources_writable(
    inventory_api, monkeypatch, tmp_path, path
):
    import json

    api, rows = inventory_api
    policy = tmp_path / "inventory-policy.json"
    policy.write_text(json.dumps({"read_only_paths": ["/api/dcim/sites/"]}))
    monkeypatch.setenv("PROXBOX_INVENTORY_POLICY_FILE", str(policy))
    created = await netbox_rest.rest_create_async(api, path, {"name": "New inventory"})
    assert created.serialize() == {"id": 43, "name": "New inventory"}
    assert rows[-1] == created.serialize()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "contents",
    [
        "{",
        "[]",
        "{}",
        '{"read_only_paths": null}',
        '{"read_only_paths": ["/api/dcim/sites/?all=true"]}',
        '{"read_only_paths": ["/api/dcim/../sites/"]}',
        None,
    ],
)
async def test_invalid_inventory_policy_never_falls_back_to_writable(
    inventory_api, monkeypatch, tmp_path, contents
):
    from proxbox_api.exception import ProxboxException

    api, rows = inventory_api
    policy = tmp_path / "inventory-policy.json"
    if contents is not None:
        policy.write_text(contents)
    monkeypatch.setenv("PROXBOX_INVENTORY_POLICY_FILE", str(policy))
    with pytest.raises(ProxboxException, match="Inventory ownership policy"):
        await netbox_rest.rest_create_async(api, "/api/dcim/sites/", {"name": "New site"})
    assert rows == [{"id": 42, "name": "Operator name", "slug": "existing"}]
