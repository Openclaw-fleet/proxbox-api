"""Regression: adopt a pre-existing unassigned IP by host, regardless of mask.

NetBox's `address` filter is exact-CIDR, so `1.2.3.4/24` does not match an
existing `1.2.3.4/32`. With ENFORCE_GLOBAL_UNIQUE the duplicate create then
fails and the address silently never attaches. The adoption lookup must query
by host so an operator-seeded `/32` is adopted onto the interface (and its mask
normalized), while still never reassigning a foreign-owned address.
"""

from types import SimpleNamespace

import pytest

from proxbox_api.exception import ProxboxException
from proxbox_api.services.sync import ip_ownership


def _mocks(monkeypatch, existing):
    captured = {"list_query": None, "reconcile": []}

    async def fake_list(nb, path, *, query=None, authoritative=False):
        assert authoritative
        captured["list_query"] = query
        return existing

    async def fake_reconcile(nb, path, *, lookup, payload, **kw):
        captured["reconcile"].append({"lookup": lookup, "payload": payload})
        return SimpleNamespace(id=lookup.get("id", 99))

    monkeypatch.setattr(ip_ownership, "rest_list_async", fake_list)
    monkeypatch.setattr(ip_ownership, "rest_reconcile_async", fake_reconcile)
    return captured


async def test_adopts_existing_unassigned_slash32_as_slash24(monkeypatch):
    from datetime import datetime, timezone

    existing = [
        {
            "id": 1,
            "address": "141.94.139.106/32",
            "assigned_object_type": None,
            "assigned_object_id": None,
        }
    ]
    cap = _mocks(monkeypatch, existing)

    result = await ip_ownership._reconcile_interface_ip(
        object(),
        ip_addr="141.94.139.106/24",
        interface_id=5,
        tag_refs=[],
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
        dns_name=None,
        interface_name="vmbr0",
        assigned_object_type="dcim.interface",
        interface_lookup_field="interface_id",
    )

    # Lookup is by host (mask stripped) so the /32 is found.
    assert cap["list_query"]["address"] == "141.94.139.106"
    # Adopted by id (not a create-by-address), assigned to this interface, mask -> /24.
    assert len(cap["reconcile"]) == 1
    assert cap["reconcile"][0]["lookup"] == {"id": 1}
    payload = cap["reconcile"][0]["payload"]
    assert payload["address"] == "141.94.139.106/24"
    assert payload["assigned_object_id"] == 5
    assert result == 1


async def test_never_adopts_foreign_owned_address(monkeypatch):
    from datetime import datetime, timezone

    # Same host, but already owned by a different interface -> must NOT be reused.
    existing = [
        {
            "id": 7,
            "address": "141.94.139.106/32",
            "assigned_object_type": "dcim.interface",
            "assigned_object_id": 999,
        }
    ]
    cap = _mocks(monkeypatch, existing)

    with pytest.raises(ProxboxException, match="ownership"):
        await ip_ownership._reconcile_interface_ip(
            object(),
            ip_addr="141.94.139.106/24",
            interface_id=5,
            tag_refs=[],
            now=datetime(2026, 1, 1, tzinfo=timezone.utc),
            dns_name=None,
            interface_name="vmbr0",
            assigned_object_type="dcim.interface",
            interface_lookup_field="interface_id",
        )

    assert cap["reconcile"] == []


@pytest.mark.parametrize("failure", ["lookup", "duplicate", "malformed", "foreign_type"])
async def test_uncertain_ip_ownership_performs_no_writes(monkeypatch, failure):
    from datetime import datetime, timezone

    own = {
        "id": 8,
        "address": "192.0.2.31/24",
        "assigned_object_type": "virtualization.vminterface",
        "assigned_object_id": 5,
    }
    existing = [own]
    if failure == "duplicate":
        existing.append({**own, "id": 9, "assigned_object_id": 71})
    elif failure == "malformed":
        existing = [{"id": 8, "address": "192.0.2.31/24"}]
    elif failure == "foreign_type":
        existing = [{**own, "assigned_object_type": "dcim.interface"}]
    cap = _mocks(monkeypatch, existing)
    if failure == "lookup":

        async def unavailable(*args, **kwargs):
            raise TimeoutError("synthetic lookup failure")

        monkeypatch.setattr(ip_ownership, "rest_list_async", unavailable)

    with pytest.raises(ProxboxException, match="ownership"):
        await ip_ownership._reconcile_interface_ip(
            object(),
            ip_addr="192.0.2.31/24",
            interface_id=5,
            tag_refs=[],
            now=datetime(2026, 1, 1, tzinfo=timezone.utc),
            dns_name=None,
            interface_name="net0",
        )
    assert cap["reconcile"] == []
