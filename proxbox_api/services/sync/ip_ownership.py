"""Ownership-safe IP address reconciliation helpers."""

from __future__ import annotations

from datetime import datetime
from ipaddress import ip_interface

from proxbox_api.exception import ProxboxException
from proxbox_api.logger import logger
from proxbox_api.netbox_rest import (
    clear_rest_get_cache_for_path,
    rest_list_async,
    rest_reconcile_async,
)
from proxbox_api.proxmox_to_netbox.models import NetBoxIpAddressSyncState


def _ip_address_current_normalizer(record: dict) -> dict:
    """Shared normalizer for ip-address reconcile drift comparison."""
    return {
        "address": record.get("address"),
        "assigned_object_type": record.get("assigned_object_type"),
        "assigned_object_id": record.get("assigned_object_id"),
        "status": record.get("status"),
        "dns_name": record.get("dns_name"),
        "tags": record.get("tags"),
    }


def _record_field(record: object, key: str, default: object = None) -> object:
    """Read a field from a NetBox record that may be a dict or a RestRecord."""
    if isinstance(record, dict):
        return record.get(key, default)
    serialize = getattr(record, "serialize", None)
    if callable(serialize):
        try:
            return serialize().get(key, default)
        except Exception:
            pass
    return getattr(record, key, default)


def _relation_id_or_none(value: object) -> int | None:
    if isinstance(value, dict):
        value = value.get("id")
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _host_address(ip_addr: str) -> str:
    """Return the host portion of a CIDR (drops the mask).

    NetBox's ``address`` filter is exact-CIDR, so querying ``1.2.3.4/24`` will
    NOT match an existing ``1.2.3.4/32`` record. Looking up adoptable records by
    host (mask-agnostic) lets us adopt a pre-existing address regardless of its
    stored mask — e.g. an operator-seeded ``/32`` — instead of failing to create
    a duplicate under ENFORCE_GLOBAL_UNIQUE.
    """
    return ip_addr.split("/", 1)[0]


def _select_ip_owner(
    existing: list,
    *,
    ip_addr: str,
    assigned_object_type: str,
    interface_id: int,
) -> object | None:
    """Resolve one globally unique address; uncertainty never permits a write."""
    if not existing:
        return None
    if len(existing) != 1:
        raise ProxboxException(message=f"IP ownership is ambiguous for {ip_addr}")
    record = existing[0]
    try:
        if ip_interface(str(_record_field(record, "address"))).ip != ip_interface(ip_addr).ip:
            raise ValueError("address filter did not match")
    except ValueError as exc:
        raise ProxboxException(message=f"IP ownership lookup is invalid for {ip_addr}") from exc
    missing = object()
    assigned_type = _record_field(record, "assigned_object_type", missing)
    raw_id = _record_field(record, "assigned_object_id", missing)
    assigned_id = _relation_id_or_none(raw_id)
    own = assigned_type == assigned_object_type and assigned_id == interface_id
    free = assigned_type in (None, "") and raw_id is None
    if not (own or free) or _relation_id_or_none(_record_field(record, "id")) is None:
        raise ProxboxException(message=f"IP ownership conflict for {ip_addr}")
    return record


async def _preflight_vm_ip_payloads(nb: object, payloads: list[dict]) -> None:
    """Validate the complete batch before its first write, across object types.

    Bulk sync never changes assignment or masks. A free or differently masked
    existing address must therefore use targeted sync, not a duplicate create.
    """
    clear_rest_get_cache_for_path(nb, "/api/ipam/ip-addresses/")
    records = await rest_list_async(nb, "/api/ipam/ip-addresses/")
    by_host: dict[str, list] = {}
    for record in records:
        host = str(ip_interface(str(_record_field(record, "address"))).ip)
        by_host.setdefault(host, []).append(record)
    desired: dict[str, tuple[int, str]] = {}
    for payload in payloads:
        address = str(payload["address"])
        host = str(ip_interface(address).ip)
        interface_id = int(payload["assigned_object_id"])
        claim = (interface_id, str(ip_interface(address)))
        if payload.get("assigned_object_type") != "virtualization.vminterface":
            raise ProxboxException(message=f"IP ownership target is invalid for {address}")
        if host in desired and desired[host] != claim:
            raise ProxboxException(message=f"IP ownership has conflicting batch claims for {host}")
        desired[host] = claim
        target = _select_ip_owner(
            by_host.get(host, []),
            ip_addr=address,
            assigned_object_type="virtualization.vminterface",
            interface_id=interface_id,
        )
        if target is not None and (
            _record_field(target, "assigned_object_type") != "virtualization.vminterface"
            or _relation_id_or_none(_record_field(target, "assigned_object_id")) != interface_id
            or str(ip_interface(str(_record_field(target, "address")))) != claim[1]
        ):
            raise ProxboxException(
                message=f"IP ownership for {address} requires targeted sync before bulk sync",
            )


async def _reconcile_interface_ip(
    nb,
    *,
    ip_addr: str,
    interface_id: int,
    tag_refs: list[dict],
    now: datetime,
    dns_name: str | None,
    interface_name: str,
    assigned_object_type: str = "virtualization.vminterface",
    interface_lookup_field: str = "vminterface_id",
) -> int | None:
    """Reconcile a single interface IP without stealing another object's address.

    Ownership is resolved before any write:

    * reuse a record already assigned to this interface,
    * adopt a record that is currently unassigned, or
    * create a new record scoped to this interface.

    A foreign, duplicate, malformed, or unreadable address fails closed rather
    than creating a second record. This fork enforces global host uniqueness.
    """
    interface_id = int(interface_id)
    payload = {
        "address": ip_addr,
        "assigned_object_type": assigned_object_type,
        "assigned_object_id": interface_id,
        "status": "active",
        "dns_name": dns_name or "",
        "tags": tag_refs,
    }

    try:
        clear_rest_get_cache_for_path(nb, "/api/ipam/ip-addresses/")
        existing = await rest_list_async(
            nb,
            "/api/ipam/ip-addresses/",
            query={"address": _host_address(ip_addr), "limit": 50},
        )
    except Exception as list_exc:
        raise ProxboxException(
            message=f"IP ownership lookup failed for {ip_addr}",
            http_status_code=502,
        ) from list_exc

    target = _select_ip_owner(
        existing,
        ip_addr=ip_addr,
        assigned_object_type=assigned_object_type,
        interface_id=interface_id,
    )
    try:
        record_id = (
            _relation_id_or_none(_record_field(target, "id")) if target is not None else None
        )
        if record_id is not None:
            # Reconcile the specific record we own/adopt by id. For an owned
            # record the assignment already matches; for an unassigned record
            # the assignment fields are patched, adopting it onto this interface.
            reconciled = await rest_reconcile_async(
                nb,
                "/api/ipam/ip-addresses/",
                lookup={"id": record_id},
                payload=payload,
                schema=NetBoxIpAddressSyncState,
                current_normalizer=_ip_address_current_normalizer,
                strict_lookup=True,
            )
        else:
            # No reusable record exists. Create one scoped to this interface; the
            # strict, interface-scoped lookup means the reconcile fallback can
            # never match a foreign address and reassign it.
            reconciled = await rest_reconcile_async(
                nb,
                "/api/ipam/ip-addresses/",
                lookup={"address": ip_addr, interface_lookup_field: interface_id},
                payload=payload,
                schema=NetBoxIpAddressSyncState,
                current_normalizer=_ip_address_current_normalizer,
                strict_lookup=True,
            )
    except Exception as ip_exc:
        logger.warning(
            "Failed to sync IP %s for interface %s: %s",
            ip_addr,
            interface_name,
            ip_exc,
        )
        return None

    return _relation_id_or_none(_record_field(reconciled, "id"))
