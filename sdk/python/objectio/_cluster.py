"""Cluster operations: nodes, rebalancing, pools, KMS, Iceberg warehouses
and the Prometheus proxy.

The node, topology, usage, pool and metrics shapes are returned as plain
``dict``/``list`` exactly as the server sends them: they are large, read
mostly by people and dashboards, and change faster than this client would
want to track field by field. KMS keys and warehouses are small and typed.
"""

from __future__ import annotations

from typing import Any

from .models import KMSKey, Warehouse, _only_known


class ClusterMixin:
    # -- cluster ----------------------------------------------------------

    def cluster_info(self) -> dict:
        """This gateway's configured topology and its distance to every
        active OSD."""
        return self._request("GET", "/_admin/cluster-info")

    def list_nodes(self) -> Any:
        """Every OSD, including ones marked out or draining. System admin."""
        return self._request("GET", "/_admin/nodes")

    def topology(self) -> dict:
        """The failure-domain tree: region → zone → datacenter → rack → host
        → OSDs."""
        return self._request("GET", "/_admin/topology")

    def usage(self) -> dict:
        """Capacity and consumption. The system admin gets the cluster and
        every tenant; a tenant admin only its own tenant's row and buckets.
        Served from a background refresh, so up to one poll interval old
        (``updated_at`` says how old); a 503 means it is not gathered yet."""
        return self._request("GET", "/_admin/usage")

    def drain_status(self) -> dict:
        """Progress of every OSD being drained (``{"drains": [...]}``)."""
        return self._request("GET", "/_admin/drain-status")

    def rebalance_status(self) -> dict:
        return self._request("GET", "/_admin/rebalance-status")

    def pause_rebalance(self) -> dict:
        """Pause the rebalancer cluster-wide. Persisted through Raft, so it
        survives a leader failover or restart until resumed."""
        return self._request("POST", "/_admin/rebalance/pause")

    def resume_rebalance(self) -> dict:
        return self._request("POST", "/_admin/rebalance/resume")

    def set_osd_admin_state(self, node_id: str, state: str) -> Any:
        """Mark an OSD ``"in"``, ``"out"`` or ``"draining"``.

        ``node_id`` is the 32-hex-character id :meth:`list_nodes` reports.
        """
        return self._request(
            "PUT", f"/_admin/osds/{node_id}/admin-state", body={"state": state}
        )

    # -- pools ------------------------------------------------------------

    def list_pools(self) -> list[dict]:
        return self._request("GET", "/_admin/pools") or []

    def create_pool(self, name: str, **fields: Any) -> dict:
        """Create a storage pool. ``fields`` by wire name: ``ec_k``,
        ``ec_m``, ``replication_count``, ``failure_domain``, ``osd_tags``,
        ``pg_count``, ``quota_bytes``, ``tier``, ``description`` …

        Unset fields take the *server's* defaults, which are not the
        cluster's: ``ec_k`` 3, ``ec_m`` 2, ``failure_domain`` ``"rack"`` —
        name what you mean.
        """
        return self._request("POST", "/_admin/pools", body={"name": name, **fields})

    def get_pool(self, name: str) -> dict:
        return self._request("GET", f"/_admin/pools/{name}")

    def update_pool(self, name: str, **fields: Any) -> dict:
        """Change some of a pool's settings.

        The server's ``PUT`` replaces the whole pool, resetting anything
        left out to the create defaults (``ec_k`` 3, ``enabled`` true …).
        So this reads the pool, applies ``fields`` on top and writes the
        result back.
        """
        current = self.get_pool(name) or {}
        return self._request(
            "PUT", f"/_admin/pools/{name}", body={**current, **fields, "name": name}
        )

    def delete_pool(self, name: str) -> None:
        self._request("DELETE", f"/_admin/pools/{name}")

    def list_placement_groups(
        self, pool: str, *, start_after: int = 0, max_results: int = 1000
    ) -> dict:
        """One page of a pool's placement groups: ``{"pgs": [...],
        "next_pg_id": n}``. Pass ``next_pg_id`` back as ``start_after`` for
        the next page; it is 0 after the last."""
        query = {"max": str(max_results)}
        if start_after:
            query["start_after"] = str(start_after)
        return self._request(
            "GET", f"/_admin/pools/{pool}/placement-groups", query=query
        )

    # -- KMS --------------------------------------------------------------

    def kms_status(self) -> dict:
        """``{"enabled", "backend", "master_key_configured"}``. ``backend``
        is ``"local"``, ``"external"`` (Vault / AWS KMS — keys are managed
        there, not here) or ``"disabled"``."""
        return self._request("GET", "/_admin/kms/status")

    def list_kms_keys(self) -> list[KMSKey]:
        """Every local KMS key, following pagination."""
        keys: list[KMSKey] = []
        token = ""
        while True:
            query = {"max_results": "100"}
            if token:
                query["page_token"] = token
            out = self._request("GET", "/_admin/kms/keys", query=query) or {}
            keys.extend(_only_known(KMSKey, k) for k in out.get("keys", []))
            token = out.get("next_page_token") or ""
            if not token:
                return keys

    def create_kms_key(self, key_id: str = "", description: str = "") -> KMSKey:
        """Create a local KMS key; the server picks the id if ``key_id`` is
        empty. The key material never leaves the gateway unwrapped."""
        out = self._request(
            "POST",
            "/_admin/kms/keys",
            body={"key_id": key_id, "description": description},
        )
        return _only_known(KMSKey, out)

    def get_kms_key(self, key_id: str) -> KMSKey:
        return _only_known(KMSKey, self._request("GET", f"/_admin/kms/keys/{key_id}"))

    def delete_kms_key(self, key_id: str) -> None:
        """Delete a key. Objects encrypted under it become unreadable."""
        self._request("DELETE", f"/_admin/kms/keys/{key_id}")

    # -- Iceberg warehouses -----------------------------------------------

    def list_warehouses(self) -> list[Warehouse]:
        """The caller's tenant's warehouses; every one for the system admin."""
        out = self._request("GET", "/_admin/warehouses") or {}
        return [_only_known(Warehouse, w) for w in out.get("warehouses", [])]

    def create_warehouse(
        self,
        name: str,
        *,
        tenant: str = "",
        properties: dict[str, str] | None = None,
    ) -> Warehouse:
        """Create an Iceberg warehouse. Meta provisions its backing bucket
        (``iceberg-<name>``); Iceberg REST clients then pass
        ``?warehouse=<name>``."""
        body: dict[str, Any] = {"name": name}
        if tenant:
            body["tenant"] = tenant
        if properties:
            body["properties"] = dict(properties)
        return _only_known(Warehouse, self._request("POST", "/_admin/warehouses", body=body))

    def delete_warehouse(self, name: str) -> None:
        self._request("DELETE", f"/_admin/warehouses/{name}")

    # -- metrics ----------------------------------------------------------

    def metrics_query(self, promql: str, time: Any = None) -> dict:
        """A Prometheus instant query through the gateway, answered in
        Prometheus's own response shape. ``time`` is RFC 3339 or a unix
        timestamp; omitted means now.

        Needs the gateway's ``--prometheus-url``; without it this raises
        :class:`APIError` 503 (``prometheus_not_configured``).
        """
        query = {"query": promql}
        if time is not None and time != "":
            query["time"] = str(time)
        return self._request("GET", "/_admin/metrics/query", query=query)

    def metrics_query_range(self, promql: str, start: Any, end: Any, step: Any) -> dict:
        """A Prometheus range query. ``start``/``end`` as RFC 3339 or unix
        timestamps, ``step`` in seconds. More than 11 000 points is refused
        (400 ``range_too_wide``)."""
        return self._request(
            "GET",
            "/_admin/metrics/query_range",
            query={
                "query": promql,
                "start": str(start),
                "end": str(end),
                "step": str(step),
            },
        )
