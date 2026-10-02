"""Named IAM policies, groups and roles.

Each belongs to a tenant or to system scope. A tenant admin acts in its own
tenant implicitly (naming another is refused); the system admin names the
tenant with ``tenant=`` and otherwise acts in system scope. Policy and role
names are unique per tenant; groups are addressed by id.
"""

from __future__ import annotations

from typing import Any

from .models import Group, Policy, Role, _only_known


def _target(user_id: str, group_id: str, role_name: str) -> dict[str, str]:
    """The one principal an attachment names.

    The server takes the first of ``user_id``, ``group_id``, ``role_name``
    that is set and silently ignores the rest, so passing two is refused
    here rather than attaching to whichever happens to win.
    """
    given = {
        k: v
        for k, v in (("user_id", user_id), ("group_id", group_id), ("role_name", role_name))
        if v
    }
    if len(given) != 1:
        raise ValueError("exactly one of user_id, group_id or role_name is required")
    return given


class IAMMixin:
    # -- policies ---------------------------------------------------------

    def list_policies(self, tenant: str = "") -> list[Policy]:
        """Policies the caller can use.

        The system admin sees every policy, or one tenant's when ``tenant``
        is named. A tenant admin sees its tenant's plus the shared system
        catalogue.
        """
        out = self._request("GET", "/_admin/policies", query=self._tenant_query(tenant)) or {}
        return [_only_known(Policy, p) for p in out.get("policies", [])]

    def create_policy(
        self,
        name: str,
        document: Any,
        *,
        tenant: str = "",
        shared: bool = False,
    ) -> Policy:
        """Create a named policy from an IAM policy document (a ``dict`` or
        its JSON text). The server validates it as the authorizer will read
        it, so a malformed document fails here, not at request time.

        ``shared`` publishes a *system* policy to every tenant's admins to
        attach (not edit); only the system admin may set it, and only with
        no ``tenant``.
        """
        body: dict[str, Any] = {"name": name, "policy": document}
        if tenant:
            body["tenant"] = tenant
        if shared:
            body["shared"] = True
        return _only_known(Policy, self._request("POST", "/_admin/policies", body=body))

    def get_policy(self, name: str, tenant: str = "") -> Policy:
        """A policy. Looked up in the tenant first; a tenant admin may also
        read a shared system policy of that name."""
        out = self._request(
            "GET", f"/_admin/policies/{name}", query=self._tenant_query(tenant)
        )
        return _only_known(Policy, out)

    def update_policy(self, name: str, document: Any, tenant: str = "") -> Policy:
        """Replace a policy's document in place — it never stops applying to
        what it is attached to, and those principals pick up the change at
        once."""
        out = self._request(
            "PUT",
            f"/_admin/policies/{name}",
            query=self._tenant_query(tenant),
            body={"policy": document},
        )
        return _only_known(Policy, out)

    def delete_policy(self, name: str, tenant: str = "") -> None:
        self._request(
            "DELETE", f"/_admin/policies/{name}", query=self._tenant_query(tenant)
        )

    # -- attachments ------------------------------------------------------

    def attach_policy(
        self,
        policy_name: str,
        *,
        user_id: str = "",
        group_id: str = "",
        role_name: str = "",
        tenant: str = "",
    ) -> None:
        """Attach a policy to exactly one user, group or role.

        The principal's tenant decides which policies it can take: its
        tenant's own, a shared system policy, or (for the system admin) any
        system policy. A user's or group's tenant is looked up; a role is
        named within ``tenant`` (default: the caller's own).
        """
        body: dict[str, Any] = {"policy_name": policy_name, **_target(user_id, group_id, role_name)}
        if tenant:
            body["tenant"] = tenant
        self._request("POST", "/_admin/policies/attach", body=body)

    def detach_policy(
        self,
        policy_name: str,
        *,
        user_id: str = "",
        group_id: str = "",
        role_name: str = "",
        tenant: str = "",
    ) -> None:
        """Undo :meth:`attach_policy`; same arguments."""
        body: dict[str, Any] = {"policy_name": policy_name, **_target(user_id, group_id, role_name)}
        if tenant:
            body["tenant"] = tenant
        self._request("POST", "/_admin/policies/detach", body=body)

    def list_attached_policies(
        self,
        *,
        user_id: str = "",
        group_id: str = "",
        role_name: str = "",
        tenant: str = "",
    ) -> list[str]:
        """Names of the policies attached directly to one user, group or role
        (not those it inherits through a group). Names are relative to the
        principal's tenant."""
        query = _target(user_id, group_id, role_name)
        if tenant:
            query["tenant"] = tenant
        out = self._request("GET", "/_admin/policies/attached", query=query) or {}
        return list(out.get("policy_names", []))

    # -- groups -----------------------------------------------------------

    def list_groups(self, tenant: str = "") -> list[Group]:
        out = self._request("GET", "/_admin/groups", query=self._tenant_query(tenant)) or {}
        return [_only_known(Group, g) for g in out.get("groups", [])]

    def create_group(self, name: str, tenant: str = "") -> Group:
        body: dict[str, Any] = {"group_name": name}
        if tenant:
            body["tenant"] = tenant
        return _only_known(Group, self._request("POST", "/_admin/groups", body=body))

    def get_group(self, group_id: str) -> Group:
        return _only_known(Group, self._request("GET", f"/_admin/groups/{group_id}"))

    def delete_group(self, group_id: str) -> None:
        self._request("DELETE", f"/_admin/groups/{group_id}")

    def add_group_member(self, group_id: str, user_id: str) -> None:
        """Add a user to a group. The user must be in the group's tenant."""
        self._request(
            "POST", f"/_admin/groups/{group_id}/members", body={"user_id": user_id}
        )

    def remove_group_member(self, group_id: str, user_id: str) -> None:
        self._request("DELETE", f"/_admin/groups/{group_id}/members/{user_id}")

    # -- roles ------------------------------------------------------------

    def list_roles(self, tenant: str = "") -> list[Role]:
        out = self._request("GET", "/_admin/roles", query=self._tenant_query(tenant)) or {}
        return [_only_known(Role, r) for r in out.get("roles", [])]

    def create_role(
        self,
        name: str,
        trust_policy: Any,
        *,
        description: str = "",
        max_session_seconds: int = 0,
        tenant: str = "",
    ) -> Role:
        """Create a role that STS can hand out.

        ``trust_policy`` (a ``dict`` or JSON text) decides who may assume
        it: its conditions see the web identity token's claims. Which
        identity providers may vouch at all depends on the role's scope —
        a system role only the operator's, a tenant's role only that
        tenant's own provider. Attach policies to the role to give its
        sessions permissions; it has none of its own.
        """
        body: dict[str, Any] = {"name": name, "trust_policy": trust_policy}
        if description:
            body["description"] = description
        if max_session_seconds:
            body["max_session_seconds"] = max_session_seconds
        if tenant:
            body["tenant"] = tenant
        return _only_known(Role, self._request("POST", "/_admin/roles", body=body))

    def get_role(self, name: str, tenant: str = "") -> Role:
        """A role, with the policies attached to it."""
        out = self._request("GET", f"/_admin/roles/{name}", query=self._tenant_query(tenant))
        return _only_known(Role, out)

    def update_role(
        self,
        name: str,
        *,
        trust_policy: Any = None,
        description: str | None = None,
        max_session_seconds: int | None = None,
        tenant: str = "",
    ) -> Role:
        """Change a role. Fields left as ``None`` are not touched."""
        body: dict[str, Any] = {}
        if trust_policy is not None:
            body["trust_policy"] = trust_policy
        if description is not None:
            body["description"] = description
        if max_session_seconds is not None:
            body["max_session_seconds"] = max_session_seconds
        out = self._request(
            "PUT", f"/_admin/roles/{name}", query=self._tenant_query(tenant), body=body
        )
        return _only_known(Role, out)

    def delete_role(self, name: str, tenant: str = "") -> None:
        self._request(
            "DELETE", f"/_admin/roles/{name}", query=self._tenant_query(tenant)
        )
