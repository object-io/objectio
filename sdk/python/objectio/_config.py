"""Stored cluster configuration and the OIDC providers kept in it.

Configuration is a key/value store in meta (``/_admin/config/<key>``) whose
values are JSON. It is system-admin territory, with one exception: a tenant
admin may read and write its own tenant's OIDC provider
(:func:`~objectio.tenant_oidc_provider_name`) and the one bound to its
tenant, which is how a tenant brings its own identity provider.
"""

from __future__ import annotations

import json
from typing import Any

from .models import (
    OIDC_CONFIG_PREFIX,
    REDACTED_SECRET,
    ConfigEntry,
    OIDCProvider,
    _only_known,
)


class ConfigMixin:
    # -- generic config ---------------------------------------------------

    def list_config(self, prefix: str = "") -> list[ConfigEntry]:
        """Config entries whose key starts with ``prefix`` (all of them by
        default). A tenant admin sees only its own OIDC provider entries."""
        query = {"prefix": prefix} if prefix else None
        out = self._request("GET", "/_admin/config", query=query) or []
        return [_only_known(ConfigEntry, e) for e in out]

    def get_config(self, key: str) -> ConfigEntry:
        """One entry. Raises :class:`APIError` (``not_found``) if unset."""
        return _only_known(ConfigEntry, self._request("GET", f"/_admin/config/{key}"))

    def set_config(self, key: str, value: Any) -> ConfigEntry:
        """Store ``value`` (anything JSON-serialisable) under ``key``,
        replacing what was there. The answer carries ``key``, ``value`` and
        the new ``version``."""
        out = self._request(
            "PUT",
            f"/_admin/config/{key}",
            raw_body=json.dumps(value).encode("utf-8"),
        )
        return _only_known(ConfigEntry, out or {"key": key, "value": value})

    def delete_config(self, key: str) -> None:
        self._request("DELETE", f"/_admin/config/{key}")

    # -- OIDC identity providers ------------------------------------------

    def list_oidc_providers(self) -> list[OIDCProvider]:
        """Stored OIDC providers. Secrets come back redacted.

        The gateway's own ``--oidc-*`` provider is command-line
        configuration, not stored, and is not listed.
        """
        return [
            OIDCProvider.from_config(e.key[len(OIDC_CONFIG_PREFIX):], e.value)
            for e in self.list_config(OIDC_CONFIG_PREFIX)
            if e.key.startswith(OIDC_CONFIG_PREFIX)
        ]

    def get_oidc_provider(self, name: str) -> OIDCProvider:
        entry = self.get_config(OIDC_CONFIG_PREFIX + name)
        return OIDCProvider.from_config(name, entry.value)

    def put_oidc_provider(self, name: str, cfg: OIDCProvider | dict) -> OIDCProvider:
        """Create or replace a provider.

        The stored document is replaced whole, and reads return the client
        secret as ``"********"`` — so writing back what :meth:`get_oidc_provider`
        returned would store the asterisks as the secret. That is refused
        here: set ``client_secret`` to the real value (or ``None``/``""``
        for a public client) before writing.

        A tenant admin may write only its own tenant's provider
        (:func:`~objectio.tenant_oidc_provider_name`); doing so also binds
        the tenant to it.
        """
        doc = cfg.to_config() if isinstance(cfg, OIDCProvider) else dict(cfg)
        if doc.get("client_secret") == REDACTED_SECRET:
            raise ValueError(
                "client_secret is the redacted placeholder from a read; "
                "writing it back would replace the real secret with asterisks"
            )
        entry = self.set_config(OIDC_CONFIG_PREFIX + name, doc)
        return OIDCProvider.from_config(name, entry.value)

    def delete_oidc_provider(self, name: str) -> None:
        self.delete_config(OIDC_CONFIG_PREFIX + name)
