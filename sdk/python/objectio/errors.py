"""Errors raised by the ObjectIO management client."""

from __future__ import annotations


class ObjectIOError(Exception):
    """Base for everything this package raises."""


class APIError(ObjectIOError):
    """A non-2xx response from the management API."""

    def __init__(self, status_code: int, method: str, path: str, message: str = ""):
        self.status_code = status_code
        self.method = method
        self.path = path
        #: The server's body. The management API answers in plain text for
        #: denials and JSON for handler errors, so this is whatever it sent.
        self.message = message
        super().__init__(f"{method} {path}: {status_code}: {message}")

    @property
    def not_found(self) -> bool:
        return self.status_code == 404

    @property
    def forbidden(self) -> bool:
        """Authenticated but not permitted. The usual cause here is a scoped
        credential — those are refused on the management API."""
        return self.status_code == 403

    @property
    def already_exists(self) -> bool:
        """The server refusing to create something that is already there.

        409 is the clean answer, but the tenant and bucket creates predate
        that and still return 400 with the reason in the message — so accept
        either rather than making a caller's idempotency depend on which
        endpoint it happened to call.
        """
        if self.status_code == 409:
            return True
        if self.status_code != 400:
            return False
        lowered = self.message.lower()
        return "already exists" in lowered or "alreadyexists" in lowered
