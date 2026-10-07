"""Per-request context (spec Phase 89 — request IDs).

A request_id is minted for every HTTP request (uuid4 hex), carried in a
contextvar so any layer can read it without threading it through calls,
echoed to the client in the X-Request-Id response header, and embedded in
structured error bodies and log lines so a user-visible failure can be
matched to exactly one server log entry.
"""

import contextvars
import uuid

_request_id_var = contextvars.ContextVar("leakguard_request_id", default=None)


def new_request_id():
    """Mint a fresh request id (uuid4, hex form)."""
    return uuid.uuid4().hex


def set_request_id(request_id):
    """Bind request_id to the current context; returns a reset token."""
    return _request_id_var.set(request_id)


def get_request_id():
    """The request id bound to this context, or None outside a request."""
    return _request_id_var.get()


def reset_request_id(token):
    _request_id_var.reset(token)
