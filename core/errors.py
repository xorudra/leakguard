"""Structured API errors (spec Phases 86-87).

Every API error response uses one shape:

    {"error": {"code": <stable machine code>,
               "message": <human message, safe to show users>,
               "request_id": <per-request id, matches X-Request-Id>}}

Success responses are untouched by this contract.
"""

import json


class ApiError(Exception):
    """An error that maps cleanly onto an HTTP response."""

    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = int(status)
        self.code = str(code)
        self.message = str(message)

    def to_body(self, request_id):
        return error_body(self.status, self.code, self.message, request_id)


def error_body(status, code, message, request_id):
    """Build the structured error body dict for an HTTP status."""
    return {
        "error": {
            "code": str(code),
            "message": str(message),
            "request_id": request_id,
        }
    }


def error_json(status, code, message, request_id):
    return json.dumps(error_body(status, code, message, request_id))


# Convenience constructors for the error kinds the API already produces.
# Messages are kept byte-identical to the pre-S1 plain {"error": msg} API.

def not_found(message="Not found"):
    return ApiError(404, "not_found", message)


def invalid_json(message="Invalid JSON"):
    return ApiError(400, "invalid_json", message)


def bad_request(code, message):
    return ApiError(400, code, message)


def internal_error():
    return ApiError(500, "internal_error", "Internal server error")
