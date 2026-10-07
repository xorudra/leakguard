"""Feature flags + emergency controls (spec Phases 120, 122).

A flag is one environment variable; every flag defaults to ON, so a
deployment that sets nothing behaves exactly as before. Setting

    LEAKGUARD_FLAG_<NAME>=off

(in the host's environment — on Render: Environment, then "Save,
rebuild, and deploy") switches that one capability off; the gated
routes answer a structured 503 feature_disabled and the monitoring
scheduler skips its work entirely. That is the emergency lever: if
registration is being abused, or removal runs misbehave, the owner
can stop exactly that capability without taking the site — or the
anonymous Quick Scan — down.

The flags are deliberately coarse (one per user-visible capability,
not per route or per user): an emergency control you have to think
about is one you will not use in an emergency. The state is read
from the environment on every check, and the admin overview reports
the current snapshot, so what the panel shows is what the code will
do.

The anonymous Quick Scan (POST /api/scan) is NEVER gated: it is the
public front door, account-free and storage-free, and no flag here
can close it.
"""

import os

# name -> the environment variable that switches it off.
FLAGS = (
    "registration",         # POST /api/auth/register
    "account_scans",        # POST /api/scans (account full scans)
    "removal_runs",         # POST /api/remediation/run
    "monitoring_scheduler",  # the hourly monitoring scheduler's tick
)

_OFF_VALUES = frozenset(("0", "false", "off", "no"))


def env_key(name):
    """The environment variable backing a flag."""
    if name not in FLAGS:
        raise ValueError("unknown feature flag: %r" % (name,))
    return "LEAKGUARD_FLAG_" + name.upper()


def is_enabled(name):
    """True unless the flag's environment variable holds one of the
    off values ('0', 'false', 'off', 'no', case-insensitive).
    Unset — and any other value — means ON: flags fail open toward
    the product working, never toward a silent outage."""
    raw = os.environ.get(env_key(name))
    if raw is None:
        return True
    return raw.strip().lower() not in _OFF_VALUES


def snapshot():
    """{flag_name: enabled} for every flag — the admin overview's
    view of the emergency controls."""
    return {name: is_enabled(name) for name in FLAGS}
