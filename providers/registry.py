"""Provider registry + in-memory health tracking (spec Phases 9, 10).

The registry is the ordered catalogue of provider adapters with their
declared metadata (name, category, capabilities, cost model, privacy
properties, version). The HealthTracker keeps rolling per-provider
outcome counts in memory only — the anonymous scan is storage-free by
design, so health is never written to the database.

Mode: LEAKGUARD_PROVIDERS=mock swaps every real adapter for the canned
MockProvider (tests, demos). The mode and the mock status are always
visible in /api/providers/health so mock data can never silently
pretend to be real.
"""

import os
import threading
from collections import deque

from .base import HttpClient
from .ddg_discovery import DuckDuckGoDiscoveryProvider
from .domain_intel import DomainIntelProvider
from .hibp_passwords import HibpPasswordsProvider
from .mock import (MockDiscoveryProvider, MockDomainIntelProvider,
                  MockProvider, MockUsernameProvider)
from .username_platforms import UsernamePlatformsProvider
from .xposedornot import XposedOrNotProvider

# Stage S6 politeness: the public discovery sources get a shared
# 1-second minimum interval between calls (per provider).
DISCOVERY_MIN_INTERVAL = 1.0

RECENT_WINDOW = 50


class HealthTracker:
    """Rolling per-provider outcomes: totals, last latency, last error
    kind, and a bounded window of recent results for degraded checks."""

    def __init__(self):
        self._lock = threading.Lock()
        self._stats = {}

    def _entry(self, name):
        return self._stats.setdefault(name, {
            "successes": 0,
            "failures": 0,
            "last_latency_ms": None,
            "last_error_kind": None,
            "recent": deque(maxlen=RECENT_WINDOW),
        })

    def record(self, name, ok, latency_ms, error_kind=None):
        with self._lock:
            entry = self._entry(name)
            if ok:
                entry["successes"] += 1
            else:
                entry["failures"] += 1
                entry["last_error_kind"] = error_kind
            entry["last_latency_ms"] = latency_ms
            entry["recent"].append(bool(ok))

    def snapshot(self, name):
        with self._lock:
            entry = self._stats.get(name)
            if entry is None:
                return {"successes": 0, "failures": 0,
                        "last_latency_ms": None, "last_error_kind": None,
                        "recent_failure": False}
            return {
                "successes": entry["successes"],
                "failures": entry["failures"],
                "last_latency_ms": entry["last_latency_ms"],
                "last_error_kind": entry["last_error_kind"],
                "recent_failure": not all(entry["recent"]),
            }


class Registry:
    """Ordered provider catalogue for one mode ("real" | "mock")."""

    def __init__(self, mode="real"):
        self.mode = mode
        self.health = HealthTracker()
        if mode == "mock":
            self.providers = [
                MockProvider(health=self.health),
                MockDiscoveryProvider(health=self.health),
                MockUsernameProvider(health=self.health),
                MockDomainIntelProvider(health=self.health),
            ]
        else:
            self.providers = [
                XposedOrNotProvider(
                    health=self.health,
                    client=HttpClient(XposedOrNotProvider.info.name,
                                      health=self.health)),
                HibpPasswordsProvider(
                    health=self.health,
                    client=HttpClient(HibpPasswordsProvider.info.name,
                                      health=self.health)),
                DuckDuckGoDiscoveryProvider(
                    health=self.health,
                    client=HttpClient(
                        DuckDuckGoDiscoveryProvider.info.name,
                        health=self.health,
                        min_interval=DISCOVERY_MIN_INTERVAL)),
                UsernamePlatformsProvider(
                    health=self.health,
                    client=HttpClient(
                        UsernamePlatformsProvider.info.name,
                        health=self.health,
                        min_interval=DISCOVERY_MIN_INTERVAL)),
                DomainIntelProvider(
                    health=self.health,
                    client=HttpClient(
                        DomainIntelProvider.info.name,
                        health=self.health,
                        min_interval=DISCOVERY_MIN_INTERVAL)),
            ]

    def get_providers(self, capability):
        """Providers declaring `capability`, in registry order."""
        return [p for p in self.providers
                if capability in p.info.capabilities]

    def summary(self):
        return {
            "mode": self.mode,
            "providers": [p.health_summary() for p in self.providers],
        }


def _env_mode():
    return ("mock" if os.environ.get("LEAKGUARD_PROVIDERS", "")
            .strip().lower() == "mock" else "real")


_registry = None
_registry_lock = threading.Lock()


def get_registry():
    """Process-wide registry, built lazily from the environment."""
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = Registry(_env_mode())
    return _registry


def reset_registry(instance=None):
    """Drop the cached registry (tests install their own or force a
    rebuild from the current environment)."""
    global _registry
    with _registry_lock:
        _registry = instance
