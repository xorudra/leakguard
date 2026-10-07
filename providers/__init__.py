"""External provider adapters (Stage S4 — spec Phases 8, 9, 10, 110, 118).

Every outside data source LeakGuard talks to sits behind this package:
a normalized adapter contract (base.py), a registry with metadata and
in-memory health tracking (registry.py), and one module per provider.
The anonymous scan stays storage-free — health lives in memory only,
nothing per-scan is ever written to the database.
"""
