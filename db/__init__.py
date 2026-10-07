"""Database layer (Stage S2 — spec Phases 2 & 73).

PostgreSQL is the durable store (Neon free tier in production). The app
reads the connection string ONLY from the DATABASE_URL environment
variable. If it is unset, the whole DB layer stays dormant: every
pre-S2 feature keeps working and /api/health reports "db": "disabled".

This package deliberately imports nothing third-party at module level —
psycopg is imported lazily inside functions, so the app boots even in an
environment where the driver was never installed, as long as no database
is configured.
"""
