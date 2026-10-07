"""Monitoring, notifications and the exposure timeline (Stage S8 —
spec Phases 41–47, 99, 158–160).

Design rules for everything in this package:

* Monitoring is a SCHEDULE over the sources LeakGuard already
  checks. Nothing here widens coverage, and no copy anywhere in
  this package claims the whole internet is watched — the scheduler
  re-runs the same scan jobs the user can run by hand.
* Consent precedes capability, twice over: the scheduler only
  enqueues for users whose 'monitoring' consent is currently
  granted, and email delivery only happens for users whose
  'notifications' consent is currently granted. Everything else is
  recorded in-app only — the ledger never pretends an email was
  sent (see notify.py and migration 0006).
* Change detection is a pure diff between two completed jobs'
  finding sets (diff.py). The completion hook (events.py) runs it
  after every finished scan job, writes the notification ledger,
  and wires reappearance: a verified-removed broker whose listing
  shows up as a new finding flips back to 'reappeared' through
  remediation.verify.mark_reappeared — the Stage S7 hook.
* The timeline (service.py) is a READ MODEL over rows that already
  exist (scan jobs, findings, remediation cases + verification
  checks, notifications are exposed separately). No events table,
  no second source of truth.
* Password reset (accounts/auth.py) rides this package's lane: the
  reset URL travels in the notification payload + the email, and
  nowhere else — never in a log line.
"""
