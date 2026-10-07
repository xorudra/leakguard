"""Remediation engine v2 (Stage S7 — spec Phases 30–39, 153–157,
162, 167).

The signed-in counterpart of the anonymous zero-touch agent: one
command from the user ("Remove my data everywhere", behind the
'automated_remediation' consent) opens one idempotent case per data
broker, and the in-process worker drives each case through probe →
submit / letter / human-handoff, with every action audit-logged.

Honesty rules (spec rules 8–9, owner UX law):
* 'submitted' means a request was sent — NEVER that data is gone.
  Only a verification check with outcome 'gone' may move a case to
  'verified_removed', and the UI uses the word "Removed" only there.
* CAPTCHA and login walls are never bypassed: they become
  needs_human cases with the exact reason and a concrete next step
  for the user (HUMAN_ACTION_REQUIRED).
* Email-channel brokers get a ready-to-send erasure letter — sent by
  the user from their own mailbox, because brokers only accept
  requests from the data subject's own address.
* No identifier values are ever logged; profiles are assembled from
  the vault at run time and exist only in memory.
"""
