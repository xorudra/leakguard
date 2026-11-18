"""Worker idle polling (owner order 2026-11-18).

The scan and remediation workers used to re-query every 2
seconds with an empty queue, which kept the Neon compute awake
around the clock and burned the free monthly compute allowance
by mid-month. These tests pin the replacement contract without
a database: an undisturbed idle wait lasts the full (patched)
interval, wake() and stop both end it at once, and the shipped
interval stays far beyond Neon's scale-to-zero window.
"""

import time
import unittest

from remediation import worker as remediation_worker
from scanning import worker as scan_worker


class _IdleWaitCase:
    """Shared cases, mixed into the two concrete classes below
    (a plain mixin, so discovery does not collect it on its own
    with MOD unset)."""
    MOD = None

    def setUp(self):
        self._saved_idle = self.MOD.IDLE_POLL_SECONDS
        self.MOD._stop.clear()
        self.MOD._wake.clear()

    def tearDown(self):
        self.MOD.IDLE_POLL_SECONDS = self._saved_idle
        self.MOD._stop.clear()
        self.MOD._wake.clear()

    def test_wake_returns_promptly(self):
        self.MOD.IDLE_POLL_SECONDS = 60.0
        self.MOD.wake()
        started = time.monotonic()
        self.MOD._idle_wait()
        self.assertLess(time.monotonic() - started, 5.0)

    def test_stop_returns_promptly(self):
        self.MOD.IDLE_POLL_SECONDS = 60.0
        self.MOD._stop.set()
        started = time.monotonic()
        self.MOD._idle_wait()
        self.assertLess(time.monotonic() - started, 5.0)

    def test_waits_full_idle_when_undisturbed(self):
        self.MOD.IDLE_POLL_SECONDS = 0.4
        started = time.monotonic()
        self.MOD._idle_wait()
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.35)
        self.assertLess(elapsed, 5.0)

    def test_idle_poll_is_long(self):
        # The shipped value must stay far beyond Neon's
        # scale-to-zero window, or the burn comes back.
        self.assertGreaterEqual(self._saved_idle, 1800.0)


class TestScanWorkerIdle(_IdleWaitCase, unittest.TestCase):
    MOD = scan_worker


class TestRemediationWorkerIdle(_IdleWaitCase, unittest.TestCase):
    MOD = remediation_worker


if __name__ == "__main__":
    unittest.main()
