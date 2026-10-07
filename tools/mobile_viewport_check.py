#!/usr/bin/env python3
"""Recorded mobile-viewport check (spec Phase 97).

Loads the main pages in headless Chromium at two mobile/tablet
viewports and asserts, per page per viewport:

  * no horizontal overflow —
    document.documentElement.scrollWidth <= window.innerWidth + 1;
  * the primary header (header.topbar, which carries the nav) is
    rendered and visible;
  * no VISIBLE element is wider than the viewport (a fixed-width
    element larger than the screen is the usual overflow source).

Target: the LIVE staging site by default
(https://leakguard-staging.onrender.com — it runs the current
production code), reached through the repo's proxy_relay.py on
127.0.0.1:8899: headless Chromium on this VM cannot open pages
directly (see browser_probe.py), and the relay strips the egress
proxy's auth for it. If the relay is not already listening, this
script starts it and stops it again at the end. Pass --base to
check another origin, --no-relay to skip relay management.

Exit code 0 = every page passed at every viewport.

    python3 tools/mobile_viewport_check.py
"""

import argparse
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

PAGES = ("/", "/privacy", "/terms", "/support", "/trust", "/reset")
VIEWPORTS = ((360, 740), (768, 1024))
RELAY_PORT = 8899
MOBILE_UA = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36")

MEASURE_JS = """() => {
  const iw = window.innerWidth;
  const sw = document.documentElement.scrollWidth;
  const header = document.querySelector('header.topbar')
      || document.querySelector('header');
  let headerVisible = false;
  if (header) {
    const r = header.getBoundingClientRect();
    const cs = getComputedStyle(header);
    headerVisible = r.height > 0 && r.width > 0
        && cs.display !== 'none' && cs.visibility !== 'hidden';
  }
  const offenders = [];
  document.querySelectorAll('body *').forEach(el => {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') return;
    const r = el.getBoundingClientRect();
    if (r.height === 0) return;
    if (r.width > iw + 1) {
      let cls = '';
      try { cls = String(el.className || '').slice(0, 48); } catch (e) {}
      offenders.push({
        tag: el.tagName.toLowerCase(),
        id: el.id || '',
        cls: cls,
        width: Math.round(r.width),
      });
    }
  });
  return {
    innerWidth: iw,
    scrollWidth: sw,
    overflow: sw > iw + 1,
    headerVisible: headerVisible,
    offenderCount: offenders.length,
    offenders: offenders.slice(0, 8),
  };
}"""


def _relay_up():
    try:
        with socket.create_connection(("127.0.0.1", RELAY_PORT), timeout=1):
            return True
    except OSError:
        return False


def _find_chrome():
    for candidate in (os.environ.get("LEAKGUARD_CHROME", ""),
                      "/opt/meta-chromium/chrome",
                      "/usr/bin/chromium",
                      "/usr/bin/chromium-browser",
                      "/usr/bin/google-chrome"):
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base", default="https://leakguard-staging.onrender.com",
        help="origin to check (default: live staging)")
    parser.add_argument("--no-relay", action="store_true",
                        help="do not start proxy_relay.py if it is down")
    args = parser.parse_args()
    base = args.base.rstrip("/")

    relay_proc = None
    if not args.no_relay and not _relay_up():
        relay = os.path.join(os.path.dirname(__file__), "..",
                             "proxy_relay.py")
        relay_proc = subprocess.Popen(
            [sys.executable, relay],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(20):
            if _relay_up():
                break
            time.sleep(0.25)

    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        print("BLOCKED: playwright is not installed "
              "(pip install -r requirements-optional.txt)")
        return 2

    rows = []
    failures = 0
    try:
        with sync_playwright() as pw:
            launch = {"headless": True,
                      "args": ["--no-sandbox", "--disable-dev-shm-usage"],
                      "proxy": {"server": "http://127.0.0.1:%d"
                                % RELAY_PORT}}
            chrome = _find_chrome()
            if chrome:
                launch["executable_path"] = chrome
            browser = pw.chromium.launch(**launch)
            for width, height in VIEWPORTS:
                context = browser.new_context(
                    viewport={"width": width, "height": height},
                    user_agent=MOBILE_UA, ignore_https_errors=True,
                    has_touch=True)
                page = context.new_page()
                for path in PAGES:
                    url = base + path
                    status = None
                    result = None
                    error = ""
                    for attempt in (1, 2, 3):  # staging cold-starts
                        try:
                            resp = page.goto(
                                url, timeout=120000,
                                wait_until="domcontentloaded")
                            status = resp.status if resp else None
                            if status in (502, 503) and attempt < 3:
                                # Render's free tier answers 503 with
                                # a "service is starting" page while
                                # the instance wakes — wait and retry
                                # rather than measuring that page.
                                page.wait_for_timeout(8000)
                                continue
                            try:
                                page.wait_for_load_state(
                                    "networkidle", timeout=10000)
                            except Exception:
                                pass
                            page.wait_for_timeout(400)
                            result = page.evaluate(MEASURE_JS)
                            break
                        except Exception as exc:  # noqa: BLE001
                            error = "%s: %s" % (type(exc).__name__,
                                                str(exc)[:120])
                            if attempt == 3:
                                break
                    if result is None:
                        rows.append((path, width, height, status, None,
                                     error))
                        failures += 1
                        continue
                    ok = (status == 200 and not result["overflow"]
                          and result["headerVisible"]
                          and result["offenderCount"] == 0)
                    if not ok:
                        failures += 1
                    rows.append((path, width, height, status, result,
                                 "" if ok else "FAIL"))
                context.close()
            browser.close()
    finally:
        if relay_proc is not None:
            relay_proc.terminate()

    print("Mobile viewport check — %s" % base)
    print("Criteria per row: HTTP 200, scrollWidth <= innerWidth + 1, "
          "header.topbar visible, no visible element wider than the "
          "viewport.")
    print()
    header = ("%-9s %-11s %-6s %-11s %-11s %-7s %-9s %s"
              % ("page", "viewport", "http", "innerWidth",
                 "scrollWidth", "header", "offenders", "result"))
    print(header)
    print("-" * len(header))
    for path, width, height, status, result, note in rows:
        vp = "%dx%d" % (width, height)
        if result is None:
            print("%-9s %-11s %-6s %-11s %-11s %-7s %-9s %s (%s)"
                  % (path, vp, status, "-", "-", "-", "-", "ERROR",
                     note))
            continue
        print("%-9s %-11s %-6s %-11d %-11d %-7s %-9d %s"
              % (path, vp, status, result["innerWidth"],
                 result["scrollWidth"],
                 "yes" if result["headerVisible"] else "NO",
                 result["offenderCount"],
                 "PASS" if not note else note))
        for off in result["offenders"]:
            print("    wide element: <%s id=%r class=%r> width=%dpx"
                  % (off["tag"], off["id"], off["cls"], off["width"]))
    print()
    if failures:
        print("RESULT: FAIL — %d of %d page/viewport rows failed."
              % (failures, len(rows)))
        return 1
    print("RESULT: PASS — all %d page/viewport rows clean." % len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
