#!/usr/bin/env python3
"""Recorded accessibility check (spec Phase 96).

Loads the main pages in headless Chromium and asserts, per page,
the DOM-level accessibility invariants the static tests
(tests/test_accessibility.py) cannot see because they only read
the shipped source:

  * the document has a non-empty <title> and a lang attribute;
  * the landmarks exist in the rendered DOM (header, nav, main,
    footer);
  * no VISIBLE interactive element is unlabeled — every input,
    select, textarea, button and link must have an accessible
    name (visible text, an associated <label>, an aria-label, an
    aria-labelledby target, or a title);
  * heading order never skips a level among visible headings;
  * the polite live regions that announce scan completion and
    notifications are present (home page).

Target: the LIVE staging site by default
(https://leakguard-staging.onrender.com — it runs the current
production code), reached through the repo's proxy_relay.py on
127.0.0.1:8899: headless Chromium on this VM cannot open pages
directly (see browser_probe.py), and the relay strips the egress
proxy's auth for it. If the relay is not already listening, this
script starts it and stops it again at the end. Pass --base to
check another origin, --no-relay to skip relay management.

NOTE: this check runs against a DEPLOYED site — run it after a
deploy lands the Phase 96 changes; it proves nothing about code
that exists only in the working tree (that is the static tests'
job).

Exit code 0 = every page passed.

    python3 tools/a11y_check.py
"""

import argparse
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

PAGES = ("/", "/privacy", "/terms", "/support", "/trust", "/reset")
RELAY_PORT = 8899

MEASURE_JS = """() => {
  const visible = (el) => {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 || r.height > 0 || el === document.activeElement;
  };
  const nameOf = (el) => {
    const aria = el.getAttribute('aria-label');
    if (aria && aria.trim()) return aria.trim();
    const labelledby = el.getAttribute('aria-labelledby');
    if (labelledby) {
      const t = labelledby.split(/\\s+/).map((id) => {
        const n = document.getElementById(id);
        return n ? n.textContent : '';
      }).join(' ').trim();
      if (t) return t;
    }
    if (el.id) {
      const lab = document.querySelector('label[for="' + el.id + '"]');
      if (lab && lab.textContent.trim()) return lab.textContent.trim();
    }
    const wrap = el.closest('label');
    if (wrap && wrap.textContent.trim()) return wrap.textContent.trim();
    if (el.textContent && el.textContent.trim())
      return el.textContent.trim();
    if (el.getAttribute('title')) return el.getAttribute('title');
    if (el.getAttribute('placeholder')) return el.getAttribute('placeholder');
    return '';
  };
  const unlabeled = [];
  document.querySelectorAll(
      'input, select, textarea, button, a[href]').forEach((el) => {
    if (el.getAttribute('type') === 'hidden') return;
    if (!visible(el)) return;
    if (!nameOf(el)) {
      unlabeled.push({
        tag: el.tagName.toLowerCase(),
        id: el.id || '',
        type: el.getAttribute('type') || '',
      });
    }
  });
  const headings = [];
  document.querySelectorAll('h1, h2, h3, h4, h5, h6').forEach((h) => {
    if (visible(h)) headings.push(Number(h.tagName.slice(1)));
  });
  let headingSkip = false;
  for (let i = 1; i < headings.length; i++) {
    if (headings[i] > headings[i - 1] + 1) headingSkip = true;
  }
  const liveIds = ['scanStatus', 'notifList', 'searchExposureList'];
  const live = {};
  liveIds.forEach((id) => {
    const el = document.getElementById(id);
    live[id] = el ? (el.getAttribute('aria-live') || '') : null;
  });
  return {
    title: document.title || '',
    lang: document.documentElement.getAttribute('lang') || '',
    landmarks: {
      header: !!document.querySelector('header'),
      nav: !!document.querySelector('nav'),
      main: !!document.querySelector('main'),
      footer: !!document.querySelector('footer'),
    },
    unlabeledCount: unlabeled.length,
    unlabeled: unlabeled.slice(0, 8),
    headingSkip: headingSkip,
    live: live,
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
            context = browser.new_context(ignore_https_errors=True)
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
                    rows.append((path, status, None, error))
                    failures += 1
                    continue
                problems = []
                if status != 200:
                    problems.append("http %s" % status)
                if not result["title"]:
                    problems.append("empty title")
                if not result["lang"]:
                    problems.append("no lang")
                missing = [k for k, v in result["landmarks"].items()
                           if not v]
                if missing:
                    problems.append("missing landmarks: "
                                    + ", ".join(missing))
                if result["unlabeledCount"]:
                    problems.append("%d unlabeled interactive elements"
                                    % result["unlabeledCount"])
                if result["headingSkip"]:
                    problems.append("heading level skip")
                if path == "/":
                    for rid, val in result["live"].items():
                        if val != "polite":
                            problems.append(
                                "live region %s is %r" % (rid, val))
                if problems:
                    failures += 1
                rows.append((path, status, result, "; ".join(problems)))
            context.close()
            browser.close()
    finally:
        if relay_proc is not None:
            relay_proc.terminate()

    print("Accessibility check — %s" % base)
    print("Criteria per row: HTTP 200, non-empty title, lang set, "
          "header/nav/main/footer landmarks, zero unlabeled visible "
          "interactive elements, no heading-level skip; home page "
          "also: scanStatus/notifList/searchExposureList are "
          "aria-live=polite.")
    print()
    header = ("%-9s %-6s %-9s %-9s %-11s %-9s %s"
              % ("page", "http", "title", "lang", "landmarks",
                 "unlabeled", "result"))
    print(header)
    print("-" * len(header))
    for path, status, result, note in rows:
        if result is None:
            print("%-9s %-6s %-9s %-9s %-11s %-9s %s (%s)"
                  % (path, status, "-", "-", "-", "-", "ERROR", note))
            continue
        lm = sum(1 for v in result["landmarks"].values() if v)
        print("%-9s %-6s %-9s %-9s %-11s %-9d %s"
              % (path, status,
                 "yes" if result["title"] else "NO",
                 result["lang"] or "NO",
                 "%d/4" % lm,
                 result["unlabeledCount"],
                 "PASS" if not note else "FAIL — " + note))
        for el in result["unlabeled"]:
            print("    unlabeled: <%s id=%r type=%r>"
                  % (el["tag"], el["id"], el["type"]))
    print()
    if failures:
        print("RESULT: FAIL — %d of %d pages failed."
              % (failures, len(rows)))
        return 1
    print("RESULT: PASS — all %d pages clean." % len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
