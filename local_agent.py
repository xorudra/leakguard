#!/usr/bin/env python3
"""
LeakGuard Local Runner — run Agent Mode from YOUR OWN device.

Why this exists: some brokers (BeenVerified, Whitepages, Nuwber…) block
datacenter/server IPs outright — Cloudflare challenges every probe that
comes from a hosting network, no matter how good the code is. From a home
connection those same pages usually open normally. This runner uses the
exact same zero-token engine (agent.py) on your machine, under your IP.

Usage (Python 3, no dependencies):
    python3 local_agent.py
        -> interactive: asks your name/email/phone/city, probes every
           broker, prints the plan + live probe results.
    python3 local_agent.py --broker Spokeo
        -> probe just one broker.
    python3 local_agent.py --open
        -> also opens each opt-out page in your default browser so you
           can finish the human steps (CAPTCHA / email confirmation).

Nothing is sent anywhere except the brokers' own opt-out pages (GET
requests to read them). Submissions are never made by this script —
you submit in your browser, where you can see exactly what happens.
"""

import argparse
import json
import sys
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent as agent_engine


def main():
    ap = argparse.ArgumentParser(description="LeakGuard local runner (zero-token)")
    ap.add_argument("--broker", help="probe only this broker")
    ap.add_argument("--open", action="store_true", help="open opt-out pages in your browser")
    ap.add_argument("--deep", action="store_true", help="use relay + browser layers too")
    args = ap.parse_args()

    print("LeakGuard Local Runner — zero tokens, your IP, your data stays here.\n")
    profile = {
        "full_name": input("Your full name: ").strip(),
        "email": input("Your email: ").strip(),
        "phone": input("Phone (optional): ").strip(),
        "city": input("City / country (optional): ").strip(),
    }
    plan = agent_engine.build_plan(profile)
    if args.broker:
        plan = [p for p in plan if p["broker"].lower() == args.broker.lower()]
        if not plan:
            print(f"Unknown broker: {args.broker}")
            return 1
    for item in plan:
        print(f"\n=== {item['broker']} ({item['automation']}) ===")
        print("Opt-out:", item["optout_url"])
        print("Steps:", " -> ".join(item["flow"]))
        if item["needs"]:
            print("Needs from you:", ", ".join(item["needs"]))
        probe = (agent_engine.probe_with_browser_fallback(item["broker"], profile)
                 if args.deep else agent_engine.probe_broker(item["broker"], profile))
        print("Probe: reachable =", probe.get("reachable"), "| status =", probe.get("status"),
              "| forms =", len(probe.get("forms", [])))
        if probe.get("payload_preview"):
            print("Can pre-fill:", probe["payload_preview"])
        for b in probe.get("blockers", []):
            print("  blocker:", b)
        if args.open:
            webbrowser.open(item["optout_url"])
    print("\nDone. Finish the human steps (CAPTCHA, email confirmation, phone")
    print("verification) in your browser, then mark progress in the LeakGuard GUI.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
