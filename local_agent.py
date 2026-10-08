#!/usr/bin/env python3
"""
LeakGuard Local Runner — the one-click removal run, on YOUR device.

Why this exists: some brokers (BeenVerified, Whitepages, Nuwber…)
block datacenter/server IPs outright — Cloudflare challenges every
request that comes from a hosting network, no matter how good the
code is. From a home connection those same pages usually open
normally. This runner uses the exact same zero-token engine
(agent.py) on your machine, under your IP.

Usage (Python 3, no dependencies):
    python3 local_agent.py
        -> asks your details once, probes every broker, shows the
           plan, and — after you type YES once — does the whole run:
           submits every fillable opt-out form, writes every email
           broker's erasure letter as a ready-to-send .eml file,
           then walks you through ONLY the brokers that demand a
           human (CAPTCHA / login / phone check), opening each
           opt-out page in your browser one at a time.
    python3 local_agent.py --broker Spokeo
        -> run just one broker.
    python3 local_agent.py --no-open
        -> skip the guided browser walk; the human-only brokers
           are listed in the report instead.
    python3 local_agent.py --probe-only
        -> the old read-only behaviour: probe and print, send
           nothing.

What is sent, and where: form submissions go ONLY to the brokers'
own opt-out forms (the same SSRF-guarded submit the server uses).
Nothing is ever sent to LeakGuard or anywhere else; your details
never leave this machine except inside the removal requests
themselves. Email letters are written as .eml files (double-click
one and it opens in your mail app, addressed and written, ready to
send) because brokers answer the person, not a service.

Every outcome is recorded in leakguard-run-report.json (and a
readable .txt) in the folder you run this from: submitted forms
with their HTTP status, letters written, and the human-only
brokers with the exact reason each one needs you.

LOCAL-ONLY (Phase 178 decision, docs/DOC_REVIEW.md): this file is
a user-run device tool. The LeakGuard server never imports or
executes it; the app's only contact with it is serving its bytes
at /local_agent.py so users can download it (added 2026-10-08 with
the one-click run). Its only project import is the `agent` engine,
shared with the server. Deleting it would remove the walled-broker
path, not any server behaviour.
"""

import argparse
import json
import sys
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent as agent_engine

LETTER_SUBJECT = "Request for erasure of my personal data"


def letter_text(broker_name, profile):
    """The erasure letter for one email broker — the same request
    the server-side generator writes (DPDP Act 2023 §12, GDPR
    Art. 17, CCPA/CPRA as applicable), composed locally so the
    runner needs no server package."""
    name = (profile.get("full_name") or "").strip() or "[Your full name]"
    email = (profile.get("email") or "").strip() or "[Your email]"
    city = (profile.get("city") or "").strip()
    lines = [
        "To: Data Protection / Privacy Team, " + (broker_name or "your company"),
        "",
        "Subject: " + LETTER_SUBJECT,
        "",
        "Hello,",
        "",
        "I am writing to request the erasure of my personal data and",
        "to opt out of the sale or sharing of my personal information,",
        "under the DPDP Act 2023 (Section 12), GDPR Article 17, and",
        "the CCPA/CPRA, as applicable.",
        "",
        "My details, so you can find my listing:",
        "  Full name: " + name,
        "  Email: " + email,
    ]
    if city:
        lines.append("  City / country: " + city)
    lines += [
        "",
        "Please remove every listing and record you hold about me,",
        "confirm the removal by replying to this email, and do not",
        "sell or share my information again.",
        "",
        "Thank you,",
        name,
        email,
    ]
    return "\n".join(lines)


def _slug(name):
    keep = [c if c.isalnum() else "-" for c in (name or "broker").lower()]
    return "".join(keep).strip("-") or "broker"


def run(profile, deep=False, do_open=True, assume_yes=False,
        only_broker=None, probe_only=False, out_dir=None,
        probe_fn=None, submit_fn=None, open_fn=None,
        input_fn=None, print_fn=print):
    """The whole run. Returns the per-broker result list; also
    writes the report files unless out_dir is None. All IO seams
    are injectable so the run is testable offline."""
    input_fn = input_fn or input
    open_fn = open_fn or webbrowser.open
    submit_fn = submit_fn or agent_engine.submit_form
    out = Path(out_dir) if out_dir is not None else Path.cwd()
    plan = agent_engine.build_plan(profile)
    if only_broker:
        plan = [p for p in plan
                if p["broker"].lower() == only_broker.lower()]
        if not plan:
            print_fn(f"Unknown broker: {only_broker}")
            return []

    def probe(item):
        if probe_fn is not None:
            return probe_fn(item["broker"], profile)
        if deep:
            return agent_engine.probe_with_browser_fallback(
                item["broker"], profile)
        return agent_engine.probe_broker(item["broker"], profile)

    # Probe everything first (read-only), then sort the brokers
    # into the three honest piles.
    results = []
    for item in plan:
        pr = probe(item) or {}
        entry = {"broker": item["broker"],
                 "optout_url": item["optout_url"],
                 "contact_email": item.get("contact_email") or "",
                 "blockers": pr.get("blockers", []),
                 "probe_status": pr.get("status")}
        forms = pr.get("forms") or []
        if forms and pr.get("payload_preview"):
            entry["route"] = "form"
            entry["_form"] = forms[-1]
            entry["_payload"] = pr["payload_preview"]
        elif entry["contact_email"]:
            entry["route"] = "email"
        else:
            entry["route"] = "human"
        results.append(entry)

    forms_n = sum(1 for r in results if r["route"] == "form")
    mail_n = sum(1 for r in results if r["route"] == "email")
    human_n = sum(1 for r in results if r["route"] == "human")
    print_fn(f"\nPlan: {forms_n} forms to submit automatically, "
             f"{mail_n} erasure letters to write, "
             f"{human_n} brokers that need you in person.")

    if probe_only:
        for r in results:
            print_fn(f"  {r['broker']}: route={r['route']} "
                     f"probe_status={r['probe_status']}")
        return results

    if not assume_yes:
        answer = input_fn(
            "Type YES to start the automatic run: ").strip().lower()
        if answer != "yes":
            print_fn("Aborted — nothing was submitted or written.")
            for r in results:
                r["outcome"] = "aborted_by_user"
            return results

    # Automatic part 1: submit the fillable forms.
    for r in results:
        if r["route"] != "form":
            continue
        form = r.pop("_form")
        payload = r.pop("_payload")
        try:
            res = submit_fn(form.get("action", ""), form.get("method", "post"),
                            payload) or {}
            r["outcome"] = "submitted"
            r["submit_status"] = res.get("status")
        except Exception as exc:  # one bad broker never stops the run
            r["outcome"] = "submit_failed"
            r["error"] = type(exc).__name__
        print_fn(f"  {r['broker']}: {r['outcome']}"
                 + (f" (HTTP {r['submit_status']})"
                    if r.get("submit_status") else ""))

    # Automatic part 2: write every email broker's letter as a
    # ready-to-send .eml file.
    letters_dir = out / "leakguard-letters"
    for r in results:
        if r["route"] != "email":
            continue
        letters_dir.mkdir(parents=True, exist_ok=True)
        path = letters_dir / (_slug(r["broker"]) + ".eml")
        eml = ("To: " + r["contact_email"] + "\n"
               "From: " + (profile.get("email") or "") + "\n"
               "Subject: " + LETTER_SUBJECT + "\n"
               "Content-Type: text/plain; charset=utf-8\n\n"
               + letter_text(r["broker"], profile))
        path.write_text(eml, encoding="utf-8")
        r["outcome"] = "letter_written"
        r["letter_file"] = str(path)
        print_fn(f"  {r['broker']}: letter written -> {path.name}")

    # The human-only brokers: open each page in the user's own
    # browser, one at a time — this is the part no honest tool can
    # do for them (CAPTCHA, login, phone verification).
    human = [r for r in results if r["route"] == "human"]
    for idx, r in enumerate(human):
        r["outcome"] = "needs_you"
        reason = "; ".join(r["blockers"]) or "no automatic route"
        print_fn(f"  {r['broker']}: needs you — {reason}")
        print_fn(f"    {r['optout_url']}")
        if do_open:
            open_fn(r["optout_url"])
            if idx < len(human) - 1:
                input_fn("    Finish that one, then press Enter "
                         "for the next… ")

    # Report: machine-readable + readable, in the working folder.
    # The probe internals (form payloads carry the user's own
    # details) never belong in a report file — strip them first.
    for r in results:
        r.pop("_form", None)
        r.pop("_payload", None)
    stamp = datetime.now(timezone.utc).isoformat()
    report = {"generated_at": stamp, "results": results}
    (out / "leakguard-run-report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8")
    lines = ["LeakGuard local run — " + stamp, ""]
    for r in results:
        lines.append(f"{r['broker']}: {r.get('outcome', r['route'])}")
    (out / "leakguard-run-report.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8")
    done_n = sum(1 for r in results if r.get("outcome") == "submitted")
    print_fn(f"\nDone: {done_n} submitted, {mail_n} letters in "
             f"./leakguard-letters (open each and press Send), "
             f"{human_n} need you in person. "
             f"Full report: leakguard-run-report.txt")
    return results


def main():
    ap = argparse.ArgumentParser(
        description="LeakGuard local runner (zero-token, one-click run)")
    ap.add_argument("--broker", help="run only this broker")
    ap.add_argument("--deep", action="store_true",
                    help="use relay + browser layers too")
    ap.add_argument("--no-open", action="store_true",
                    help="don't open the human-only pages in a browser")
    ap.add_argument("--yes", action="store_true",
                    help="start the automatic run without typing YES")
    ap.add_argument("--probe-only", action="store_true",
                    help="probe and print only; submit and write nothing")
    args = ap.parse_args()

    print("LeakGuard Local Runner — zero tokens, your IP, "
          "your data stays on this machine.\n")
    profile = {
        "full_name": input("Your full name: ").strip(),
        "email": input("Your email: ").strip(),
        "phone": input("Phone (optional): ").strip(),
        "city": input("City / country (optional): ").strip(),
    }
    results = run(profile, deep=args.deep, do_open=not args.no_open,
                  assume_yes=args.yes, only_broker=args.broker,
                  probe_only=args.probe_only)
    if args.broker and not results:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
