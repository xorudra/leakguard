# LeakGuard 🛡️

**Your data got leaked. Find it. Remove it.**

A free, GUI-based tool (web UI, no CLI) that:

1. **Scans** your email against real breach databases — [XposedOrNot](https://xposedornot.com) (free, no key) — and checks a password against [Have I Been Pwned Pwned Passwords](https://haveibeenpwned.com/Passwords) using k-anonymity, so the password itself is never sent or stored.
2. **Scores** your exposure 0–100 and lists exactly which breaches contain your email and what types of data were exposed.
3. **Agent Mode (zero-token)** — the agent does the boring work with plain scripts, no AI: it builds a personal removal plan from per-broker **playbooks** (16 hand-mapped, 40 covered), then **probes each broker's live opt-out page** — reading its real form fields, building the pre-filled payload, and honestly reporting blockers (CAPTCHA, login, bot protection, JavaScript walls) instead of pretending. Submission only happens behind your explicit per-broker confirmation, and only to the broker's own host (SSRF-guarded). If a form can't be understood, an optional fallback may ask **your own free gateway** (FreeLLMAPI — `LEAKGUARD_FREE_LANE_URL/KEY/MODEL`) to classify the fields. That fallback is off by default, costs no Claude/Muse tokens ever, and silently stays off if your gateway is down or rate-limited.
4. **Removes (manual path)** — a Removal Centre with the same 40 brokers: opt-out links, a tracking board (saved in your browser), and a one-click **erasure-request letter generator** citing India's DPDP Act §12, GDPR Art. 17, or CCPA.
5. **Google** — builds the searches a stranger would run on you and links Google's own *Results about you* removal tool.

> **Field reality (measured, Oct 2026):** probing the top brokers from a server IP, most big people-search sites answer scripts with 403 (bot protection) or require email/phone verification — Spokeo's opt-out page was reachable and its form readable. The probe exists precisely so you see this per broker instead of a fake "removed ✓". A headless-browser layer (Playwright) for the JavaScript/bot-walled sites is the planned v2.1; CAPTCHA, email-confirmation and phone-verification steps will always need the user — by design.

### The honest limits
- **Can be removed:** data brokers, people-search sites, Google search results — they must answer a legal erasure request.
- **Cannot be removed:** a breach dump already copied to Telegram, dark-web forums or torrents. No tool can delete every copy — anyone promising that is lying. The defence there is changing compromised passwords and using 2FA.

## Run it

Zero dependencies — Python 3 standard library only.

```bash
python3 app.py
# open http://localhost:8000
```

Environment: `PORT` (default 8000), `HOST` (default 0.0.0.0).

## Deploy (Render free tier)

`render.yaml` is included: create a Web Service from this repo, or use Render Blueprint. Start command is `python3 app.py` — no build step, no requirements to install.

## Privacy

- No accounts, no database, no server-side storage of scans.
- Broker removal progress is stored only in the visitor's browser (`localStorage`).
- Passwords are checked via k-anonymity (only the first 5 chars of the SHA-1 hash leave the server) and are never logged.

## Roadmap

- **v1:** breach + password scan, exposure score, Removal Centre (40 brokers), letter generator, Google tools.
- **v2 (this):** Agent Mode in the same GUI — playbooks, personal removal plan, live form probe with blocker detection, guarded submission, optional free-lane field classification. One LeakGuard, one repo.
- **v2.1:** headless-browser (Playwright) runner for JavaScript/bot-walled opt-out pages; email-confirmation tracking.
- **v3:** 150+ brokers; recurring monitoring — re-scan monthly, alert when an email appears in a *new* breach or a broker re-lists you.

## License

MIT
