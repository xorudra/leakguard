# LeakGuard 🛡️

**Your data got leaked. Find it. Remove it.**

A free, GUI-based tool (web UI, no CLI) that:

1. **Scans** your email against real breach databases — [XposedOrNot](https://xposedornot.com) (free, no key) — and checks a password against [Have I Been Pwned Pwned Passwords](https://haveibeenpwned.com/Passwords) using k-anonymity, so the password itself is never sent or stored.
2. **Scores** your exposure 0–100 and lists exactly which breaches contain your email and what types of data were exposed.
3. **Agent Mode (zero-token)** — the agent does the boring work with plain scripts, no AI: it builds a personal removal plan from per-broker **playbooks** (16 hand-mapped, 40 covered), then **probes each broker's live opt-out page** — reading its real form fields, building the pre-filled payload, and honestly reporting blockers (CAPTCHA, login, bot protection, JavaScript walls) instead of pretending. Submission only happens behind your explicit per-broker confirmation, and only to the broker's own host (SSRF-guarded). If a form can't be understood, an optional fallback may ask **your own free gateway** (FreeLLMAPI — `LEAKGUARD_FREE_LANE_URL/KEY/MODEL`) to classify the fields. That fallback is off by default, costs no Claude/Muse tokens ever, and silently stays off if your gateway is down or rate-limited.
4. **Removes (manual path)** — a Removal Centre with the same 40 brokers: opt-out links, a tracking board (saved in your browser), and a one-click **erasure-request letter generator** citing India's DPDP Act §12, GDPR Art. 17, or CCPA.
5. **Google** — builds the searches a stranger would run on you and links Google's own *Results about you* removal tool.

> **Field reality (measured, Oct 2026, updated for v2.1):** ThatsThem's opt-out moved to `/optout` (fixed) and Acxiom's official form is the `isapps.acxiom.com` page (fixed, HTTP 200). With the **browser probe** (Playwright + real Chromium, `browser_probe.py`), Spokeo's opt-out form renders fully — fields `url` + `email` — and its CAPTCHA-at-submit is detected and reported. BeenVerified / Whitepages still refuse **this dev server's datacenter network** in both HTTP and browser modes (403 / connection failures): that's IP reputation, not a code bug — Agent Mode is designed to also run on the user's own machine/IP (like a local app), where those walls are far lower. Nuwber's whole domain was unreachable from this network during testing. CAPTCHA, email-confirmation and phone-verification steps will always need the user — by design.
>
> **Browser layer setup (optional):** `pip install -r requirements-optional.txt` and have any Chromium/Chrome installed. If your network's proxy can't be used by Chromium directly, run `python3 proxy_relay.py` (a local no-auth CONNECT relay to your env proxy) and set `LEAKGUARD_BROWSER_PROXY=http://127.0.0.1:8899`. Set `LEAKGUARD_NO_BROWSER=1` to disable the layer.
>
> **v2.2 — three more layers, all measured live:**
> - **Relay-reader probe:** if a broker 403s this server, the deep probe retries through a public relay reader on a different network (with backoff — the free relay is intermittent). This **fixed Whitepages**: real page + listing-search forms + pre-filled payload, where direct access is 403.
> - **Local Runner (`local_agent.py`):** for sites that block *every* datacenter route (BeenVerified's Cloudflare challenges scripts, relays and headless browsers alike; Nuwber refused this network entirely) — run the same zero-token engine **on your own device**, under your home IP, and finish the human steps in your own browser. `python3 local_agent.py` — no dependencies, nothing is submitted automatically.
> - **Free-lane fallback verified end-to-end:** with the user's FreeLLMAPI gateway configured (`LEAKGUARD_FREE_LANE_MODEL=openai/gpt-oss-20b` recommended — a Groq-served model), unknown form fields are classified correctly (measured: `eaddr→email`, `subscriber_nm→full_name`, junk→ignore). Two gotchas found by testing: reasoning models need a ≥900-token budget or they truncate before answering (the engine handles this and extracts the JSON from reasoning text), and Gemini models currently can't serve as the lane if the gateway's Google key is disabled — use a Groq/OpenRouter-served model instead.

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
- **v2.1 (this):** headless-browser (Playwright) probe layer for JavaScript/bot-walled opt-out pages, fixed ThatsThem + Acxiom opt-out URLs, local proxy relay for locked-down networks.
- **v2.2:** browser form *filling* (not just probing) for rendered forms; email-confirmation tracking.
- **v3:** 150+ brokers; recurring monitoring — re-scan monthly, alert when an email appears in a *new* breach or a broker re-lists you.

## License

MIT
