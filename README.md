# LeakGuard 🛡️

**Your data got leaked. Find it. Remove it.**

🔗 **Live:** https://leakguard-hh8e.onrender.com

A free web tool (GUI, no CLI) that scans for your leaked personal data and walks you through removing it — built for India's DPDP Act, GDPR and CCPA erasure rights. No accounts, no database, nothing to install.

## What it does

1. **Scan** — enter your email; LeakGuard checks real breach databases ([XposedOrNot](https://xposedornot.com), free, no API key) and tells you which breaches contain you and what data types leaked. You can also check a password against [Have I Been Pwned](https://haveibeenpwned.com/Passwords) — via k-anonymity, so the password itself never leaves your device.
2. **Score** — an exposure score from 0–100 with a clear risk label.
3. **Remove** — a Removal Centre covering 40 data brokers and people-search sites: opt-out links, step-by-step flows, a progress tracker (saved only in your browser), and a one-click erasure-request letter generator citing DPDP Act §12, GDPR Art. 17, or CCPA.
4. **Google** — builds the searches a stranger would run on you, and links Google's own *Results about you* removal tool.

## Agent Mode (zero-token)

The agent does the boring work with plain deterministic scripts — **no AI tokens are burned, ever**.

- **Personal plan** — per-broker playbooks (16 hand-mapped, all 40 covered) turned into a removal plan for your details.
- **Live probe** — for each broker, the agent fetches the real opt-out page and inspects it in layers: direct HTTP → relay reader (a different network, for sites that block servers) → a real headless browser (for JavaScript walls). It reads the actual form fields, pre-fills the payload with your details, and honestly reports blockers — CAPTCHA, login walls, bot protection — instead of pretending they aren't there.
- **Email channels** — some sites (e.g. BeenVerified, Nuwber) wall off their web forms from datacenter networks entirely. For those, LeakGuard surfaces their official opt-out email addresses, which work from anywhere.
- **Guarded submit** — submission happens only behind your explicit per-broker confirmation, and only to the broker's own host.
- **Optional free-lane fallback** — if a form's fields are too cryptic for the matcher, LeakGuard can ask *your own* FreeLLMAPI gateway to classify them (`LEAKGUARD_FREE_LANE_URL` / `LEAKGUARD_FREE_LANE_KEY` / `LEAKGUARD_FREE_LANE_MODEL`, e.g. `openai/gpt-oss-20b` or `gemini-3.5-flash-lite`). Off by default; uses only your gateway's free tiers.

## The honest limits

- **Can be removed:** data brokers, people-search sites, Google search results — they must answer a legal erasure request.
- **Cannot be removed:** a breach dump already copied to Telegram, dark-web forums or torrents. No tool can delete every copy — anyone promising that is lying. The defence there is changing compromised passwords and turning on 2FA.
- CAPTCHA, email-confirmation and phone-verification steps always need you. That's by design — they're proof you're a human removing *your own* data.

## Run it yourself

Zero dependencies — Python 3 standard library only.

```bash
python3 app.py
# open http://localhost:8000
```

Environment: `PORT` (default 8000), `HOST` (default 0.0.0.0).

**On your own device (recommended for walled sites):** `python3 local_agent.py` runs the same engine under your home IP, where broker sites behave normally. It probes, prints the plan, and can open opt-out pages in your browser — it never submits anything automatically.

**Optional browser probe layer:** `pip install -r requirements-optional.txt` plus any Chromium/Chrome. On proxy-locked networks, run `python3 proxy_relay.py` and set `LEAKGUARD_BROWSER_PROXY=http://127.0.0.1:8899`. Disable with `LEAKGUARD_NO_BROWSER=1`.

## Deploy

`render.yaml` is included — create a Web Service from this repo on Render's free tier (or use Blueprint). Start command: `python3 app.py`. No build step.

## Privacy

- No accounts, no database, **no server-side storage of scans**.
- Removal progress lives only in the visitor's browser (`localStorage`).
- Password checks use k-anonymity — only the first 5 characters of the SHA-1 hash ever leave, and passwords are never logged.

## Roadmap

- **v3:** 150+ brokers; recurring monitoring — monthly re-scans with alerts when your email appears in a *new* breach or a broker re-lists you.
- Browser form *filling* for rendered opt-out forms; email-confirmation tracking.

## License

MIT
