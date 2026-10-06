# LeakGuard 🛡️

**Your data got leaked. Find it. Remove it.**

A free, GUI-based tool (web UI, no CLI) that:

1. **Scans** your email against real breach databases — [XposedOrNot](https://xposedornot.com) (free, no key) — and checks a password against [Have I Been Pwned Pwned Passwords](https://haveibeenpwned.com/Passwords) using k-anonymity, so the password itself is never sent or stored.
2. **Scores** your exposure 0–100 and lists exactly which breaches contain your email and what types of data were exposed.
3. **Removes** — a Removal Centre with 40 data brokers & people-search sites (Spokeo, BeenVerified, Whitepages, Acxiom, LexisNexis, …): opt-out links, a tracking board (saved in your browser), and a one-click **erasure-request letter generator** citing India's DPDP Act §12, GDPR Art. 17, or CCPA.
4. **Google** — builds the searches a stranger would run on you and links Google's own *Results about you* removal tool.

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

- **v1 (this):** breach + password scan, exposure score, Removal Centre (40 brokers), letter generator, Google tools.
- **v2:** 150+ brokers, semi-automated opt-out submission, email-confirmation tracking.
- **v3:** recurring monitoring — re-scan monthly, alert when an email appears in a *new* breach or a broker re-lists you.

## License

MIT
