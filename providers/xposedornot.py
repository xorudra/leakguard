"""XposedOrNot adapter — email breach lookup + breach analytics.

Wraps the free, keyless XposedOrNot API. The response parsing below is
byte-for-byte the logic the scan handler used before Stage S4, so scan
results are unchanged; only the transport (timeout/retries/breaker/
health) moved into providers.base.HttpClient.
"""

import urllib.parse

from .base import Provider, ProviderInfo, ProviderResult

CHECK_EMAIL = "https://api.xposedornot.com/v1/check-email/{email}"
BREACH_ANALYTICS = "https://api.xposedornot.com/v1/breach-analytics?email={email}"
UA = {"User-Agent": "LeakGuard/1.0 (+https://github.com/xorudra/leakguard)"}


class XposedOrNotProvider(Provider):
    info = ProviderInfo(
        name="XposedOrNot",
        category="breach_database",
        capabilities=("email_breach", "breach_analytics"),
        privacy=("The email address is sent to XposedOrNot's free API "
                 "over HTTPS to look up breaches. LeakGuard stores "
                 "nothing from the lookup."),
    )

    def check_email(self, email):
        """ProviderResult with data = list of breach names ([] when the
        address is not found), or a non-ok status on failure."""
        url = CHECK_EMAIL.format(email=urllib.parse.quote(email, safe=""))
        result = self.client.get_json(url, headers=UA)
        if result.status != "ok":
            return result
        data = result.data
        if isinstance(data, dict) and data.get("Error"):
            return ProviderResult(status="ok", data=[],
                                  latency_ms=result.latency_ms)
        breaches = []
        raw = data.get("breaches") if isinstance(data, dict) else None
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, list):
                    breaches.extend(str(x) for x in item)
                elif isinstance(item, str):
                    breaches.append(item)
        return ProviderResult(status="ok", data=breaches,
                              latency_ms=result.latency_ms)

    def breach_analytics(self, email):
        """ProviderResult with data = {risk_label, risk_score,
        exposed_data, passwords_strength} or None when the provider has
        no metrics for the address."""
        url = BREACH_ANALYTICS.format(
            email=urllib.parse.quote(email, safe=""))
        result = self.client.get_json(url, headers=UA)
        if result.status != "ok":
            return result
        data = result.data
        metrics = data.get("BreachMetrics") if isinstance(data, dict) else None
        if not isinstance(metrics, dict):
            return ProviderResult(status="ok", data=None,
                                  latency_ms=result.latency_ms)
        out = {"risk_label": None, "risk_score": None,
               "exposed_data": [], "passwords_strength": None}
        risk = metrics.get("risk")
        if isinstance(risk, list) and risk and isinstance(risk[0], dict):
            out["risk_label"] = risk[0].get("risk_label")
            out["risk_score"] = risk[0].get("risk_score")
        xposed = metrics.get("xposed_data")
        if isinstance(xposed, list):
            types = []

            def walk(node):
                if isinstance(node, dict):
                    name = str(node.get("name", ""))
                    if name.startswith("data_"):
                        types.append(name[5:].replace("_", " "))
                    for child in node.get("children", []) or []:
                        walk(child)

            for node in xposed:
                walk(node)
            out["exposed_data"] = sorted(set(types))
        if isinstance(metrics.get("passwords_strength"), list) \
                and metrics["passwords_strength"]:
            out["passwords_strength"] = metrics["passwords_strength"][0]
        return ProviderResult(status="ok", data=out,
                              latency_ms=result.latency_ms)
