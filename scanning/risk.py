"""Deterministic risk engine v2 (spec Phases 25, 27).

Two scorers, both pure functions — same inputs, same outputs, forever:

* score_email_profile(breaches, analytics, pwned_count) is the LEGACY
  exposure score, moved here verbatim from app.py so the anonymous
  Quick Scan and the signed-in full scan share one implementation.
  The arithmetic is byte-for-byte the pre-S5 rule:

      base  = analytics risk_score when the provider supplies one,
              else min(100, breach_count * 8) when the lookup ran,
              else 0
      floor = 85 when the password was seen > 1000 times,
              70 when it was seen at all (applied via max)
      score = clamp(base-or-floor, 0, 100)

  On top of the number it now returns an EXPLANATION: one plain-
  language entry per component that fed the score, so a user can see
  WHY they got the number they got. The explanation never changes
  the score.

* finding_risk(exposed_fields, source_reliability) scores ONE
  normalized finding. Documented rubric (weights by exposed field,
  matched case-insensitively on substrings of the field name, in the
  order listed — first match wins per field):

      social security / ssn / national id .... 50
      password ............................... 45
      credit card / bank / financial /
        payment .............................. 40
      date of birth / birth .................. 15
      phone .................................. 15
      ip address ............................. 10
      username ............................... 10
      email ..................................  5
      physical address / address ............. 15
      name ...................................  5
      anything else ..........................  8

  ("email" is matched before "address" on purpose: the field
  "email addresses" is an email exposure, not a postal one.)

  Field weights sum, capped at 90; a finding with no attributable
  fields starts from a floor of 5. The sum is then scaled by source
  reliability (high x1.0, medium x0.8, low x0.5), rounded, and
  clamped to 0..100. Sensitive identity/financial material weighs
  most because it is what enables account takeover and fraud.
"""


def score_email_profile(breaches, analytics, pwned_count):
    """(score:int, explanation:list[str]) — the legacy exposure
    score plus the reasons for it. `breaches` is the list of breach
    names (None when the lookup itself failed), `analytics` the
    provider analytics dict or None, `pwned_count` the password
    sighting count or None/0 when unchecked or unseen."""
    explanation = []
    base = 0
    base_kind = None
    if analytics and isinstance(analytics.get("risk_score"), (int, float)):
        base = int(analytics["risk_score"])
        base_kind = "analytics"
    elif breaches is not None:
        base = min(100, len(breaches) * 8)
        base_kind = "count"

    count = len(breaches) if breaches else 0
    if base_kind == "analytics":
        explanation.append(
            "+%d — breach-database risk score across %d known breach%s"
            % (base, count, "" if count == 1 else "es"))
    elif base_kind == "count" and count:
        explanation.append(
            "+%d — %d known breach%s × 8 points each"
            % (base, count, "" if count == 1 else "es"))
    elif base_kind == "count":
        explanation.append(
            "No points — no known breaches for this address")
    else:
        explanation.append(
            "No score — the breach lookup itself was unavailable")

    score = base
    if pwned_count:
        floor = 85 if pwned_count > 1000 else 70
        if floor > score:
            explanation.append(
                "+%d — a password for this address was seen %s times in "
                "breach data (score raised to at least %d)"
                % (floor - score, format(pwned_count, ","), floor))
            score = floor
        else:
            explanation.append(
                "A password for this address was seen %s times in breach "
                "data — the breach score already covers this"
                % format(pwned_count, ","))
    return max(0, min(100, score)), explanation


_FIELD_WEIGHTS = (
    (("social security", "ssn", "national id"), 50),
    (("password",), 45),
    (("credit card", "bank", "financial", "payment"), 40),
    (("date of birth", "birth"), 15),
    (("phone",), 15),
    (("ip address",), 10),
    (("username",), 10),
    (("email",), 5),
    (("physical address", "address"), 15),
    (("name",), 5),
)
_DEFAULT_FIELD_WEIGHT = 8
_NO_FIELDS_FLOOR = 5
_FIELD_SUM_CAP = 90
_RELIABILITY_SCALE = {"high": 1.0, "medium": 0.8, "low": 0.5}


def _field_weight(field):
    name = str(field or "").strip().lower()
    for needles, weight in _FIELD_WEIGHTS:
        if any(needle in name for needle in needles):
            return weight
    return _DEFAULT_FIELD_WEIGHT


def finding_risk(exposed_fields, source_reliability):
    """Risk 0..100 for one finding, per the rubric in the module
    docstring. Unknown reliability labels scale as low."""
    fields = list(exposed_fields or [])
    if fields:
        total = sum(_field_weight(f) for f in fields)
    else:
        total = _NO_FIELDS_FLOOR
    total = min(total, _FIELD_SUM_CAP)
    scale = _RELIABILITY_SCALE.get(
        str(source_reliability or "").strip().lower(), 0.5)
    return max(0, min(100, int(round(total * scale))))
