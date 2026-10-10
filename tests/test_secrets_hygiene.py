"""Phase 74 (Secrets) — permanent secret-hygiene guard + audit record.

AUDIT RECORD (first recorded secret-hygiene audit)
---------------------------------------------------
Date: 2026-10-07. Method: pattern scans over (a) every git-tracked
file in the working tree and (b) the full git history
(``git log --all -p``), plus ``git check-ignore`` verification of every
known secret filename.

Patterns scanned: GitHub tokens (``ghp_``, ``gho_``, ``ghu_``,
``ghs_``, ``ghr_``, ``github_pat_``), AWS access keys
(``AKIA[0-9A-Z]{16}``), PEM private-key blocks, generic credential
assignments (api-key/secret/token/password names bound to a quoted
value of 16+ characters) in non-test files, credential-bearing URLs
(``scheme://user:pass@host``), and long high-entropy literals.

Findings (counts only; no suspected value is ever reproduced):
  * credential-shaped token/key material: 0 in the working tree,
    0 in the full history (52 commits at audit date);
  * secret-named files (``.neon-*`` / ``.vault-*`` / ``.brevo-*`` /
    ``.staging-*``) tracked now or at any point in history: 0;
  * generic credential assignments in non-test tracked files: 0 real
    credentials — the pattern's only non-test hit is a public DNS
    verification prefix constant in accounts/domains.py; every other
    hit anywhere is an obvious test fixture or the README placeholder
    (all allowlisted below by exact string, with reasons);
  * MINOR GAP FOUND AND FIXED THE SAME DAY: the repo ``.gitignore``
    did not cover ``.siteguard-*`` filenames. The real token file
    lives outside this repository and has never been tracked here
    (verified in the history scan), so exposure was nil, but the
    guard gap was real: ``.siteguard-*`` was added to ``.gitignore``
    and is asserted by the test below.

These tests keep the audit true: they fail if a secret file becomes
trackable, stops being ignored, or credential-shaped content lands in
any tracked file or in history.
"""

import re
import subprocess
from pathlib import Path

import unittest

REPO = Path(__file__).resolve().parent.parent

# Every filename that holds (or would hold) a real secret for this
# project or the owner's sibling tooling. Each must be git-ignored so
# it can never be committed by accident.
SECRET_FILENAMES = [
    ".neon-database-url",          # production DB connection string
    ".neon-app-database-url",      # least-privilege app-role connection
    ".neon-app-role-password",     # app-role password
    ".vault-master-key",           # identifier-vault master key
    ".vault-lookup-key",           # vault HMAC lookup key
    ".brevo-api-key",              # email-lane API key
    ".brevo-password",             # email-lane account password
    ".staging-vault-master-key",   # staging vault master key
    ".staging-vault-lookup-key",   # staging vault lookup key
    ".siteguard-github-token",     # GitHub PAT (lives outside the repo)
    ".env",                        # generic dotenv
]

# Substrings that mark a tracked path as a secret file. None may ever
# appear in `git ls-files`.
SECRET_PATH_MARKERS = (".neon-", ".vault-", ".brevo-", ".staging-vault-",
                       ".siteguard-")

# Strong credential shapes. These are never legitimate in source,
# fixtures included — no allowlist applies.
STRONG_PATTERNS = [
    rb"ghp_[A-Za-z0-9]{20,}",
    rb"gho_[A-Za-z0-9]{20,}",
    rb"ghu_[A-Za-z0-9]{20,}",
    rb"ghs_[A-Za-z0-9]{20,}",
    rb"ghr_[A-Za-z0-9]{20,}",
    rb"github_pat_[A-Za-z0-9_]{20,}",
    rb"AKIA[0-9A-Z]{16}",
    rb"-----BEGIN [A-Z ]*PRIVATE KEY-----",
]
STRONG_RES = [re.compile(p) for p in STRONG_PATTERNS]

# Generic credential assignment: a credential-ish name bound to a
# quoted literal of 16+ characters. The value class excludes newlines
# on purpose: a credential never spans lines, and an earlier version
# of this pattern produced a false positive by swallowing the source
# lines following a string concatenation in accounts/auth.py.
ASSIGNMENT_RE = re.compile(
    r"(?i)(?:api[_-]?key|apikey|secret|token|password|passwd)"
    r"\w*[\"']?\s*[:=]\s*[\"']([^\"'\n]{16,})[\"']"
)

# Credential embedded in a URL authority: scheme://userinfo@host.
# Group 1 is the userinfo, group 2 the host — compared together
# against the exact-string allowlist.
URL_USERINFO_RE = re.compile(
    r"[a-z][a-z0-9+.-]*://([A-Za-z0-9._~!$&'()*+,;=:%-]+)@([A-Za-z0-9.-]+)",
    re.IGNORECASE)

# Exact-string allowlist for the two generic checks. Every entry is a
# complete literal that is public-by-design (a fixture or a documented
# placeholder); an entry can only ever excuse that one literal.
ALLOWLISTED_LITERALS = {
    # tests/test_accounts.py — deliberately wrong password used to
    # prove failed logins behave identically to unknown accounts.
    "wrong-password-1",
    # tests/test_accounts.py — fixture password for the
    # change-password flow; never a real credential.
    "brand-new-password-2",
    # README.md — the documented placeholder a user replaces with
    # their own LeakGuard API token; the value itself grants nothing.
    "lg_REPLACE_WITH_YOUR_TOKEN",
    # tests/test_batch_a.py — SSRF fixture proving credential-bearing
    # broker URLs are rejected; .example is a reserved TLD (RFC 2606)
    # and the userinfo is the literal "user:pass".
    "user:pass@broker.example",
    # accounts/domains.py — TOKEN_PREFIX, the public prefix of the
    # DNS TXT ownership-verification token. It is published in DNS by
    # design and is not itself a secret (the random part is separate).
    "leakguard-verify=",
    # tests/test_batch_b.py — fixture password for flag-gate flows.
    "batch-b-password-1",
    # tests/test_remediation.py, tests/test_verify_sources.py and
    # tests/test_fake_broker_e2e.py — shared fixture password for
    # throwaway accounts.
    "test-password-123",
    # tests/test_orgs_admin.py — fixture password for the S11
    # password-reset flow.
    "S11 reset password 456",
    # tests/test_accounts.py — vault fixture: an email-shaped
    # identifier value stored to prove masking/encryption behaviour;
    # generated per-test with a random suffix, never a credential.
    "target-%s@example.com",
    # tests/test_orgs_admin.py — same kind of fixture identifier for
    # the audit-log tests.
    "audit-me-%s@example.com",
    # tests/test_secrets_hygiene.py — this module's own docstring
    # names the shape it hunts (``scheme://user:pass@host``); the
    # host is the literal word "host", not a resolvable name, and
    # the userinfo is the generic placeholder "user:pass".
    "user:pass@host",
    # tests/test_privacy_center_walk.py — fixture password for the
    # throwaway walk-through accounts, and the deliberately wrong
    # password its re-auth rejection case submits.
    "walk-through-pass-1",
    "not-the-password-1",
    # tests/test_launch_safety_wave1.py — fixture password for the
    # throwaway wave-1 accounts (policy acceptance / export /
    # reset-limit flows); never a real credential.
    "correct-horse-battery-9",
}


def _git(*args):
    return subprocess.run(
        ["git", "-C", str(REPO), *args],
        capture_output=True, text=True, timeout=120,
    )


def _require_git():
    if _git("--version").returncode != 0:
        raise unittest.SkipTest(
            "git is required for the secret-hygiene guard")


def _tracked_files():
    out = _git("ls-files")
    assert out.returncode == 0, out.stderr
    return [REPO / line for line in out.stdout.splitlines() if line]


class TestSecretsHygiene(unittest.TestCase):

    def test_secret_filenames_are_git_ignored(self):
        _require_git()
        not_ignored = [
            name for name in SECRET_FILENAMES
            if _git("check-ignore", "-q", name).returncode != 0
        ]
        assert not_ignored == [], (
            f"secret filenames not covered by .gitignore: {not_ignored}")


    def test_no_secret_filenames_are_tracked(self):
        _require_git()
        tracked = _git("ls-files").stdout.splitlines()
        offenders = [
            path for path in tracked
            if any(marker in Path(path).name for marker in SECRET_PATH_MARKERS)
        ]
        assert offenders == [], f"secret-named files tracked: {offenders}"


    def test_no_credential_shapes_in_tracked_files(self):
        _require_git()
        hits = []
        for path in _tracked_files():
            data = path.read_bytes()
            for pattern in STRONG_RES:
                if pattern.search(data):
                    hits.append(f"{path.relative_to(REPO)}: {pattern.pattern!r}")
        assert hits == [], f"credential-shaped content in tracked files: {hits}"


    def test_no_credential_assignments_in_tracked_files(self):
        _require_git()
        hits = []
        for path in _tracked_files():
            text = path.read_bytes().decode("utf-8", errors="ignore")
            for match in ASSIGNMENT_RE.finditer(text):
                value = match.group(1)
                if value not in ALLOWLISTED_LITERALS:
                    hits.append(
                        f"{path.relative_to(REPO)}: credential assignment "
                        f"with non-allowlisted value (length {len(value)})")
            for match in URL_USERINFO_RE.finditer(text):
                # Userinfo without a password (a bare username, as in
                # URL-parsing fixtures and socket-style database URLs)
                # carries no credential and is not a finding.
                if ":" not in match.group(1):
                    continue
                authority = f"{match.group(1)}@{match.group(2)}"
                if authority not in ALLOWLISTED_LITERALS:
                    hits.append(
                        f"{path.relative_to(REPO)}: URL with embedded "
                        f"credentials outside the allowlist")
        assert hits == [], hits


    def test_no_credential_shapes_in_git_history(self):
        _require_git()
        out = subprocess.run(
            ["git", "-C", str(REPO), "log", "--all", "-p", "-U0", "--no-color"],
            capture_output=True, timeout=300,
        )
        assert out.returncode == 0
        hits = [pattern.pattern for pattern in STRONG_RES
                if pattern.search(out.stdout)]
        assert hits == [], (
            f"credential-shaped content found in git history: {hits} — "
            "a secret that was committed and later removed is still leaked")


if __name__ == "__main__":
    unittest.main()
