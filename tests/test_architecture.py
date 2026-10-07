"""Phase 1 (Repository restructure) — boundary verification record.

VERIFICATION RECORD (import-graph audit)
----------------------------------------
Date: 2026-10-07. Method: AST scan of every import in the entry
scripts and all nine packages, then a fresh-subprocess import of each
package (every submodule) to prove each imports cleanly standalone.

Module boundaries AS FOUND (not as assumed):

  Entry points
    app.py          the HTTP server; imports every package + agent.
    agent.py        legacy deterministic broker-agent engine; imports
                    only `core` from the project.
    local_agent.py  imports `agent` only. browser_probe.py and
                    proxy_relay.py import no project code.

  Leaf packages (import no project code at all)
    db/             persistence (pool + migrations).
    providers/      external data providers; deliberately ignorant of
                    accounts/remediation — it is handed identifiers,
                    it never reaches into the account layer.

  Foundation
    vault/          imports only db (store) — crypto imports nothing.
    core/           top level imports only db (in core/retention.py).
                    The retention pass additionally reaches UP into
                    accounts and remediation through DEFERRED
                    (function-level) imports in that same file — the
                    one sanctioned upward reach, pinned by the tests
                    below so it cannot spread silently.

  Feature packages
    accounts/       the mid-layer hub: imports core, db, vault at top
                    level; providers from admin/domains; monitoring
                    and remediation only via deferred imports.
    scanning/       imports accounts, core, db, providers, vault;
                    monitoring deferred (worker) — except
                    scanning/feedback.py, which imports monitoring at
                    top level.
    remediation/    imports accounts, core, db, providers, vault, and
                    the legacy `agent` module it wraps.
    monitoring/     imports accounts, core, db, scanning;
                    remediation deferred (events).
    dashboard/      the top layer: imports accounts, core, db,
                    monitoring, scanning. Nothing imports dashboard
                    except app.

  Honest irregularities (recorded, not "fixed" — this audit verifies
  the graph as it is):
    * A package-level cycle exists between scanning and monitoring
      (monitoring/events.py -> scanning at top level;
      scanning/feedback.py -> monitoring at top level). It resolves
      because the concrete module edges never loop back during
      initialisation, and every package imports cleanly standalone.
    * core/retention.py's deferred upward imports (above).

The tests below encode ONLY the invariants verified true above.
"""

import ast
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PACKAGES = ["core", "accounts", "providers", "scanning", "remediation",
            "monitoring", "dashboard", "db", "vault"]
ENTRY_SCRIPTS = ["app", "local_agent", "browser_probe", "proxy_relay"]
PROJECT_ROOTS = set(PACKAGES) | set(ENTRY_SCRIPTS) | {"agent"}


def _project_imports(path, own_root):
    """Return (top_level_roots, all_roots) of project imports in a file.

    Relative imports resolve inside the importer's own package and are
    recorded as that package. Third-party/stdlib imports are ignored.
    """
    tree = ast.parse(path.read_text(errors="replace"))
    top_level_nodes = set(tree.body)
    top, all_ = set(), set()
    for node in ast.walk(tree):
        modules = []
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                modules = [own_root]
            elif node.module:
                modules = [node.module]
        for module in modules:
            root = module.split(".")[0]
            if root in PROJECT_ROOTS:
                all_.add(root)
                if node in top_level_nodes:
                    top.add(root)
    return top, all_


def _files_under(root):
    base = REPO / root
    return sorted(base.rglob("*.py"))


def _all_imports(root):
    """Map of relative file path -> (top_level_roots, all_roots)."""
    result = {}
    for path in _files_under(root):
        result[str(path.relative_to(REPO))] = _project_imports(path, root)
    return result


def test_packages_never_import_entry_scripts():
    offenders = []
    for package in PACKAGES:
        for rel, (_top, all_) in _all_imports(package).items():
            bad = all_ & set(ENTRY_SCRIPTS)
            if bad:
                offenders.append(f"{rel} imports {sorted(bad)}")
    assert offenders == [], offenders


def test_db_and_providers_are_leaf_packages():
    for package in ("db", "providers"):
        for rel, (_top, all_) in _all_imports(package).items():
            external = all_ - {package}
            assert external == set(), (
                f"{rel}: leaf package imports project code {external}")


def test_core_top_level_imports_only_db():
    for rel, (top, _all) in _all_imports("core").items():
        assert top - {"core", "db"} == set(), (
            f"{rel}: core top level imports {top - {'core', 'db'}}")


def test_core_upward_reach_is_confined_to_retention():
    for rel, (top, all_) in _all_imports("core").items():
        upward = (all_ - {"core", "db"})
        if rel == "core/retention.py":
            assert upward <= {"accounts", "remediation"}, (
                f"retention.py reaches into {upward}")
            assert upward & top == set(), (
                "retention.py upward imports must stay deferred "
                "(function-level), never top-level")
        else:
            assert upward == set(), f"{rel}: core reaches up into {upward}"


def test_vault_imports_only_db():
    for rel, (_top, all_) in _all_imports("vault").items():
        assert all_ - {"vault", "db"} == set(), (
            f"{rel}: vault imports {all_ - {'vault', 'db'}}")


def test_agent_engine_imports_only_core():
    _top, all_ = _project_imports(REPO / "agent.py", "agent")
    assert all_ - {"core"} == set(), f"agent.py imports {all_ - {'core'}}"


def test_nothing_but_app_imports_dashboard():
    for package in PACKAGES:
        if package == "dashboard":
            continue
        for rel, (_top, all_) in _all_imports(package).items():
            assert "dashboard" not in all_, f"{rel} imports dashboard"


def test_packages_import_cleanly_standalone():
    code = (
        "import importlib, pkgutil, sys\n"
        "name = sys.argv[1]\n"
        "pkg = importlib.import_module(name)\n"
        "if hasattr(pkg, '__path__'):\n"
        "    for m in pkgutil.walk_packages(pkg.__path__, prefix=name + '.'):\n"
        "        importlib.import_module(m.name)\n"
    )
    for name in PACKAGES + ["agent"]:
        proc = subprocess.run(
            [sys.executable, "-c", code, name],
            cwd=REPO, capture_output=True, text=True, timeout=180,
        )
        assert proc.returncode == 0, (
            f"standalone import of {name} failed:\n{proc.stderr[-2000:]}")
