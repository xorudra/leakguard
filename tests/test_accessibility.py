"""Accessibility invariant tests (spec Phase 96).

Static assertions over the SHIPPED HTML/JS/CSS — the regression
net that keeps the accessibility pass from silently rotting:

* the document has a lang and a non-empty title;
* landmarks exist (header, nav, main, footer) and the nav is
  labelled;
* every form control in the static HTML has an accessible name —
  a wrapping <label>, a <label for>, or an aria-label;
* every static <button> has visible text or an aria-label
  (no icon-only button ships unnamed);
* the announcement regions exist with aria-live="polite": the
  scan-completion status, the auth status, the full-scan and
  removal statuses, the notifications list, the agent run log and
  the search-exposure list;
* heading order never skips a level and there is exactly one h1;
* no positive tabindex anywhere in the HTML or app.js (positive
  tabindex breaks the natural focus order);
* images carry alt discipline (any <img> must have an alt);
* the stylesheet keeps a :focus-visible rule, so keyboard focus
  is always visible;
* the dynamic controls app.js creates carry their names too:
  the per-broker removal-progress select and the whose-detail
  select set aria-labels, and the dispute toggle maintains
  aria-expanded.

The live DOM check (rendered page, JS-built controls included)
is tools/a11y_check.py, run against a deployed site.

Run:  python3 -m unittest discover -s tests
"""

import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
APP_JS = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "static" / "style.css").read_text(encoding="utf-8")

_VOID = {"input", "img", "br", "hr", "meta", "link", "source"}


class _Audit(HTMLParser):
    """Collects the facts the assertions below reason about."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []            # open (tag, attrs) elements
        self.lang = None
        self.title_text = ""
        self.landmarks = set()
        self.controls = []         # (tag, attrs, wrapped_in_label)
        self.buttons = []          # (attrs, text)
        self.images = []           # attrs
        self.headings = []         # levels in document order
        self.live_regions = {}     # id -> aria-live value
        self.label_fors = set()
        self.tabindexes = []
        self._button = None        # [attrs, text parts]
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "html":
            self.lang = attrs.get("lang")
        if tag == "title":
            self._in_title = True
        if tag in ("header", "nav", "main", "footer"):
            self.landmarks.add(tag)
        if tag == "label" and attrs.get("for"):
            self.label_fors.add(attrs["for"])
        if tag in ("input", "select", "textarea"):
            wrapped = any(t == "label" for t, _a in self.stack)
            self.controls.append((tag, attrs, wrapped))
        if tag == "button":
            self._button = [attrs, []]
        if tag == "img":
            self.images.append(attrs)
        if re.fullmatch(r"h[1-6]", tag):
            self.headings.append(int(tag[1]))
        if attrs.get("id") and attrs.get("aria-live"):
            self.live_regions[attrs["id"]] = attrs["aria-live"]
        if "tabindex" in attrs:
            self.tabindexes.append(attrs["tabindex"])
        if tag not in _VOID:
            self.stack.append((tag, attrs))

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        if tag == "button" and self._button is not None:
            attrs, parts = self._button
            self.buttons.append((attrs, "".join(parts).strip()))
            self._button = None
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        if self._in_title:
            self.title_text += data
        if self._button is not None:
            self._button[1].append(data)


def _audit():
    parser = _Audit()
    parser.feed(HTML)
    return parser


class TestDocumentBasics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = _audit()

    def test_lang_and_title(self):
        self.assertEqual(self.a.lang, "en")
        self.assertIn("LeakGuard", self.a.title_text)

    def test_landmarks_present(self):
        for tag in ("header", "nav", "main", "footer"):
            self.assertIn(tag, self.a.landmarks)

    def test_nav_is_labelled(self):
        self.assertIn('<nav aria-label="Main">', HTML)


class TestFormControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = _audit()

    def test_every_control_has_an_accessible_name(self):
        unnamed = []
        for tag, attrs, wrapped in self.a.controls:
            if attrs.get("type") == "hidden":
                continue
            named = (wrapped or attrs.get("aria-label")
                     or (attrs.get("id")
                         and attrs["id"] in self.a.label_fors))
            if not named:
                unnamed.append("%s#%s" % (tag, attrs.get("id")))
        self.assertEqual(unnamed, [])


class TestButtons(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = _audit()

    def test_every_button_has_text_or_label(self):
        unnamed = [attrs.get("id") for attrs, text in self.a.buttons
                   if not text and not attrs.get("aria-label")]
        self.assertEqual(unnamed, [])


class TestLiveRegions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = _audit()

    def test_announcement_regions_are_polite_live(self):
        for region in ("scanStatus", "acStatus", "rsStatus",
                       "fullScanStatus", "removalStatus", "planStatus",
                       "runStatus", "autoFeed", "notifList",
                       "searchExposureList"):
            self.assertEqual(self.a.live_regions.get(region), "polite",
                             region)


class TestStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = _audit()

    def test_heading_order_never_skips(self):
        levels = self.a.headings
        self.assertEqual(levels[0], 1)
        self.assertEqual(levels.count(1), 1)
        for prev, cur in zip(levels, levels[1:]):
            self.assertLessEqual(cur, prev + 1,
                                 "heading jump h%d -> h%d" % (prev, cur))

    def test_no_positive_tabindex(self):
        for value in self.a.tabindexes:
            self.assertLessEqual(int(value), 0)
        self.assertNotIn("tabIndex", APP_JS)

    def test_images_have_alt(self):
        for attrs in self.a.images:
            self.assertIn("alt", attrs)

    def test_focus_visible_styling_present(self):
        self.assertIn(":focus-visible", CSS)

    def test_skip_link_present(self):
        self.assertIn('class="skipLink"', HTML)


class TestDynamicControls(unittest.TestCase):
    """The JS-built controls carry accessible names too — the
    static source is where that contract is pinned."""

    def test_broker_progress_select_labelled(self):
        self.assertIn('"Removal progress for " + b.name', APP_JS)

    def test_member_select_labelled(self):
        self.assertIn('"Whose detail is this? ("', APP_JS)

    def test_dispute_toggle_tracks_expanded(self):
        self.assertIn('toggle.setAttribute("aria-expanded"', APP_JS)

    def test_consent_toggles_labelled(self):
        self.assertIn('toggle.setAttribute("aria-label", title)', APP_JS)

    def test_search_exposure_view_wired(self):
        # Phase 40: the view exists and calls its endpoint.
        self.assertIn("<h3>Search exposure</h3>", HTML)
        self.assertIn('apiJson("/api/search-exposure")', APP_JS)
        self.assertIn('id="searchExposureList"', HTML)

    def test_admin_broker_health_rendered(self):
        # Phase 125: the Admin card renders the broker_health block.
        self.assertIn("d.broker_health", APP_JS)
        self.assertIn('"Broker: " + b.name', APP_JS)


if __name__ == "__main__":
    unittest.main()
