"""Static checks for the keyboard and accessibility pass (milestone 8).

There is no JS runtime in the Python suite, so these assert what is cheap to read from the files.
The behavior itself (shortcuts, overflow at 390px, labels after render) is driven in a real browser
by scripts/ui_check.js.
"""
import re
import unittest
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "static"


def read(name):
    return (STATIC / name).read_text()


def function_body(source, name):
    """Text of a top-level `[async] function name(...) {...}` (up to the first line that is just `}`)."""
    match = re.search(rf"^(?:async )?function {name}\(.*?^\}}$", source, re.S | re.M)
    if not match:
        raise AssertionError(f"function {name} not found")
    return match.group(0)


def luminance(hex_color):
    channels = [int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(a, b):
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


class IndexLandmarkTests(unittest.TestCase):
    def setUp(self):
        self.html = read("index.html")

    def test_landmarks(self):
        self.assertEqual(len(re.findall(r"<main\b", self.html)), 1)
        self.assertRegex(self.html, r'<nav\b[^>]*aria-label="[^"]+"')
        self.assertRegex(self.html, r'<a class="skip-link" href="#main">')
        self.assertRegex(self.html, r'<main id="main" tabindex="-1">')

    def test_live_regions_exist_before_any_toast(self):
        self.assertRegex(self.html, r'<div id="toast-status" role="status">')
        self.assertRegex(self.html, r'<div id="toast-alert" role="alert">')
        self.assertRegex(self.html, r'id="login-error" role="alert"')

    def test_every_form_control_has_a_label(self):
        # Each control in index.html sits inside a <label> or carries aria-label.
        for match in re.finditer(r"<(input|select|textarea)\b[^>]*>", self.html):
            before = self.html[:match.start()]
            inside_label = before.rfind("<label") > before.rfind("</label>")
            with self.subTest(control=match.group(0)):
                self.assertTrue(inside_label or "aria-label=" in match.group(0))

    def test_every_button_has_a_name(self):
        for match in re.finditer(r"<button\b([^>]*)>(.*?)</button>", self.html, re.S):
            text = re.sub(r"<svg.*?</svg>|<[^>]+>", "", match.group(2)).strip()
            with self.subTest(button=match.group(0)[:80]):
                self.assertTrue(text or "aria-label=" in match.group(1))

    def test_menu_toggle_is_wired_for_assistive_tech(self):
        self.assertRegex(self.html, r'id="nav-toggle"[^>]*aria-expanded="false"[^>]*aria-controls="nav"')


class ShortcutHandlerTests(unittest.TestCase):
    def setUp(self):
        self.app = read("app.js")

    def test_typing_targets_are_ignored(self):
        typing = re.search(r"const isTyping = .*", self.app).group(0)
        for tag in ("INPUT", "TEXTAREA", "SELECT"):
            self.assertIn(f'"{tag}"', typing)
        self.assertIn("isContentEditable", typing)
        allowed = function_body(self.app, "shortcutsAllowed")
        self.assertIn("!isTyping(ev.target)", allowed)
        self.assertIn("!m.open", allowed, "shortcuts must not fire while a dialog is open")
        for mod in ("ev.ctrlKey", "ev.metaKey", "ev.altKey"):
            self.assertIn(f"!{mod}", allowed)

    def test_handler_checks_before_acting(self):
        body = function_body(self.app, "onShortcut")
        first = body.splitlines()[1].strip()
        self.assertEqual(first, "if (!shortcutsAllowed(ev)) return;")
        self.assertIn('document.addEventListener("keydown", onShortcut)', self.app)

    def test_action_keys_need_a_role_that_may_act(self):
        detail = function_body(self.app, "alertDetail")
        self.assertRegex(detail, r'if \(state\.keys && can\("analyst"\) && a\.status !== "resolved"\) \{\s*state\.keys\.a = .*\s*state\.keys\.r = ')
        # Esc is set for everyone; a and r appear nowhere else in the alert view.
        self.assertEqual(len(re.findall(r"state\.keys\.[ar] =", detail)), 2)

    def test_route_marks_the_current_view(self):
        route = function_body(self.app, "route")
        self.assertIn('setAttribute("aria-current", "page")', route)
        self.assertIn('removeAttribute("aria-current")', route)
        self.assertIn("state.keys = null", route, "view keys must not leak into the next view")

    def test_clickable_rows_are_keyboard_reachable(self):
        table = function_body(self.app, "table")
        self.assertIn('tabindex: onClick ? "0" : null', table)
        self.assertIn('ev.key !== "Enter"', table)

    def test_dialogs_return_focus(self):
        self.assertNotIn('$("#modal").showModal()', self.app, "open dialogs through openModal()")
        self.assertIn('$("#modal").addEventListener("close"', self.app)

    def test_generated_controls_are_labelled(self):
        # Inputs built in JS are wrapped in el("label", ...) on the same line, carry aria-label, or are
        # assigned to a variable that a label wraps later.
        for path in ("app.js", "dashboard.js"):
            src = read(path)
            lines = src.splitlines()
            for n, line in enumerate(lines):
                if not re.search(r'el\("(input|select|textarea)"', line) or 'el("label"' in line or "aria-label" in line:
                    continue
                var = re.match(r"\s*const (\w+) = el\(", line)
                wrapped_later = var and re.search(rf'el\("label"[^\n]*\b{var.group(1)}\)', src)
                wrapped_above = 'el("label"' in lines[n - 1]
                with self.subTest(file=path, line=n + 1):
                    self.assertTrue(wrapped_later or wrapped_above, line.strip())


class StyleTests(unittest.TestCase):
    def setUp(self):
        self.css = read("style.css")
        self.tokens = dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})", self.css))

    def test_reduced_motion(self):
        self.assertRegex(self.css, r"@media \(prefers-reduced-motion: reduce\) \{[^}]*animation: none !important")

    def test_text_and_badge_colors_meet_wcag_aa(self):
        # The only theme is dark. Every text or badge color against every surface it sits on: 4.5:1.
        surfaces = ("bg", "bg-2", "panel", "panel-2", "raise")
        texts = ("ink", "ink-2", "muted", "crit", "high", "med", "low", "info", "accent", "ok", "warn", "bad", "synthetic")
        for fg in texts:
            for bg in surfaces:
                with self.subTest(fg=fg, bg=bg):
                    self.assertGreaterEqual(contrast(self.tokens[fg], self.tokens[bg]), 4.5)
        danger = re.search(r"button\.danger \{ background: (#[0-9a-f]{6});[^}]*color: #fff;", self.css)
        self.assertGreaterEqual(contrast("#ffffff", danger.group(1)), 4.5)
        self.assertGreaterEqual(contrast(self.tokens["accent-ink"], self.tokens["accent"]), 4.5)

    def test_tables_scroll_inside_a_wrapper(self):
        self.assertIn(".table-wrap { overflow-x: auto; }", self.css)

    def test_focus_is_visible(self):
        self.assertIn(":focus-visible { outline: 2px solid var(--accent)", self.css)


if __name__ == "__main__":
    unittest.main()
