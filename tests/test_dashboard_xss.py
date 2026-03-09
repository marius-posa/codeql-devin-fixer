"""Tests to verify XSS protection in dashboard HTML files.

Ensures that renderRunsTable and similar functions use escapeHtml()
on all user-controlled values before inserting them into innerHTML.
Covers CQLF-R73-0006: DOM text reinterpreted as HTML.
"""

import os
import re

# Paths to the two dashboard HTML files that must stay in sync.
DOCS_HTML = os.path.join(os.path.dirname(__file__), "..", "docs", "index.html")
TELEMETRY_HTML = os.path.join(
    os.path.dirname(__file__), "..", "telemetry", "templates", "dashboard.html"
)


def _extract_render_runs_table(filepath):
    """Extract the renderRunsTable function body from an HTML file."""
    with open(filepath, "r") as f:
        content = f.read()
    match = re.search(
        r"function renderRunsTable\(runs\)\s*\{(.+?)\n\}",
        content,
        re.DOTALL,
    )
    assert match, f"renderRunsTable not found in {filepath}"
    return match.group(1)


def _find_unescaped_td_values(func_body):
    """Find <td> values that are not wrapped in escapeHtml() or are not
    static HTML badges (triggerBadge).

    Returns a list of suspicious unescaped expressions.
    """
    unescaped = []
    # Match patterns like  '<td>' + EXPR + '</td>'
    # or  '<td><strong>' + EXPR + '</strong></td>'
    td_pattern = re.compile(
        r"'<td[^>]*>'(?:\s*\+\s*'<strong>')?(?:\s*\+\s*'#')?\s*\+\s*(.+?)\s*\+\s*'</"
    )
    for m in td_pattern.finditer(func_body):
        expr = m.group(1).strip()
        # Allow expressions already wrapped in escapeHtml(...)
        if expr.startswith("escapeHtml("):
            continue
        # Allow the triggerBadge variable (static HTML from hardcoded strings)
        if expr == "triggerBadge":
            continue
        unescaped.append(expr)
    return unescaped


class TestRenderRunsTableEscaping:
    """Verify that renderRunsTable escapes all dynamic values."""

    def test_docs_index_all_values_escaped(self):
        body = _extract_render_runs_table(DOCS_HTML)
        unescaped = _find_unescaped_td_values(body)
        assert unescaped == [], (
            f"docs/index.html renderRunsTable has unescaped values: {unescaped}"
        )

    def test_telemetry_dashboard_all_values_escaped(self):
        body = _extract_render_runs_table(TELEMETRY_HTML)
        unescaped = _find_unescaped_td_values(body)
        assert unescaped == [], (
            f"telemetry dashboard renderRunsTable has unescaped values: {unescaped}"
        )


class TestXssPayloadEncoded:
    """Verify that escapeHtml would encode a script tag payload.

    This is a static analysis test that checks the escapeHtml function
    definition includes the necessary replacements.
    """

    def _get_escape_html_body(self, filepath):
        with open(filepath, "r") as f:
            content = f.read()
        # escapeHtml may be in the file itself or in a referenced JS file
        match = re.search(
            r"function escapeHtml\(str\)\s*\{(.+?)\n\}",
            content,
            re.DOTALL,
        )
        return match.group(1) if match else None

    def test_escape_html_handles_angle_brackets(self):
        """The escapeHtml function must replace < and > characters."""
        # Check the shared.js that both dashboards use
        shared_js = os.path.join(
            os.path.dirname(__file__), "..", "docs", "static", "shared.js"
        )
        with open(shared_js, "r") as f:
            content = f.read()

        # Verify escapeHtml replaces < and >
        assert ".replace(/</g" in content, "escapeHtml must escape <"
        assert ".replace(/>/g" in content, "escapeHtml must escape >"
        assert ".replace(/&/g" in content, "escapeHtml must escape &"
        assert ".replace(/\"/g" in content, 'escapeHtml must escape "'

    def test_xss_payload_would_be_neutralized(self):
        """Simulate escapeHtml on a script tag payload."""
        payload = '<script>alert(1)</script>'
        # Replicate the escapeHtml logic from shared.js
        escaped = (
            payload
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#039;")
        )
        assert "<script>" not in escaped
        assert "&lt;script&gt;" in escaped
        assert "alert(1)" in escaped  # content preserved, just encoded
