"""Tests verifying XSS escaping in dashboard HTML files.

Ensures that functions handling external data properly escape output
before inserting into innerHTML sinks.
"""

import os
import re

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
DOCS_HTML = os.path.join(REPO_ROOT, "docs", "index.html")
DASHBOARD_HTML = os.path.join(REPO_ROOT, "telemetry", "templates", "dashboard.html")


def _read(path):
    with open(path, "r") as f:
        return f.read()


class TestRenderTrendChartJsEscaping:
    """CQLF-ALL-R55-0001: renderTrendChartJs must not spread tainted objects."""

    def test_no_object_assign_spread_in_renderTrendChartJs(self):
        for path in (DOCS_HTML, DASHBOARD_HTML):
            src = _read(path)
            fn_match = re.search(
                r"function renderTrendChartJs\b.*?\n\}", src, re.DOTALL
            )
            assert fn_match, f"renderTrendChartJs not found in {path}"
            body = fn_match.group(0)
            assert "Object.assign" not in body, (
                f"renderTrendChartJs in {path} should not use Object.assign "
                "to spread untrusted run objects"
            )

    def test_explicit_property_construction(self):
        for path in (DOCS_HTML, DASHBOARD_HTML):
            src = _read(path)
            fn_match = re.search(
                r"function renderTrendChartJs\b.*?\n\}", src, re.DOTALL
            )
            assert fn_match
            body = fn_match.group(0)
            assert "parseInt(r.run_number" in body
            assert "parseInt(r.issues_found" in body
            assert "Array.isArray(r.sessions)" in body


class TestRenderFixRatesPanelEscaping:
    """CQLF-ALL-R55-0002: renderFixRatesPanel must escape all interpolated values."""

    def test_item_total_escaped(self):
        for path in (DOCS_HTML, DASHBOARD_HTML):
            src = _read(path)
            assert "escapeHtml(String(item.total))" in src, (
                f"item.total not escaped in {path}"
            )

    def test_item_fixed_escaped(self):
        for path in (DOCS_HTML, DASHBOARD_HTML):
            src = _read(path)
            assert "escapeHtml(String(item.fixed))" in src, (
                f"item.fixed not escaped in {path}"
            )

    def test_pct_escaped(self):
        for path in (DOCS_HTML, DASHBOARD_HTML):
            src = _read(path)
            assert "escapeHtml(String(pct))" in src, (
                f"pct not escaped in {path}"
            )

    def test_overall_values_escaped(self):
        for path in (DOCS_HTML, DASHBOARD_HTML):
            src = _read(path)
            assert "escapeHtml(String(overall.fix_rate" in src
            assert "escapeHtml(String(overall.fixed" in src
            assert "escapeHtml(String(overall.total" in src

    def test_script_payload_would_be_encoded(self):
        xss_payload = '<script>alert(1)</script>'
        expected_encoded = '&lt;script&gt;alert(1)&lt;/script&gt;'
        escaped = (
            xss_payload
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#039;")
        )
        assert escaped == expected_encoded
