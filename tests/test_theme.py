"""Design V2: Akzentfarbe aus der Konfiguration, /theme.css, Kontraste der Farbvariablen."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from aluco.config import ConfigError
from aluco.web import WebConfig, create_app
from aluco.web.theme import DEFAULT_ACCENT, MIN_CONTRAST, SURFACE, Theme, ThemeError, contrast

CSS = Path(__file__).parents[1] / "src/aluco/web/static/aluco.css"


def test_default_theme_matches_stylesheet_defaults() -> None:
    tokens = dict(re.findall(r"--([\w-]+):\s*(#[0-9a-f]{6})", CSS.read_text()))
    t = Theme()
    assert t.accent == DEFAULT_ACCENT
    assert (tokens["accent"], tokens["accent-strong"], tokens["accent-tint"]) == (
        t.accent, t.strong, t.tint,
    )  # fmt: skip
    assert tokens["on-accent"] == t.on_accent


@pytest.mark.parametrize("raw", ["#22D3EE", "22d3ee", " #a78bfa "])
def test_parse_accepts_hex_and_derives_readable_tones(raw: str) -> None:
    t = Theme.parse(raw)
    assert re.fullmatch(r"#[0-9a-f]{6}", t.accent)
    assert contrast(t.accent, SURFACE) >= MIN_CONTRAST
    assert contrast(t.on_accent, t.accent) >= MIN_CONTRAST
    assert contrast(t.strong, t.tint) >= MIN_CONTRAST


def test_parse_rejects_bad_or_too_dark_colors() -> None:
    assert Theme.parse("") == Theme() == Theme.parse(None)
    with pytest.raises(ThemeError, match="Hex-Farbe"):
        Theme.parse("blue")
    with pytest.raises(ThemeError, match="zu schwach"):
        Theme.parse("#1d4ed8")  # V1-Blau ist auf dunklem Grund zu dunkel


def test_web_config_reads_accent() -> None:
    env = {"ALUCO_DASHBOARD_PASSWORD": "x" * 12}
    assert WebConfig.from_env(env).theme == Theme()
    assert WebConfig.from_env({**env, "ALUCO_UI_ACCENT": "#22d3ee"}).theme.accent == "#22d3ee"
    with pytest.raises(ConfigError, match="ALUCO_UI_ACCENT"):
        WebConfig.from_env({**env, "ALUCO_UI_ACCENT": "#000000"})


def test_theme_css_is_public_and_follows_config(tmp_path: Path) -> None:
    cfg = WebConfig(db_path=tmp_path / "a.db", password="x" * 12, theme=Theme("#22d3ee"))
    client = TestClient(create_app(cfg))
    r = client.get("/theme.css")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/css")
    assert "--accent: #22d3ee;" in r.text
    assert '<link rel="stylesheet" href="/theme.css">' in client.get("/login").text


def test_stylesheet_is_dark_only() -> None:
    css = CSS.read_text()
    assert "prefers-color-scheme" not in css and "color-scheme: dark" in css


@pytest.mark.parametrize(
    ("fg", "bg"),
    [
        ("text", "bg"), ("text", "surface"), ("text-2", "surface"), ("muted", "surface"),
        ("muted", "surface-2"), ("accent", "surface"), ("on-accent", "accent"),
        ("ok-text", "ok-tint"), ("danger", "surface"),
        ("sev-critical-fg", "sev-critical-bg"), ("sev-high-fg", "sev-high-bg"),
        ("sev-medium-fg", "sev-medium-bg"), ("sev-low-fg", "sev-low-bg"),
        ("sev-info-fg", "sev-info-bg"),
        ("trust-known-fg", "trust-known-bg"), ("trust-iot-fg", "trust-iot-bg"),
        ("trust-guest-fg", "trust-guest-bg"), ("trust-unknown-fg", "trust-unknown-bg"),
        ("trust-company-fg", "trust-company-bg"), ("ai-fg", "ai-bg"), ("ai-accent", "ai-bg"),
    ],
)  # fmt: skip
def test_token_contrast_meets_wcag_aa(fg: str, bg: str) -> None:
    tokens = dict(re.findall(r"--([\w-]+):\s*(#[0-9a-f]{6})", CSS.read_text()))
    assert contrast(tokens[fg], tokens[bg]) >= MIN_CONTRAST


def test_fonts_are_local_with_license(tmp_path: Path) -> None:
    client = TestClient(create_app(WebConfig(db_path=tmp_path / "a.db", password="x" * 12)))
    css = CSS.read_text()
    for name in ("Geist-Variable.woff2", "GeistMono-Variable.woff2"):
        assert f'url("fonts/{name}")' in css
        r = client.get(f"/static/fonts/{name}")
        assert r.status_code == 200 and r.content[:4] == b"wOF2"
        assert r.headers["content-type"] == "font/woff2"
    assert "SIL Open Font License" in (CSS.parent / "fonts/OFL.txt").read_text()
    assert "http" not in re.sub(r"/\*.*?\*/", "", css, flags=re.S)  # keine externen Quellen
