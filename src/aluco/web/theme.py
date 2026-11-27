"""Akzentfarbe des Dashboards aus der Konfiguration (Design V2, nur dunkles Thema).

Die CSP erlaubt keine Inline-Styles. Deshalb liefert ``/theme.css`` die Akzentfarbe und
ihre abgeleiteten Töne als kleine Stylesheet-Datei aus – nach ``aluco.css`` geladen, damit
sie die Standardwerte dort überschreibt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

DEFAULT_ACCENT = "#10b981"  # Grün (Design V2)
SURFACE = "#1b1b24"  # Kartenfläche – der Akzent muss darauf lesbar sein
BACKGROUND = "#13131a"
MIN_CONTRAST = 4.5  # WCAG AA für normalen Text (Links sind Akzent auf Fläche)

_HEX = re.compile(r"^#?([0-9a-fA-F]{6})$")


class ThemeError(ValueError):
    pass


def _rgb(hex_color: str) -> tuple[int, int, int]:
    h = hex_color.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _hex(rgb: tuple[float, float, float]) -> str:
    return "#" + "".join(f"{round(max(0, min(255, c))):02x}" for c in rgb)


def _mix(a: str, b: str, weight_a: float) -> str:
    ra, rb = _rgb(a), _rgb(b)
    return _hex(tuple(x * weight_a + y * (1 - weight_a) for x, y in zip(ra, rb, strict=True)))


def _luminance(hex_color: str) -> float:
    def channel(c: int) -> float:
        s = c / 255
        return s / 12.92 if s <= 0.03928 else ((s + 0.055) / 1.055) ** 2.4

    r, g, b = (channel(c) for c in _rgb(hex_color))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    hi, lo = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


@dataclass(frozen=True, slots=True)
class Theme:
    accent: str = DEFAULT_ACCENT

    @classmethod
    def parse(cls, raw: str | None) -> Theme:
        """``ALUCO_UI_ACCENT``: Hex-Farbe (``#7ea2f7`` oder ``7ea2f7``), leer = Standard."""
        value = (raw or "").strip()
        if not value:
            return cls()
        m = _HEX.match(value)
        if not m:
            raise ThemeError("ALUCO_UI_ACCENT muss eine Hex-Farbe sein, z. B. #7ea2f7")
        accent = "#" + m.group(1).lower()
        ratio = contrast(accent, SURFACE)
        if ratio < MIN_CONTRAST:
            raise ThemeError(
                f"ALUCO_UI_ACCENT {accent} ist auf dunklem Grund zu schwach "
                f"(Kontrast {ratio:.1f}:1, nötig {MIN_CONTRAST}:1) – hellere Farbe wählen"
            )
        return cls(accent)

    @property
    def strong(self) -> str:
        """Hover/aktiv: heller als der Akzent."""
        return _mix(self.accent, "#ffffff", 0.6)

    @property
    def tint(self) -> str:
        """Hintergrund für Hervorhebungen (aktive Navigation, Kürzel)."""
        return _mix(self.accent, BACKGROUND, 0.2)

    @property
    def on_accent(self) -> str:
        """Textfarbe auf vollem Akzent (Buttons) – dunkel oder hell, je nach Kontrast."""
        dark, light = "#0b0b10", "#ffffff"
        return dark if contrast(self.accent, dark) >= contrast(self.accent, light) else light

    def css(self) -> str:
        return (
            ":root {\n"
            f"  --accent: {self.accent};\n"
            f"  --accent-strong: {self.strong};\n"
            f"  --accent-tint: {self.tint};\n"
            f"  --on-accent: {self.on_accent};\n"
            "}\n"
        )
