"""Sprache der Oberfläche (#29): Deutsch (Standard) oder Englisch.

Wie gettext, aber ohne Werkzeugkette: Der **deutsche Text ist der Schlüssel**, die englische
Übersetzung steht in ``aluco.locale_en.EN``. Fehlt eine Übersetzung, erscheint der deutsche
Text – ein Test stellt sicher, dass das nicht passiert.

    _("Geräte")                             → "Devices"
    _("{n} offen", n=3)                     → "3 open"
    ngettext("{n} Gerät", "{n} Geräte", n)  → "1 device" / "2 devices"

Die Sprache gilt für den ganzen Prozess (``ALUCO_LANGUAGE``) und wird beim Start gesetzt.
Schon gespeicherte Texte (Titel von Vorfällen und Ereignissen) bleiben in der Sprache,
in der sie entstanden sind.
"""

from __future__ import annotations

from typing import Any

LANGUAGES = ("de", "en")
DEFAULT = "de"

_language = DEFAULT


class LanguageError(ValueError):
    pass


def parse_language(raw: str | None) -> str:
    value = (raw or DEFAULT).strip().lower()[:2]
    if value not in LANGUAGES:
        raise LanguageError(f"unbekannte Sprache {raw!r} (de oder en)")
    return value


def set_language(lang: str) -> None:
    global _language
    _language = parse_language(lang)


def get_language() -> str:
    return _language


def _lookup(text: str) -> str:
    if _language == "en":
        from aluco.locale_en import EN

        return EN.get(text, text)
    return text


def _(text: str, /, **values: Any) -> str:
    out = _lookup(text)
    return out.format(**values) if values else out


def ngettext(singular: str, plural: str, n: int, /, **values: Any) -> str:
    return _(singular if n == 1 else plural, n=n, **values)


def fmt_int(n: int) -> str:
    """1234567 → '1.234.567' (de) bzw. '1,234,567' (en)."""
    s = f"{n:,}"
    return s if _language == "en" else s.replace(",", ".")


def fmt_dec(x: float, digits: int = 1) -> str:
    """0.5 → '0,5' (de) bzw. '0.5' (en)."""
    s = f"{x:.{digits}f}"
    return s if _language == "en" else s.replace(".", ",")
