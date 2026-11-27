# ruff: noqa: E501 – Schlüssel sind die vollständigen deutschen Texte
"""Englische Übersetzung der Oberfläche (#29). Schlüssel = deutscher Text (siehe aluco.i18n).

Neue Texte hier ergänzen; ``tests/test_i18n.py`` meldet fehlende und überzählige Einträge.
"""

EN: dict[str, str] = {
    # --- Datum und Zeit ---------------------------------------------------------------
    "%d.%m. %H:%M": "%b %d, %H:%M",
    "%d.%m.%Y": "%Y-%m-%d",
    "%d.%m.%Y %H:%M": "%Y-%m-%d %H:%M",
    "< 1 Min.": "< 1 min",
    "{n} Min.": "{n} min",
    "{n} Std.": "{n} h",
    "{n} Tage": "{n} days",
    "7 Tage": "7 days",
    "gerade eben": "just now",
    "vor {n} Min.": "{n} min ago",
    "vor {n} Std.": "{n} h ago",
    "gestern {time}": "yesterday {time}",
    "heute": "today",
    "Mo": "Mon",
    "Di": "Tue",
    "Mi": "Wed",
    "Do": "Thu",
    "Fr": "Fri",
    "Sa": "Sat",
    "So": "Sun",
    "seit {when}": "since {when}",
    "{n}× seit {when}": "{n}× since {when}",
    "{n}× an/ab seit {when}": "{n}× on/off since {when}",
    # --- Allgemein, Navigation ------------------------------------------------------
    "Hausradar für dein Netz": "Home radar for your network",
    "Hauptnavigation": "Main navigation",
    "Übersicht": "Overview",
    "Vorfälle": "Incidents",
    "Geräte": "Devices",
    "Gerät": "Device",
    "Regeln": "Rules",
    "Gerät, IP oder MAC suchen": "Search device, IP or MAC",
    "Geräte suchen": "Search devices",
    "Abmelden": "Sign out",
    "Anmelden": "Sign in",
    "Passwort": "Password",
    "Passwort falsch.": "Wrong password.",
    "Zu viele Versuche. Bitte später erneut.": "Too many attempts. Please try again later.",
    "{n} offen": "{n} open",
    "Alle": "All",
    "Alles": "Everything",
    "alle": "all",
    "Offen": "Open",
    "Ignoriert": "Ignored",
    "Erledigt": "Resolved",
    "System": "System",
    "Zeitraum": "Period",
    "Notiz": "Note",
    "Name": "Name",
    "Speichern": "Save",
    "Gespeichert.": "Saved.",
    "Keine.": "None.",
    "keine": "none",
    "Noch keine.": "None yet.",
    "Noch keine Daten.": "No data yet.",
    "Noch keine Ereignisse.": "No events yet.",
    "unbekannt": "unknown",
    "ok": "ok",
    "online": "online",
    "offline": "offline",
    "{n} online": "{n} online",
    "{n} offline": "{n} offline",
    "an": "on",
    "aus": "off",
    "lokal": "local",
    "neu": "new",
    "auto": "auto",
    # --- Schweregrad, Status, Aktionen, Stufen -------------------------------------
    "Info": "Info",
    "niedrig": "low",
    "mittel": "medium",
    "hoch": "high",
    "kritisch": "critical",
    "in Prüfung": "investigating",
    "ignoriert": "ignored",
    "getrennt": "disconnected",
    "erledigt": "resolved",
    "Prüfen": "Investigate",
    "Ignorieren": "Ignore",
    "Wieder öffnen": "Reopen",
    "bekannt": "known",
    "Bekannt": "Known",
    "Unbekannt": "Unknown",
    "IoT": "IoT",
    "Gast": "Guest",
    "Firma": "Company",
    # --- KI ---------------------------------------------------------------------------
    "harmlos": "harmless",
    "beobachten": "keep an eye on",
    "verdächtig": "suspicious",
    "als erledigt markieren": "mark as resolved",
    "ignorieren": "ignore",
    "genauer prüfen": "take a closer look",
    "sperren (sobald die Firewall eingebunden ist)": "block (once the firewall is connected)",
    "KI-Einschätzung": "AI assessment",
    "KI-Einschätzung anfordern": "Request AI assessment",
    "Neu bewerten": "Assess again",
    "Noch keine Einschätzung.": "No assessment yet.",
    "Risiko {risk} · Empfehlung: {action}": "Risk {risk} · Recommendation: {action}",
    "Vorschlag, keine Entscheidung": "Suggestion, not a decision",
    "Gesendet werden nur Regel, Stufe, Hersteller und ggf. die Domain – kein Name, keine IP/MAC.": (
        "Only the rule, trust level, vendor and, if relevant, the domain are sent – "
        "no name, no IP/MAC."
    ),
    "KI-Vorbewertung ist nicht aktiviert": "AI pre-assessment is not enabled",
    "Firmengeräte werden nicht von der KI bewertet.": "Company devices are never assessed by the AI.",
    # --- Regeln -----------------------------------------------------------------------
    "Neues Gerät": "New device",
    "Neue Domain (IoT)": "New domain (IoT)",
    "Schad-Domain": "Malicious domain",
    "Neu registrierte Domain": "Newly registered domain",
    "Laptop: neuer offener Port": "Laptop: new open port",
    "Laptop: neuer Autostart": "Laptop: new autostart",
    "Laptop: Fern-Anmeldung": "Laptop: remote login",
    "Laptop: Sicherheitsgrundlage aus": "Laptop: security setting off",
    # --- Übersicht ----------------------------------------------------------------------
    "Lagebild": "Status",
    "Alles ruhig – keine offenen Vorfälle": "All quiet – no open incidents",
    "{n} Vorfall braucht deine Aufmerksamkeit": "{n} incident needs your attention",
    "{n} Vorfälle brauchen deine Aufmerksamkeit": "{n} incidents need your attention",
    "Seit deinem letzten Besuch ({when}): {what}": "Since your last visit ({when}): {what}",
    "nichts Neues": "nothing new",
    "Willkommen. Hier siehst du ab jetzt, was sich seit deinem letzten Besuch getan hat.": (
        "Welcome. From now on you will see here what has happened since your last visit."
    ),
    "{n} neuer Vorfall": "{n} new incident",
    "{n} neue Vorfälle": "{n} new incidents",
    "{n} × offline": "{n} × offline",
    "{n} × online": "{n} × online",
    "{n} Meldung zu Datenquellen": "{n} data source message",
    "{n} Meldungen zu Datenquellen": "{n} data source messages",
    "Vorfälle prüfen": "Review incidents",
    "Kennzahlen": "Key figures",
    "Geräte online": "Devices online",
    "von {n}": "of {n}",
    "Offene Vorfälle": "Open incidents",
    "DNS-Anfragen (24 h)": "DNS queries (24 h)",
    "{n} blockiert ({pct} %)": "{n} blocked ({pct} %)",
    "ggü. Vortag": "vs. previous day",
    "Datenquellen": "Data sources",
    "{n} gestört": "{n} failing",
    "Letzter Lauf: {when}": "Last run: {when}",
    "noch keiner": "none yet",
    "Datenquelle nicht erreichbar": "Data source unreachable",
    "DNS-Aktivität": "DNS activity",
    "erlaubt": "allowed",
    "blockiert": "blocked",
    "Spitze: {peak}. Mit der Maus über einen Balken fahren für Details.": (
        "Peak: {peak}. Hover over a bar for details."
    ),
    "{label} ({n} Anfragen)": "{label} ({n} queries)",
    "{label}: {total} Anfragen, {blocked} blockiert": "{label}: {total} queries, {blocked} blocked",
    "Balkendiagramm: {total} Anfragen, davon {blocked} blockiert": (
        "Bar chart: {total} queries, {blocked} of them blocked"
    ),
    "Noch keine DNS-Daten in diesem Zeitraum.": "No DNS data for this period yet.",
    "Chronik": "Timeline",
    "Chronik filtern": "Filter timeline",
    "Aktivste Geräte": "Most active devices",
    "Meistblockiert": "Most blocked",
    "Nichts blockiert.": "Nothing blocked.",
    # --- Wochenbericht ------------------------------------------------------------------
    "Wochenbericht": "Weekly report",
    "Ruhige Woche – alles normal": "Quiet week – all normal",
    "{n} Auffälligkeit": "{n} finding",
    "{n} Auffälligkeiten": "{n} findings",
    "0 Auffälligkeiten": "0 findings",
    "{n} Datenquelle gestört": "{n} data source failing",
    "{n} Datenquellen gestört": "{n} data sources failing",
    "{n} neues Gerät": "{n} new device",
    "{n} neue Geräte": "{n} new devices",
    "{n} neuer Vorfall ({detail})": "{n} new incident ({detail})",
    "{n} neue Vorfälle ({detail})": "{n} new incidents ({detail})",
    "Entschieden: {list}": "Decided: {list}",
    "Offen: {n}": "Open: {n}",
    "Nichts offen": "Nothing open",
    "Vom Internet getrennt: {n} Gerät(e)": "Cut off from the internet: {n} device(s)",
    "DNS: {total} Anfragen, {pct} % blockiert": "DNS: {total} queries, {pct} % blocked",
    "Laptops: {reporting} von {total} melden sich": "Laptops: {reporting} of {total} reporting",
    "{n} Sicherheitsgrundlage(n) aus": "{n} security setting(s) off",
    "Länger als 30 Min. ausgefallen: {list}": "Down for more than 30 min: {list}",
    "Details im Dashboard.": "Details in the dashboard.",
    # --- Vorfälle -----------------------------------------------------------------------
    "Nach Schwere sortiert. Ein Klick auf einen Vorfall zeigt, warum er auffällig ist.": (
        "Sorted by severity. Click an incident to see why it stands out."
    ),
    "Status filtern": "Filter by status",
    "Nichts in dieser Ansicht": "Nothing in this view",
    "Alles ruhig. Aluco meldet sich, sobald etwas auffällt.": (
        "All quiet. Aluco will let you know as soon as something stands out."
    ),
    "Warum auffällig": "Why it stands out",
    "Gerät ansehen": "View device",
    "z. B. Besuch, Gastgerät": "e.g. visitor, guest device",
    "Trennen": "Disconnect",
    "{label} ({ip}) wirklich vom Internet trennen? Freigeben geht im Gerätedetail.": (
        "Really cut {label} ({ip}) off from the internet? You can release it on the device page."
    ),
    "Schutzliste oder Firmengerät – wird nie getrennt": (
        "Protected list or company device – never disconnected"
    ),
    "Braucht die Firewall (Stufe 1)": "Needs the firewall (stage 1)",
    "Unbekannter Status": "Unknown status",
    "Trennen muss bestätigt werden": "Disconnecting must be confirmed",
    "Trennen fehlgeschlagen: {error}": "Disconnecting failed: {error}",
    "Vorfall nicht gefunden": "Incident not found",
    "Herkunft der Anfrage ungültig": "Invalid request origin",
    # Erklärungen
    "MAC-Adresse war bisher nicht im Inventar": "MAC address was not in the inventory before",
    "Private (zufällige) MAC-Adresse – typisch für Handys und Gastgeräte": (
        "Private (randomized) MAC address – typical for phones and guest devices"
    ),
    "Hersteller: {vendor}": "Vendor: {vendor}",
    "Hersteller unbekannt": "Vendor unknown",
    "Hostname: {name}": "Hostname: {name}",
    "IP-Adresse: {ip}": "IP address: {ip}",
    "Domain {domain} von diesem Gerät noch nie angefragt": (
        "Domain {domain} never queried by this device before"
    ),
    "IoT-Gerät: verhält sich normalerweise vorhersehbar, Lernphase abgeschlossen": (
        "IoT device: normally behaves predictably, learning phase completed"
    ),
    "Angefragt: {query}": "Queried: {query}",
    "{domain} steht auf der Bedrohungsliste „{list}“": "{domain} is on the threat list “{list}”",
    "AdGuard hat die Anfrage blockiert – der Versuch deutet trotzdem auf Schadsoftware oder einen Phishing-Link hin": (
        "AdGuard blocked the query – the attempt still points to malware or a phishing link"
    ),
    "Die Anfrage wurde NICHT blockiert – Domain in AdGuard sperren": (
        "The query was NOT blocked – block the domain in AdGuard"
    ),
    "{domain} wurde in den letzten 14 Tagen registriert": (
        "{domain} was registered within the last 14 days"
    ),
    "Neue Domains nutzen Betrüger gern für Phishing und Schadsoftware – viele sind aber harmlos. Kennst du die Seite nicht, Domain in AdGuard sperren.": (
        "Scammers like new domains for phishing and malware – but many are harmless. "
        "If you don't know the site, block the domain in AdGuard."
    ),
    "AdGuard hat die Anfrage bereits blockiert": "AdGuard already blocked the query",
    "{program} nimmt Verbindungen auf Port {port}/{protocol} an – das war vorher nicht so": (
        "{program} accepts connections on port {port}/{protocol} – it did not before"
    ),
    "Programm: {path}": "Program: {path}",
    "Prüfen, ob du das Programm kennst und der Port nötig ist": (
        "Check whether you know the program and need the port"
    ),
    "Neuer Eintrag startet automatisch: {entry}": "New entry starts automatically: {entry}",
    "Autostart ist ein typischer Weg, wie sich Schadsoftware festsetzt": (
        "Autostart is a typical way for malware to persist"
    ),
    "Anmeldung von {host} als {user}": "Login from {host} as {user}",
    "Fern-Anmeldungen (z. B. SSH) sind auf privaten Laptops selten": (
        "Remote logins (e.g. SSH) are rare on private laptops"
    ),
    "Eine Sicherheitsgrundlage ist ausgeschaltet.": "A basic security setting is turned off.",
    "Wird automatisch erledigt, sobald der Agent sie wieder als an meldet": (
        "Resolved automatically as soon as the agent reports it back on"
    ),
    "{n}× aufgetreten": "occurred {n}×",
    # --- Geräte -------------------------------------------------------------------------
    "{total} Geräte · {online} online · {offline} offline. Ein Klick öffnet Verlauf, Domains und Einstellungen.": (
        "{total} devices · {online} online · {offline} offline. "
        "Click one for history, domains and settings."
    ),
    "Name, IP, MAC oder Hersteller": "Name, IP, MAC or vendor",
    "Geräte durchsuchen": "Search devices",
    "Nach Stufe filtern": "Filter by trust level",
    "Laptop-Agent (osquery) aktiv": "Laptop agent (osquery) active",
    "Agent": "Agent",
    "Getrennt – kein Internet": "Disconnected – no internet",
    "Nur passiv beobachtet – keine Aktivitätsdaten": "Observed passively only – no activity data",
    "DNS-Aktivität der letzten 24 Stunden": "DNS activity over the last 24 hours",
    "{n} offener Vorfall": "{n} open incident",
    "{n} offene Vorfälle": "{n} open incidents",
    "Schutzliste – nie trennbar": "Protected – never disconnected",
    "Kein Gerät passt zur Suche.": "No device matches the search.",
    "Noch keine Geräte. Sie erscheinen nach dem ersten Lauf von Aluco.": (
        "No devices yet. They appear after Aluco's first run."
    ),
    # Gerätedetail
    "Zurück zu den Geräten": "Back to devices",
    "Firmengerät: {domains} gespeicherte Domains und {incidents} Vorfälle gelöscht – ab jetzt nur passive Beobachtung.": (
        "Company device: {domains} stored domains and {incidents} incidents deleted – "
        "passive observation only from now on."
    ),
    "Gerät wieder freigegeben.": "Device released.",
    "Getrennt seit {when}": "Disconnected since {when}",
    "IP {ip} ist in der Firewall gesperrt (kein Internet).": (
        "IP {ip} is blocked in the firewall (no internet)."
    ),
    "{label} wieder freigeben?": "Release {label}?",
    "Freigeben": "Release",
    "Freigeben fehlgeschlagen: {error}": "Releasing failed: {error}",
    "Keine Firewall eingerichtet": "No firewall configured",
    "Gerät nicht gefunden": "Device not found",
    "Ungültige MAC-Adresse": "Invalid MAC address",
    "Schutzliste": "Protected",
    "offline · zuletzt {when}": "offline · last seen {when}",
    "zuletzt gesehen {when}": "last seen {when}",
    "zuerst gesehen {date}": "first seen {date}",
    "Hostname": "Hostname",
    "Laptop": "Laptop",
    "Agent-Bericht {when}": "Agent report {when}",
    "Agent eingerichtet, noch kein Bericht": "Agent set up, no report yet",
    "FileVault": "FileVault",
    "Firewall": "Firewall",
    "Gatekeeper": "Gatekeeper",
    "Systemintegritätsschutz": "System Integrity Protection",
    "Offene Ports": "Open ports",
    "Keine nach außen offenen Ports.": "No ports open to the outside.",
    "Autostart": "Autostart",
    "Keine Autostart-Einträge außerhalb von macOS.": "No autostart entries outside of macOS.",
    "Anmeldungen": "Logins",
    "Fern-Anmeldung": "Remote login",
    "Aktivität": "Activity",
    "Firmengerät – Aluco speichert keine Domains und keine DNS-Statistik, sondern beobachtet nur, ob es online ist.": (
        "Company device – Aluco stores no domains and no DNS statistics, "
        "it only observes whether the device is online."
    ),
    "{total} DNS-Anfragen · {blocked} blockiert": "{total} DNS queries · {blocked} blocked",
    "Typisches Verhalten": "Typical behaviour",
    "aktiv {start}–{end} Uhr": "active {start}:00–{end}:00",
    "nachts ruhig": "quiet at night",
    "auch nachts aktiv": "also active at night",
    "{n} Hauptdomains": "{n} main domains",
    "Noch keine DNS-Daten von diesem Gerät.": "No DNS data from this device yet.",
    "Angefragte Domains": "Queried domains",
    "Domains filtern": "Filter domains",
    "nur neue (7 Tage)": "new only (7 days)",
    "Domain": "Domain",
    "Zuerst gesehen": "First seen",
    "Anfragen 7 T.": "Queries 7 d",
    "Keine neuen Domains in den letzten 7 Tagen.": "No new domains in the last 7 days.",
    "Einstellungen": "Settings",
    "z. B. Fernseher": "e.g. TV",
    "Vertrauensstufe": "Trust level",
    "„Firma“ löscht beim Speichern alle gespeicherten Domains und Verhaltens-Vorfälle dieses Geräts. Danach nur passive Beobachtung.": (
        "“Company” deletes all stored domains and behaviour incidents of this device on save. "
        "After that, passive observation only."
    ),
    "Auf die Schutzliste (nie trennbar)": "Add to protected list (never disconnected)",
    "Verlauf": "History",
    # --- Regel-Qualität -------------------------------------------------------------------
    "Regel-Qualität": "Rule quality",
    "Wie oft löst jede Regel aus, und was hast du daraus gemacht? Werden die Vorfälle einer Regel fast immer ignoriert, stumpft sie ab und gehört nachgeschärft.": (
        "How often does each rule fire, and what did you do about it? If a rule's incidents "
        "are almost always ignored, you stop paying attention – the rule needs tuning."
    ),
    "{n} Regel mit über {pct} % ignorierten Vorfällen": (
        "{n} rule with more than {pct} % ignored incidents"
    ),
    "{n} Regeln mit über {pct} % ignorierten Vorfällen": (
        "{n} rules with more than {pct} % ignored incidents"
    ),
    "prüfen, ob die Regel zu empfindlich ist oder Geräte besser eingestuft werden sollten (z. B. als IoT oder Gast).": (
        "check whether the rule is too sensitive or devices should be classified better "
        "(e.g. as IoT or guest)."
    ),
    "Regel": "Rule",
    "ausgelöst": "fired",
    "Ignorier-Quote": "Ignore rate",
    "Median vom Auftreten bis zur Entscheidung": "Median from occurrence to decision",
    "Zeit bis Entscheidung": "Time to decision",
    "abgestumpft?": "ignored too often?",
    "KI „verdächtig“, trotzdem ignoriert: {n}": "AI “suspicious”, ignored anyway: {n}",
    "KI „harmlos“, trotzdem getrennt: {n}": "AI “harmless”, disconnected anyway: {n}",
    "erledigt und erneut aufgetreten": "resolved and occurred again",
    "wenig Daten": "little data",
    "automatisch erledigt, zählt nicht zur Quote": "resolved automatically, not counted in the rate",
    "„ausgelöst“: neue Vorfälle im Zeitraum, „+n“: erledigt und erneut aufgetreten. Ignoriert, erledigt und getrennt zählen nur Entscheidungen von Hand; die Quote erscheint erst ab {n} Entscheidungen hervorgehoben.": (
        "“fired”: new incidents in the period, “+n”: resolved and occurred again. Ignored, "
        "resolved and disconnected count manual decisions only; the rate is highlighted "
        "from {n} decisions on."
    ),
    "Aufgezeichnet seit {date}.": "Recorded since {date}.",
    "Noch keine Vorfälle aufgezeichnet.": "No incidents recorded yet.",
    # --- Meldungen, Titel neuer Vorfälle und Ereignisse (Teil 2) -------------------------
    "Aluco: neuer Vorfall": "Aluco: new incident",
    "Schweregrad {severity}. Details im Dashboard.": "Severity {severity}. Details in the dashboard.",
    "KI: {verdict} – {summary}\nEmpfehlung: {action}": "AI: {verdict} – {summary}\nRecommendation: {action}",
    "Neues Gerät im Netz: {label}": "New device on the network: {label}",
    "{label} fragt neue Domain an: {domain}": "{label} queries a new domain: {domain}",
    "{label} fragt bekannte Schad-Domain an: {domain}": "{label} queries a known malicious domain: {domain}",
    "{label} fragt neu registrierte Domain an: {domain}": "{label} queries a newly registered domain: {domain}",
    "Neuer offener Port": "New open port",
    "Neuer Autostart-Eintrag": "New autostart entry",
    "Neue Anmeldung": "New login",
    "{label}: {name} ist aus": "{label}: {name} is off",
    "Die macOS-Firewall ist ausgeschaltet.": "The macOS firewall is turned off.",
    "Die Festplatte ist nicht verschlüsselt.": "The disk is not encrypted.",
    "Gatekeeper prüft Programme nicht mehr.": "Gatekeeper no longer checks programs.",
    "SIP ist ausgeschaltet.": "SIP is turned off.",
    "Inventar übernommen: {n} Gerät": "Inventory adopted: {n} device",
    "Inventar übernommen: {n} Geräte": "Inventory adopted: {n} devices",
    "Erster Lauf – vorhandene Geräte ohne Alarm übernommen": "First run – existing devices adopted without alerts",
    "{label} ist online": "{label} is online",
    "{label} ist offline": "{label} is offline",
    "Neuer Vorfall": "New incident",
    "Vorfall wieder geöffnet": "Incident reopened",
    "Vorfall {status}: {title}": "Incident {status}: {title}",
    "wieder geöffnet": "reopened",
    "Notiz: {note}": "Note: {note}",
    "{name} nicht erreichbar": "{name} unreachable",
    "{name} wieder erreichbar": "{name} reachable again",
    "Speicherplatz knapp": "Disk space low",
    "Speicherplatz wieder ausreichend": "Disk space sufficient again",
    "{label} über die Firewall getrennt": "{label} disconnected via the firewall",
    "IP {ip} im Quarantäne-Alias": "IP {ip} in the quarantine alias",
    "{label} wieder freigegeben": "{label} released",
    "Gerät ist nicht getrennt": "Device is not disconnected",
    "Gerät nicht im Inventar – Trennen nicht möglich": "Device not in inventory – cannot disconnect",
    "Vorfall ohne Gerät kann nicht getrennt werden": "An incident without a device cannot be disconnected",
    "{label} ist geschützt (Schutzliste oder Firmengerät) und wird nie getrennt": (
        "{label} is protected (protected list or company device) and is never disconnected"
    ),
    "{old} → {new} ist nicht erlaubt": "{old} → {new} is not allowed",
    # --- KI-Kontext: zeitlicher Abstand (Teil 3) ----------------------------------------
    "gleichzeitig": "at the same time",
    "{n} Min. vorher": "{n} min before",
    "{n} Min. danach": "{n} min after",
    "{n} Std. vorher": "{n} h before",
    "{n} Std. danach": "{n} h after",
    "{n} Tage vorher": "{n} days before",
    "{n} Tage danach": "{n} days after",
    "Die Daten enthalten Text, der wie eine Anweisung an die KI aussieht – Einschätzung nicht unter „beobachten“.": (
        "The data contains text that looks like an instruction to the AI – assessment kept at "
        "“keep an eye on” or above."
    ),
}
