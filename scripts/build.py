#!/usr/bin/env python3
"""Konvertiert die StevenBlack-hosts-Liste in Palo-Alto-EDL-Dateien.

Die eigentliche Konvertierung ist trivial: aus "0.0.0.0 tracker.example"
wird "tracker.example". Der Rest hier ist Hygiene (Validierung, Allowlist)
und die optionale eTLD+1-Variante fuer Firewalls mit knappem EDL-Limit.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HOSTS_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
OUT = ROOT / "public"

REPO_URL = "https://github.com/McMarius11/hosts2paloalto"
PAGES_URL = "https://mcmarius11.github.io/hosts2paloalto"

SB_REPO = "https://github.com/StevenBlack/hosts"

# Sektionen der gemergten Datei, die unter nicht-kommerziellen Lizenzen stehen.
# Steven dedupliziert beim Mergen, jede Domain landet in genau einer Sektion -
# ein Ausschluss ueber die Marker entfernt daher ein paar hundert Domains mehr
# als noetig (die auch in permissiven Listen stehen). Das ist der Preis dafuer,
# nicht alle 16 Originallisten einzeln ziehen zu muessen.
NC_SECTIONS = {"mvps.org", "someonewhocares.org"}

# Attribution ist bei CC BY / BY-SA / BY-NC-SA Pflicht und gehoert damit in
# jede ausgelieferte Datei, nicht nur in die README.
ATTRIBUTION = [
    "",
    "Quelle der Filterdaten:",
    f"  StevenBlack/hosts - {SB_REPO}",
    f"  {HOSTS_URL}",
    "",
    "Die Liste fuehrt mehrere kuratierte Quellen mit unterschiedlichen Lizenzen",
    "zusammen; die vollstaendige Uebersicht steht in Stevens Readme:",
    f"  {SB_REPO}#sources-of-hosts-data-unified-in-this-variant",
    "",
    "Der ueberwiegende Teil der Daten stammt aus KADhosts (CC BY-SA 4.0,",
    "https://kadantiscam.netlify.app/). Weiterverbreitung dieser Datei erfolgt",
    "unter denselben Bedingungen. Die Konvertierungs-Pipeline selbst steht",
    f"unter MIT: {REPO_URL}",
]

# Hostnamen, die PAN-OS als EDL-Eintrag akzeptiert. Bewusst streng: alles was
# hier durchfaellt, wuerde die Firewall beim Import ohnehin verwerfen und nur
# eine Warnung im System-Log erzeugen.
VALID = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")

# Diese Ziele stehen in jeder hosts-Datei als Null-Route-Marker und sind keine
# echten Blockziele.
NULL_TARGETS = {"0.0.0.0", "127.0.0.1", "::1", "::", "255.255.255.255"}


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "hosts2paloalto"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read().decode("utf-8", errors="replace")


def read_list(path: Path) -> list[str]:
    """Liest eine Datei mit einem Eintrag pro Zeile, ignoriert # und Leerzeilen."""
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            out.append(line)
    return out


def parse_hosts(text: str) -> tuple[set[str], set[str]]:
    """Der Kern: 0.0.0.0-Praefix weg, Hostname behalten.

    Liefert (alle Domains, Domains aus nicht-kommerziellen Sektionen). Die
    gemergte Datei markiert die Herkunft mit "# Start <Quelle>" / "# End".
    """
    domains: set[str] = set()
    nc: set[str] = set()
    section: str | None = None

    for raw in text.splitlines():
        stripped = raw.strip()
        start = re.match(r"^#\s*Start\s+(.+?)\s*$", stripped)
        if start:
            section = start.group(1)
            continue
        if re.match(r"^#\s*End\b", stripped):
            section = None
            continue

        line = stripped.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2 or parts[0] not in NULL_TARGETS:
            continue
        for host in parts[1:]:
            host = host.strip().lower().rstrip(".")
            # "localhost"-Zeilen und der Marker selbst sind keine Blockziele
            if host in NULL_TARGETS or host == "localhost" or not VALID.match(host):
                continue
            domains.add(host)
            if section in NC_SECTIONS:
                nc.add(host)
    return domains, nc


class PublicSuffixList:
    def __init__(self, text: str) -> None:
        self.rules: set[str] = set()
        self.exceptions: set[str] = set()
        self.wildcards: set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            if line.startswith("!"):
                self.exceptions.add(line[1:])
            elif line.startswith("*."):
                self.wildcards.add(line[2:])
            else:
                self.rules.add(line)

    def registrable(self, domain: str) -> str | None:
        """Liefert die registrierbare Domain (eTLD+1), oder None wenn `domain`
        selbst ein Public Suffix ist (z.B. "co.uk" oder "lovable.app")."""
        labels = domain.split(".")
        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            parent = ".".join(labels[i + 1:])
            if candidate in self.exceptions:
                return candidate
            if candidate in self.rules or (parent and parent in self.wildcards):
                return ".".join(labels[i - 1:]) if i > 0 else None
        return domain


def is_covered(domain: str, suffixes: set[str]) -> bool:
    """True, wenn `domain` gleich einem Eintrag ist oder darunter liegt."""
    labels = domain.split(".")
    for i in range(len(labels)):
        if ".".join(labels[i:]) in suffixes:
            return True
    return False


def render_index(built: str, files: list[tuple[str, int, str, str]]) -> str:
    """Landing Page fuer GitHub Pages. Ohne die waere der Pages-Root ein 404."""
    cards = "\n".join(
        f"""      <article class="card">
        <div class="card-top">
          <h3>{name}</h3>
          <span class="count">{format(count, ",d").replace(",", ".")}</span>
        </div>
        <p class="type">{edl_type}</p>
        <p class="desc">{desc}</p>
        <div class="url-row">
          <code id="u{i}">{PAGES_URL}/{name}</code>
          <button type="button" data-target="u{i}" aria-label="URL kopieren">kopieren</button>
        </div>
      </article>"""
        for i, (name, count, edl_type, desc) in enumerate(files)
    )
    return f"""<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>hosts2paloalto - StevenBlack-Blocklisten als PAN-OS EDL</title>
<meta name="description" content="Die StevenBlack-hosts-Liste als External Dynamic List fuer Palo Alto PAN-OS. Stuendlich aktualisiert.">
<style>
  :root {{
    --bg:#fbfbfa; --fg:#1a1a18; --muted:#6b6b66; --line:#e2e2dd;
    --card:#fff; --accent:#c2410c; --code:#f4f4f1;
  }}
  @media (prefers-color-scheme:dark) {{
    :root {{
      --bg:#16161a; --fg:#e8e8e3; --muted:#9a9a94; --line:#2c2c32;
      --card:#1d1d22; --accent:#fb923c; --code:#232329;
    }}
  }}
  * {{ box-sizing:border-box; }}
  body {{
    margin:0; background:var(--bg); color:var(--fg);
    font:16px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;
  }}
  .wrap {{ max-width:860px; margin:0 auto; padding:3rem 1.25rem 5rem; }}
  header {{ border-bottom:1px solid var(--line); padding-bottom:1.75rem; margin-bottom:2.5rem; }}
  h1 {{ margin:0 0 .4rem; font-size:1.9rem; letter-spacing:-.02em; }}
  h1 span {{ color:var(--accent); }}
  .sub {{ margin:0; color:var(--muted); }}
  .built {{ margin:1rem 0 0; font-size:.85rem; color:var(--muted); }}
  .built b {{ color:var(--fg); font-weight:600; }}
  h2 {{ font-size:1.15rem; margin:2.75rem 0 1rem; letter-spacing:-.01em; }}
  .card {{
    background:var(--card); border:1px solid var(--line); border-radius:10px;
    padding:1.1rem 1.2rem; margin-bottom:.9rem;
  }}
  .card-top {{ display:flex; justify-content:space-between; align-items:baseline; gap:1rem; }}
  .card h3 {{ margin:0; font-size:1rem; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
  .count {{ font-variant-numeric:tabular-nums; font-weight:600; color:var(--accent); white-space:nowrap; }}
  .type {{ margin:.35rem 0 0; font-size:.8rem; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); }}
  .desc {{ margin:.5rem 0 .9rem; font-size:.92rem; color:var(--muted); }}
  .url-row {{ display:flex; gap:.5rem; align-items:stretch; }}
  .url-row code {{
    flex:1; background:var(--code); border-radius:6px; padding:.5rem .65rem;
    font-size:.82rem; overflow-x:auto; white-space:nowrap; font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  }}
  .url-row button {{
    border:1px solid var(--line); background:var(--card); color:var(--fg);
    border-radius:6px; padding:.5rem .8rem; cursor:pointer; font-size:.82rem; white-space:nowrap;
  }}
  .url-row button:hover {{ border-color:var(--accent); color:var(--accent); }}
  pre {{
    background:var(--code); border-radius:8px; padding:.9rem 1rem;
    overflow-x:auto; font-size:.85rem; margin:.75rem 0;
  }}
  code {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
  p code, li code {{ background:var(--code); padding:.1rem .35rem; border-radius:4px; font-size:.88em; }}
  table {{ border-collapse:collapse; width:100%; font-size:.9rem; }}
  th,td {{ text-align:left; padding:.45rem .6rem; border-bottom:1px solid var(--line); }}
  th {{ font-size:.78rem; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); }}
  a {{ color:var(--accent); }}
  .note {{
    border-left:3px solid var(--accent); background:var(--card);
    padding:.85rem 1rem; border-radius:0 8px 8px 0; font-size:.92rem; margin:1rem 0;
  }}
  .scroll {{ overflow-x:auto; }}
  footer {{ margin-top:3.5rem; padding-top:1.5rem; border-top:1px solid var(--line); font-size:.85rem; color:var(--muted); }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>hosts2<span>paloalto</span></h1>
    <p class="sub">Die StevenBlack-Blocklisten als External Dynamic List fuer Palo Alto PAN-OS.</p>
    <p class="built">Zuletzt gebaut: <b>{built}</b> &middot; stuendlich geprueft, neu gebaut nur bei Aenderung upstream</p>
  </header>

  <h2>Listen</h2>
{cards}

  <h2>Welche nehmen?</h2>
  <p>Zuerst das echte Limit deiner Firewall ermitteln - das ist die einzige verbindliche Quelle:</p>
  <pre><code>show system state | match max-edl</code></pre>
  <p>Reicht das Limit fuer die volle Liste, nimm <code>domains.txt</code>. Sonst eine der
  zusammengefassten Varianten.</p>
  <div class="note">
    <b>Wichtig:</b> Die EDL-Limits gelten <b>pro System ueber alle Listen hinweg</b>, nicht pro Liste.
    Aufsplitten bringt keine zusaetzliche Kapazitaet. Eintraege zaehlen nur, wenn die EDL in einer
    Policy referenziert wird. Bei einer <b>Domain-EDL mit Subdomain-Matching</b> zaehlt jeder
    Eintrag doppelt.
  </div>

  <h2>Einrichtung</h2>
  <p><code>Objects &gt; External Dynamic Lists &gt; Add</code> - Type auf <code>URL List</code>
  bzw. <code>Domain List</code>, eine URL von oben als Source, Check for updates auf
  <code>Hourly</code>. Mit <em>Test Source URL</em> pruefen, dann committen.</p>
  <pre><code>request system external-list refresh name &lt;EDL-Name&gt;
show system external-list name &lt;EDL-Name&gt;</code></pre>
  <p>Details und die Durchsetzung per URL-Filtering-Profil bzw. Anti-Spyware-DNS-Sinkhole
  stehen in der <a href="{REPO_URL}#einrichtung-in-pan-os" rel="noopener">README</a>.</p>

  <h2>Quellen</h2>
  <p>Dieses Projekt filtert nichts selbst - es konvertiert nur. Die eigentliche Arbeit steckt in
  <a href="{SB_REPO}" rel="noopener">StevenBlack/hosts</a>. Verarbeitet wird ausschliesslich
  die Basis-Variante:</p>
  <pre><code>{HOSTS_URL}</code></pre>
  <p>Welche kuratierten Listen dort zusammenlaufen, ist
  <a href="{SB_REPO}#sources-of-hosts-data-unified-in-this-variant" rel="noopener">in Stevens
  Readme</a> samt Lizenzen dokumentiert. Das Zusammenfassen auf die registrierbare Domain nutzt
  die <a href="https://publicsuffix.org/" rel="noopener">Public Suffix List</a> (Mozilla, MPL 2.0).</p>
  <div class="note">
    Unter den zusammengefuehrten Quellen sind zwei <b>nicht-kommerzielle</b> Lizenzen
    (MVPS: CC BY-NC-SA 4.0, someonewhocares: non-commercial with attribution). Die gelten fuer
    die Daten unabhaengig davon, ueber wie viele Zwischenschritte man sie bezieht - beim
    geschaeftlichen Einsatz also kurz pruefen.
  </div>

  <footer>
    Konvertierungs-Pipeline: MIT &middot;
    <a href="{REPO_URL}" rel="noopener">Quellcode auf GitHub</a> &middot;
    <a href="{PAGES_URL}/stats.json">stats.json</a>
  </footer>
</div>
<script>
document.querySelectorAll('.url-row button').forEach(function (b) {{
  b.addEventListener('click', function () {{
    var el = document.getElementById(b.dataset.target);
    navigator.clipboard.writeText(el.textContent).then(function () {{
      var old = b.textContent;
      b.textContent = 'kopiert';
      setTimeout(function () {{ b.textContent = old; }}, 1200);
    }});
  }});
}});
</script>
</body>
</html>
"""


def write(path: Path, header: list[str], entries: list[str]) -> int:
    """Schreibt eine EDL-Datei.

    PAN-OS ist bei der Formatierung empfindlich: keine Leerzeilen, kein
    Trailing Whitespace. Leere Header-Zeilen werden daher zu einem nackten
    "#" statt "# ", und die Eintraege stehen ohne Leerzeile dazwischen.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# {h}".rstrip() for h in header]
    lines += [e.strip() for e in entries if e.strip()]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(entries)


def main() -> int:
    built = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"[*] hole {HOSTS_URL}")
    domains, nc_domains = parse_hosts(fetch(HOSTS_URL))
    print(f"    {len(domains)} eindeutige Domains ({len(nc_domains)} aus NC-Quellen)")

    allowlist = set(read_list(DATA / "allowlist.txt"))
    no_collapse = set(read_list(DATA / "no-collapse.txt"))

    kept = sorted(d for d in domains if not is_covered(d, allowlist))
    removed = len(domains) - len(kept)
    print(f"    {removed} durch Allowlist entfernt -> {len(kept)} Eintraege")

    commercial = sorted(d for d in kept if d not in nc_domains)
    print(f"    ohne NC-Quellen: {len(commercial)} Eintraege")

    print(f"[*] hole {PSL_URL}")
    psl = PublicSuffixList(fetch(PSL_URL))

    # eTLD+1-Variante: fasst ads1.tracker.com / ads2.tracker.com zu tracker.com
    # zusammen. Unter den no-collapse-Suffixen (Shared Infrastructure wie
    # amazonaws.com) bleiben die Originaldomains stehen, sonst wuerde man sich
    # halbe CDNs wegblocken.
    collapsed: set[str] = set()
    for d in kept:
        if is_covered(d, no_collapse):
            collapsed.add(d)
            continue
        reg = psl.registrable(d)
        collapsed.add(reg if reg else d)
    collapsed = {d for d in sorted(collapsed) if not is_covered(d, allowlist)}
    collapsed_sorted = sorted(collapsed)
    print(f"    eTLD+1: {len(collapsed_sorted)} Eintraege")

    def head(*lines: str) -> list[str]:
        return ["hosts2paloalto", f"Erzeugt: {built}", *lines] + ATTRIBUTION

    n_flat = write(
        OUT / "domains.txt",
        head(f"Typ: PAN-OS EDL (Domain oder URL) | {len(kept)} Eintraege",
             "1:1-Konvertierung der hosts-Datei, exaktes Host-Matching."),
        kept,
    )
    n_coll = write(
        OUT / "domains-collapsed.txt",
        head(f"Typ: PAN-OS Domain-EDL | {len(collapsed_sorted)} Eintraege",
             "Auf eTLD+1 zusammengefasst. Subdomain-Matching aktivieren!"),
        collapsed_sorted,
    )
    n_url = write(
        OUT / "url-wildcard.txt",
        head(f"Typ: PAN-OS URL-EDL | {len(collapsed_sorted)} Eintraege",
             "Wildcard-Syntax, deckt alle Subdomains ab."),
        [f"*.{d}/" for d in collapsed_sorted],
    )
    n_comm = write(
        OUT / "domains-no-nc.txt",
        head(f"Typ: PAN-OS EDL (Domain oder URL) | {len(commercial)} Eintraege",
             "Ohne die Sektionen mvps.org und someonewhocares.org, deren Lizenzen",
             "die kommerzielle Nutzung ausschliessen. Verbleibende Daten stehen",
             "weiterhin ueberwiegend unter CC BY-SA 4.0 (ShareAlike)."),
        commercial,
    )

    stats = {
        "built": built,
        "source": HOSTS_URL,
        "parsed_domains": len(domains),
        "allowlisted_removed": removed,
        "non_commercial_excluded": len(kept) - len(commercial),
        "files": {
            "domains.txt": n_flat,
            "domains-collapsed.txt": n_coll,
            "url-wildcard.txt": n_url,
            "domains-no-nc.txt": n_comm,
        },
    }
    (OUT / "stats.json").write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")

    (OUT / "index.html").write_text(
        render_index(built, [
            ("domains.txt", n_flat, "Domain- oder URL-EDL",
             "1:1-Konvertierung der hosts-Datei. Exaktes Host-Matching, keine Wildcards. Der Standardfall."),
            ("domains-collapsed.txt", n_coll, "Domain-EDL",
             "Auf die registrierbare Domain zusammengefasst - rund halb so gross. Subdomain-Matching aktivieren."),
            ("url-wildcard.txt", n_url, "URL-EDL",
             "Wie oben, aber in Wildcard-Syntax fuer URL-EDLs. Deckt alle Subdomains ab."),
            ("domains-no-nc.txt", n_comm, "Domain- oder URL-EDL",
             "Wie domains.txt, aber ohne die Quellen mit nicht-kommerzieller Lizenz. "
             "Fuer den Einsatz im geschaeftlichen Umfeld."),
        ]),
        encoding="utf-8",
    )

    print(f"[+] index.html")
    print(f"[+] domains-no-nc.txt      {n_comm}")
    print(f"[+] domains.txt            {n_flat}")
    print(f"[+] domains-collapsed.txt  {n_coll}")
    print(f"[+] url-wildcard.txt       {n_url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
