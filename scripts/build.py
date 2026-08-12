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


def parse_hosts(text: str) -> set[str]:
    """Der Kern: 0.0.0.0-Praefix weg, Hostname behalten."""
    domains: set[str] = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
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
    return domains


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


def write(path: Path, header: list[str], entries: list[str]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(f"# {h}" for h in header)
    body += "\n" + "\n".join(entries) + "\n"
    path.write_text(body, encoding="utf-8")
    return len(entries)


def main() -> int:
    built = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"[*] hole {HOSTS_URL}")
    domains = parse_hosts(fetch(HOSTS_URL))
    print(f"    {len(domains)} eindeutige Domains")

    allowlist = set(read_list(DATA / "allowlist.txt"))
    no_collapse = set(read_list(DATA / "no-collapse.txt"))

    kept = sorted(d for d in domains if not is_covered(d, allowlist))
    removed = len(domains) - len(kept)
    print(f"    {removed} durch Allowlist entfernt -> {len(kept)} Eintraege")

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

    src = f"Quelle: {HOSTS_URL}"
    common = [f"Erzeugt: {built}", src, "Repo: https://github.com/McMarius11/hosts2paloalto"]

    n_flat = write(
        OUT / "domains.txt",
        common + [f"Typ: PAN-OS EDL (Domain oder URL) | {len(kept)} Eintraege",
                  "1:1-Konvertierung der hosts-Datei, exaktes Host-Matching."],
        kept,
    )
    n_coll = write(
        OUT / "domains-collapsed.txt",
        common + [f"Typ: PAN-OS Domain-EDL | {len(collapsed_sorted)} Eintraege",
                  "Auf eTLD+1 zusammengefasst. Subdomain-Matching aktivieren!"],
        collapsed_sorted,
    )
    n_url = write(
        OUT / "url-wildcard.txt",
        common + [f"Typ: PAN-OS URL-EDL | {len(collapsed_sorted)} Eintraege",
                  "Wildcard-Syntax, deckt alle Subdomains ab."],
        [f"*.{d}/" for d in collapsed_sorted],
    )

    stats = {
        "built": built,
        "source": HOSTS_URL,
        "parsed_domains": len(domains),
        "allowlisted_removed": removed,
        "files": {
            "domains.txt": n_flat,
            "domains-collapsed.txt": n_coll,
            "url-wildcard.txt": n_url,
        },
    }
    (OUT / "stats.json").write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")

    print(f"[+] domains.txt            {n_flat}")
    print(f"[+] domains-collapsed.txt  {n_coll}")
    print(f"[+] url-wildcard.txt       {n_url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
