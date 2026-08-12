# hosts2paloalto

Konvertiert die [StevenBlack-hosts-Liste](https://github.com/StevenBlack/hosts) in
**External Dynamic Lists (EDL)** für PAN-OS. Der Build läuft stündlich per GitHub
Actions und baut nur neu, wenn Steven upstream tatsächlich etwas geändert hat.

Basis-Variante: Adware + Malware.

## URLs für die Firewall

| Datei | Einträge | EDL-Typ | Wofür |
|---|---:|---|---|
| [`domains.txt`](https://mcmarius11.github.io/hosts2paloalto/domains.txt) | ~97.600 | Domain **oder** URL | 1:1-Konvertierung, exaktes Host-Matching. **Standard.** |
| [`domains-collapsed.txt`](https://mcmarius11.github.io/hosts2paloalto/domains-collapsed.txt) | ~48.000 | Domain | Auf eTLD+1 zusammengefasst, für knappe EDL-Limits. Subdomain-Matching aktivieren. |
| [`url-wildcard.txt`](https://mcmarius11.github.io/hosts2paloalto/url-wildcard.txt) | ~48.000 | URL | Wie oben, aber in `*.domain/`-Syntax. |
| [`stats.json`](https://mcmarius11.github.io/hosts2paloalto/stats.json) | – | – | Aktuelle Zeilenzahlen und Build-Zeitstempel. |

## Welche Datei nehmen?

Zuerst das echte Limit **deiner** Box ermitteln — das ist die einzige verbindliche Quelle:

```
show system state | match max-edl
```

Wichtig: die Limits gelten **pro System über alle EDLs hinweg**, nicht pro Liste.
Aufsplitten in mehrere EDLs bringt also keine zusätzliche Kapazität. Einträge zählen
nur, wenn die EDL in einer Policy referenziert wird.

- Reicht das URL- bzw. Domain-Limit für ~97.600 Einträge → **`domains.txt`**.
- Reicht es nicht → **`domains-collapsed.txt`** bzw. **`url-wildcard.txt`** (~48.000).

⚠️ Bei einer **Domain-EDL mit aktiviertem Subdomain-Matching** zählt laut Palo-Doku
jeder Eintrag **doppelt** („each domain in a given list requires an additional entry").
48.000 Einträge belegen dort also 96.000.

## Einrichtung in PAN-OS

**1 — EDL anlegen**

`Objects > External Dynamic Lists > Add`

- **Type:** `URL List` (für Security-Policy / URL-Filtering) oder `Domain List`
  (für Anti-Spyware DNS-Sinkhole)
- **Source:** eine der URLs oben
- **Check for updates:** `Hourly`
- **Certificate Profile:** leer lassen genügt; für strikte Prüfung ein Profil mit der
  GitHub-CA-Kette hinterlegen

Mit `Test Source URL` prüfen, ob die Firewall die Datei erreicht.

**2a — als URL-EDL durchsetzen**

Die EDL taucht in URL-Filtering-Profilen als eigene Kategorie auf. Dort auf `block`
setzen und das Profil an die ausgehende Security-Regel hängen. Alternativ die EDL
direkt im URL-Category-Feld einer Deny-Regel referenzieren.

**2b — als Domain-EDL durchsetzen**

`Objects > Security Profiles > Anti-Spyware > <Profil> > DNS Policies` → EDL
hinzufügen, Action `sinkhole`, Sinkhole-IP setzen. Das ist das echte
hosts-Datei-Äquivalent: geblockt wird bereits die DNS-Auflösung, und im Traffic-Log
siehst du den *tatsächlichen* Client hinter dem Request statt nur den Resolver.

**3 — Commit**, dann optional sofort ziehen:

```
request system external-list refresh name <EDL-Name>
show system external-list name <EDL-Name>
```

## Eigene Ausnahmen

[`data/allowlist.txt`](data/allowlist.txt) bearbeiten — ein Eintrag pro Zeile, deckt
die Domain und alle Subdomains ab. Push triggert den Build, ein bis zwei Minuten
später ist die neue Liste live.

## Warum „collapsed"?

Die flache Liste enthält u.a. 1.725 Subdomains von `2o7.net` und 121 von
`doubleclick.net`. Auf die registrierbare Domain (eTLD+1, via
[Public Suffix List](https://publicsuffix.org/)) zusammengefasst schrumpft das um
gut die Hälfte — und deckt via Subdomain-Matching sogar *mehr* ab, weil auch neue,
noch nicht gelistete Subdomains greifen.

Der Fallstrick dabei: naives Zusammenfassen erzeugt Sammel-Einträge wie `co.uk`,
`edgekey.net` (Akamai) oder `amazonaws.com` — damit blockt man sich halbe
Internet-Infrastruktur weg. Deshalb läuft das Collapsing über die Public Suffix List,
und die Suffixe in [`data/no-collapse.txt`](data/no-collapse.txt) sind zusätzlich
ausgenommen: dort bleiben die Originaldomains einzeln stehen.

## Lokal bauen

```bash
python3 scripts/build.py    # Ergebnis landet in public/
```

Keine Abhängigkeiten außer Python 3.9+.

## Quellen & Credits

Dieses Projekt filtert **nichts selbst** — es konvertiert nur ein Format ins andere. Die
eigentliche Arbeit steckt in [**StevenBlack/hosts**](https://github.com/StevenBlack/hosts)
von [Steven Black](https://github.com/StevenBlack). Verarbeitet wird ausschließlich die
Basis-Variante:

```
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
```

Die Liste ihrerseits führt mehrere kuratierte Quellen zusammen — die sind
[in Stevens Readme](https://github.com/StevenBlack/hosts#sources-of-hosts-data-unified-in-this-variant)
samt Lizenzen dokumentiert.

Das Zusammenfassen auf die registrierbare Domain nutzt die
[Public Suffix List](https://publicsuffix.org/) (Mozilla, MPL 2.0).

## Lizenz

Die **Konvertierungs-Pipeline** in diesem Repo (`scripts/`, `data/`, Workflow) steht unter
[MIT](LICENSE). Für die **Filterdaten** gelten die Lizenzen der Quellen, die StevenBlack
zusammenführt.

> ⚠️ Darunter sind zwei **nicht-kommerzielle** Lizenzen (MVPS: CC BY-NC-SA 4.0,
> someonewhocares: non-commercial with attribution). Sie gelten für die Daten unabhängig
> davon, über wie viele Zwischenschritte man sie bezieht — beim geschäftlichen Einsatz also
> kurz prüfen.
