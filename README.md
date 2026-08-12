# hosts2paloalto

Konvertiert die [StevenBlack-hosts-Liste](https://github.com/StevenBlack/hosts) in
**External Dynamic Lists (EDL)** für PAN-OS. Der Build läuft stündlich per GitHub
Actions und baut nur neu, wenn Steven upstream tatsächlich etwas geändert hat.

Basis-Variante: Adware + Malware.

## URLs für die Firewall

| Datei | Einträge | EDL-Typ | Wofür |
|---|---:|---|---|
| [`domains.txt`](https://mcmarius11.github.io/hosts2paloalto/domains.txt) | ~97.600 | Domain **oder** URL | 1:1-Konvertierung, exaktes Host-Matching. **Standard.** |
| [`domains-no-nc.txt`](https://mcmarius11.github.io/hosts2paloalto/domains-no-nc.txt) | ~79.500 | Domain **oder** URL | Wie oben, ohne die nicht-kommerziell lizenzierten Quellen. Siehe [Lizenz](#lizenz). |
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
- Geschäftlicher Einsatz → **`domains-no-nc.txt`** (~79.500), siehe [Lizenz](#lizenz).

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
[MIT](LICENSE).

Für die **Filterdaten** gelten die Lizenzen der Quellen, die StevenBlack zusammenführt. Wie
sich die Basis-Variante darauf verteilt (gemessen gegen die Originallisten):

| Anteil | Deckung | Konsequenz |
|---:|---|---|
| 21,9 % | mind. eine permissive Quelle (MIT / CC0 / CC BY) | frei nutzbar, CC-BY-Anteile brauchen Attribution |
| 59,0 % | nur über [KADhosts](https://kadantiscam.netlify.app/) | **CC BY-SA 4.0** — ShareAlike |
| 18,0 % | nur über MVPS / someonewhocares | **nicht-kommerziell** |

Daraus folgen zwei Dinge:

**Attribution ist Pflicht.** Acht der zusammengeführten Quellen verlangen laut Lizenz eine
Namensnennung (CC BY / BY-SA / BY-NC-SA) bzw. das Erhalten des Copyright-Vermerks (MIT):

| Quelle | Lizenz |
|---|---|
| [AdAway](https://adaway.org/) | CC BY 3.0 |
| [KADhosts](https://kadantiscam.netlify.app/) | CC BY-SA 4.0 |
| [Tiuxo](https://github.com/tiuxo/hosts) | CC BY 4.0 |
| [FadeMind – hosts.extras](https://github.com/FadeMind/hosts.extras) | MIT |
| [Mitchell Krog – Badd Boyz Hosts](https://github.com/mitchellkrogza/Badd-Boyz-Hosts) | MIT |
| [bigdargon – hostsVN](https://github.com/bigdargon/hostsVN) | MIT |
| [MVPS](https://winhelp2002.mvps.org/) | CC BY-NC-SA 4.0 |
| [Dan Pollock – someonewhocares](https://someonewhocares.org/hosts/) | non-commercial with attribution |

Alle stehen namentlich im Header **jeder** erzeugten Datei; beim Weitergeben nicht entfernen.
In `domains-no-nc.txt` fehlen MVPS und someonewhocares dort bewusst — deren Daten sind in
dieser Variante nicht enthalten. [minecraft-hosts](https://github.com/jamiemansfield/minecraft-hosts)
und [URLHaus](https://urlhaus.abuse.ch/) stehen unter CC0 und verzichten ausdrücklich auf
Attribution.

> ℹ️ Für [yoyo.org](https://pgl.yoyo.org/adservers/) nennt StevenBlacks Quellenübersicht
> **keine Lizenz**. Diese Domains lassen sich lizenzrechtlich daher nicht sauber einordnen —
> ein Restrisiko, das sich mit den vorliegenden Angaben nicht auflösen lässt.

**ShareAlike dominiert.** Rund 59 % der Domains sind nur über KADhosts (CC BY-SA 4.0) gedeckt.
Die erzeugten Listen sind damit als Bearbeitung unter denselben Bedingungen weiterzugeben —
sie sind *nicht* MIT, auch wenn die Pipeline es ist.

> ⚠️ **Kommerzieller Einsatz:** MVPS (CC BY-NC-SA 4.0) und someonewhocares (non-commercial
> with attribution) untersagen die kommerzielle Nutzung. Für diesen Fall gibt es
> **`domains-no-nc.txt`** — dieselbe Liste ohne diese beiden Quellen (~79.500 statt ~97.600
> Einträge). Der ShareAlike-Punkt oben bleibt davon unberührt.
>
> Der Ausschluss läuft über die `# Start`/`# End`-Marker der gemergten Datei. Da StevenBlack
> beim Mergen dedupliziert, entfernt das rund 600 Domains mehr als nötig — also konservativ
> in die sichere Richtung.

Dies ist keine Rechtsberatung. Ob Blocklisten überhaupt schutzfähig sind, ist umstritten
(reine Faktensammlungen genießen dünnen Schutz; in der EU kann das
Datenbankherstellerrecht greifen). Im Zweifel selbst prüfen lassen.
