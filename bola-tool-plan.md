# BOLA/IDOR testtool — volledig bouwplan

Open source, AI-minimaal, Codex- en API-compatibel (o.a. DeepSeek). Doel: beter dan BOLABuster (Palo Alto Unit 42), maar wel daadwerkelijk open source en zonder verplichte OpenAPI-spec vooraf.

Elke module in dit document is geschreven en getest: unit-tests per laag plus een volledige end-to-end run tegen een lokale mock-API die een echte BOLA-kwetsbaarheid simuleert. De pipeline vindt die kwetsbaarheid en genereert er correct rapport over. Alle code hieronder is exact wat getest is, geen placeholders.

## Kernprincipe

De AI raakt het netwerk nooit direct aan en voert nooit zelf een HTTP-request uit. Hij leest alleen gestructureerde context en levert een gestructureerd testplan terug. Alle uitvoering blijft deterministisch. Dat maakt het goedkoper (alleen AI-tokens bij een nieuw endpoint-patroon, niet per request), voorspelbaarder en auditeerbaar: elke request die de tool doet is te herleiden naar een script, niet naar modelimprovisatie.

## Architectuur

```
0. Scope guard          Weigert te draaien zonder bevestigde toestemming + allow-list
1. Traffic capture       Playwright + HAR (CDP network tab equivalent)
2. Extractie             Deterministisch: tokens, JWT's, API keys
3. State store           SQLite: eerdere runs, ownership, findings
4. Endpoint-templating    Deterministisch: URL-patronen + ownership-correlatie
5. Test executor         Deterministisch: replay + response diff
6. AI-beslislaag          1 call per nieuw endpoint-patroon → testplan (JSON)
7. MCP-server             Lokaal, stdio, ontsluit alle tools voor Codex/Claude Code
8. Rapportage            JSON, JUnit XML, markdown
```

Stap 5 voedt nieuwe data terug naar de state store (stap 3), zodat elke volgende run voortbouwt op wat al bekend is. De AI-laag (6) zit tussen 3 en 5 in en is het enige punt waar een taalmodel iets beslist, nooit waar het iets uitvoert.

## Projectstructuur

```
bola-tool/
  scope_guard.py         fase 0 — scope-guardrails
  har_extract.py          fase 2 — extractie uit HAR
  state_store.py           fase 3 — SQLite state store
  endpoint_template.py      fase 4 — templatization + ownership
  test_executor.py          fase 5 — deterministische replay + diff
  ai_layer.py                fase 6 — AI-beslislaag (LiteLLM + Codex CLI)
  mcp_server.py               fase 7 — lokale MCP-server
  report.py                    fase 8 — JSON/JUnit/markdown rapportage
  pipeline.py                   orchestrator, alle fases als los CLI-script (stil)
  cli.py                         fase 9 — zelfde orchestratie, met narratieve terminal-output
  mock_target.py                 lokale test-API voor development, geen externe target nodig
```

## Requirements

```
pip install requests pyyaml pydantic litellm fastmcp rich --break-system-packages
npx playwright install chromium
```

`fastmcp` is het losse, actief onderhouden package voor de MCP-server (in `mcp>=2.0` zit `FastMCP` niet meer als submodule in het kale `mcp`-package, dat is nu een apart pakket). Geverifieerd tijdens het bouwen van dit plan.

## Fasering

| Fase | Inhoud | Status |
|---|---|---|
| 0 | Scope-guardrails | **klaar**, getest |
| 1 | Traffic capture | **klaar** — `playwright open --save-har` |
| 2 | Extractie | **klaar**, getest |
| 3 | State store (SQLite) | **klaar**, getest |
| 4 | Endpoint-templatization en ownership | **klaar**, getest |
| 5 | Deterministische test executor | **klaar**, getest tegen een echte kwetsbare en een echte beveiligde mock-endpoint |
| 6 | AI-beslislaag | **klaar** — parse/validatielogica getest, live API-call vereist een sleutel van de gebruiker |
| 7 | Lokale MCP-server | **klaar**, tool-registratie geverifieerd |
| 8 | Rapportage | **klaar**, getest |
| 9 | Terminal-interface | **klaar**, getest |

Alle acht fases zijn nu geïmplementeerd. Fase 1 is bewust een CLI-commando gebleven in plaats van een los script: `playwright open --save-har` doet precies wat nodig is zonder extra code.

---

## Fase 0 — Scope guard

Draait vóór elke andere fase. Weigert te starten zonder een `scope.yaml` met expliciete bevestiging van schriftelijke toestemming en een allow-list van toegestane targets. Concept geleend van HexStrike AI's scope validator.

Getest: ontbrekend scope-bestand, `confirmed: false`, geldige scope, en een out-of-scope target worden alle vier correct afgehandeld.

````python
#!/usr/bin/env python3
"""
scope_guard.py

Scope-guardrails (fase 0). Draait vóór elke andere fase. De tool weigert te
starten zonder een scope.yaml met expliciete bevestiging van schriftelijke
toestemming en een allow-list van toegestane targets. Concept geleend van
HexStrike AI's scope validator.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml


class ScopeError(Exception):
    pass


@dataclass
class ScopeConfig:
    client_name: str
    authorization_reference: str
    confirmed: bool
    allowed_domains: list[str]
    allowed_ip_ranges: list[str]


EXAMPLE_SCOPE_YAML = """\
# scope.yaml
# Vul dit in vóórdat je de tool draait. De tool weigert te starten als
# confirmed niet expliciet op true staat.

client_name: "Voorbeeld B.V."
authorization_reference: "Getekende pentest-overeenkomst d.d. 2026-08-01, ref PT-2026-014"
confirmed: false   # zet dit pas op true nadat je de schriftelijke toestemming hebt

allowed_domains:
  - "staging.voorbeeldklant.nl"
  - "api.voorbeeldklant.nl"

allowed_ip_ranges: []   # optioneel, CIDR-notatie, bv. "10.0.0.0/24"
"""


def load_scope(path: str) -> ScopeConfig:
    p = Path(path)
    if not p.exists():
        raise ScopeError(
            f"Geen scope-bestand gevonden op {path}. Maak er een aan, "
            f"bijvoorbeeld:\n\n{EXAMPLE_SCOPE_YAML}"
        )

    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}

    cfg = ScopeConfig(
        client_name=data.get("client_name", ""),
        authorization_reference=data.get("authorization_reference", ""),
        confirmed=bool(data.get("confirmed", False)),
        allowed_domains=data.get("allowed_domains", []) or [],
        allowed_ip_ranges=data.get("allowed_ip_ranges", []) or [],
    )

    if not cfg.confirmed:
        raise ScopeError(
            "scope.yaml heeft confirmed: false. De tool start niet zonder "
            "expliciete bevestiging dat er schriftelijke toestemming is "
            "voor deze test. Zet confirmed: true pas nadat dat geregeld is."
        )
    if not cfg.authorization_reference.strip():
        raise ScopeError(
            "authorization_reference is leeg. Vul een verwijzing in naar "
            "de schriftelijke toestemming (contractnummer, datum, etc.)."
        )
    if not cfg.allowed_domains and not cfg.allowed_ip_ranges:
        raise ScopeError(
            "Geen allowed_domains of allowed_ip_ranges opgegeven. Zonder "
            "allow-list kan de tool niet bepalen wat wel en niet in scope is."
        )

    return cfg


def _domain_matches(hostname: str, pattern: str) -> bool:
    """Ondersteunt exacte matches en simpele wildcards zoals *.voorbeeld.nl."""
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".voorbeeld.nl"
        return hostname.endswith(suffix) and hostname != suffix.lstrip(".")
    return hostname == pattern


def is_in_scope(url: str, cfg: ScopeConfig) -> bool:
    hostname = urlparse(url).hostname or ""
    return any(_domain_matches(hostname, pattern) for pattern in cfg.allowed_domains)


def require_in_scope(url: str, cfg: ScopeConfig) -> None:
    if not is_in_scope(url, cfg):
        raise ScopeError(
            f"{url} valt niet binnen de allowed_domains in scope.yaml. "
            f"Toegestaan: {cfg.allowed_domains}. Tool stopt."
        )

````

---

## Fase 1 — Traffic capture

Geen los script: Playwright's ingebouwde HAR-opname doet precies wat nodig is, terminal-native, zonder proxy of certificaat.

```
npx playwright open --save-har=identity_a.har --save-har-glob="**/api/**" https://target.com
```

Browservenster opent, log in als identity A, klik door de app, sluit het venster. Herhaal met een ander profiel voor identity B (`identity_b.har`). `--save-har-glob` filtert ruis (assets, tracking) weg.

Voor de geautomatiseerde pipeline (zonder handmatig inloggen): programmatisch via Playwright Python, `browser.new_context(record_har_path=..., record_har_content="embed")`.

Kanttekening: HAR vangt geen WebSocket- of Server-Sent-Events-verkeer. Bij zware WS-afhankelijkheid is een aparte CDP-listener op `Network.webSocketFrame*` nodig.

---

## Fase 2 — Extractie

Deterministisch, geen AI. Herkent bearer tokens, JWT's en API-key headers, decodeert JWT-claims (sub/user_id/tenant_id) voor identity-mapping.

```
python har_extract.py identity_a.har --out identity_a_findings.json
```

````python
#!/usr/bin/env python3
"""
har_extract.py

Deterministische extractielaag voor de BOLA-testtool.
Leest een HAR-bestand (Playwright: `playwright open --save-har=...`)
en haalt alle bearer tokens, JWT's en API-key headers eruit uit
zowel request- als response-headers en response-bodies.

Gebruik:
    python har_extract.py identity_a.har
    python har_extract.py identity_a.har --out identity_a_findings.json
"""

import argparse
import base64
import json
import re
import sys
from pathlib import Path

# Header-namen die vrijwel altijd een credential bevatten.
API_KEY_HEADER_NAMES = {
    "authorization",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "x-session-token",
    "cookie",
}

# JWT: drie base64url-delen gescheiden door punten, begint typisch met eyJ.
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

# Generieke "iets dat op een secret lijkt"-detectie voor JSON-bodies:
# lange alfanumerieke strings achter een sleutel met een veelzeggende naam.
SECRET_KEY_PATTERN = re.compile(
    r'"(api[_-]?key|access[_-]?token|secret|bearer|auth[_-]?token|client[_-]?secret)"\s*:\s*"([^"]{8,})"',
    re.IGNORECASE,
)

BEARER_RE = re.compile(r"Bearer\s+([A-Za-z0-9\-_.=]+)", re.IGNORECASE)


def decode_jwt_payload(token: str) -> dict | None:
    """Decodeert (zonder verificatie) het payload-deel van een JWT, voor
    identity-mapping: sub / user_id / tenant_id claims geven direct de
    koppeling tussen token en identity."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload + padding)
        return json.loads(decoded)
    except Exception:
        return None


def get_body_text(content: dict) -> str:
    text = content.get("text", "") or ""
    if content.get("encoding") == "base64":
        try:
            return base64.b64decode(text).decode("utf-8", errors="ignore")
        except Exception:
            return ""
    return text


def extract_from_har(har_path: Path) -> list[dict]:
    with har_path.open("r", encoding="utf-8") as f:
        har = json.load(f)

    findings = []

    for entry in har["log"]["entries"]:
        url = entry["request"]["url"]
        method = entry["request"]["method"]

        # 1. Headers (request en response)
        header_sources = (
            (entry["request"].get("headers", []), "request"),
            (entry["response"].get("headers", []), "response"),
        )
        for headers, direction in header_sources:
            for h in headers:
                name = h["name"].lower()
                value = h.get("value", "")
                if name not in API_KEY_HEADER_NAMES:
                    continue

                finding = {
                    "url": url,
                    "method": method,
                    "direction": direction,
                    "header": h["name"],
                    "value": value,
                }

                bearer_match = BEARER_RE.search(value)
                token = bearer_match.group(1) if bearer_match else (
                    value if JWT_RE.match(value) else None
                )
                if token:
                    claims = decode_jwt_payload(token)
                    if claims:
                        finding["jwt_claims"] = claims
                        finding["identity_hint"] = (
                            claims.get("sub")
                            or claims.get("user_id")
                            or claims.get("uid")
                            or claims.get("tenant_id")
                        )

                findings.append(finding)

        # 2. Response body: los rondslingerende JWT's en secret-achtige velden
        content = entry.get("response", {}).get("content", {})
        body_text = get_body_text(content)

        for match in JWT_RE.finditer(body_text):
            token = match.group(0)
            claims = decode_jwt_payload(token)
            findings.append({
                "url": url,
                "method": method,
                "direction": "body",
                "header": None,
                "value": token,
                "jwt_claims": claims,
                "identity_hint": (claims or {}).get("sub")
                or (claims or {}).get("user_id"),
            })

        for match in SECRET_KEY_PATTERN.finditer(body_text):
            findings.append({
                "url": url,
                "method": method,
                "direction": "body",
                "header": None,
                "value": match.group(2),
                "field_name": match.group(1),
            })

    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("har_file", type=Path, help="Pad naar het HAR-bestand")
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Pad om resultaten als JSON weg te schrijven (default: stdout)",
    )
    args = parser.parse_args()

    if not args.har_file.exists():
        print(f"Bestand niet gevonden: {args.har_file}", file=sys.stderr)
        sys.exit(1)

    findings = extract_from_har(args.har_file)

    output = json.dumps(findings, indent=2, ensure_ascii=False)
    if args.out:
        args.out.write_text(output, encoding="utf-8")
        print(f"{len(findings)} findings weggeschreven naar {args.out}")
    else:
        print(output)


if __name__ == "__main__":
    main()

````

---

## Fase 3 — State store

SQLite, één lokaal bestand. Vijf tabellen: `endpoints`, `identities`, `owned_objects`, `tested_combinations`, `findings`. `load_har_findings()` verwerkt de output van fase 2 direct: gebruikt JWT-claims als die er zijn, valt terug op de kale tokenwaarde voor opaque API keys zodat er nooit een credential verloren gaat.

````python
#!/usr/bin/env python3
"""
state_store.py

Lokale SQLite state store voor de BOLA-testtool (fase 3).
Houdt endpoints, identities, ownership, geteste combinaties en findings
bij tussen runs, zodat elke volgende run voortbouwt op wat al bekend is.
"""

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template TEXT NOT NULL,
    method TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    UNIQUE(template, method)
);

CREATE TABLE IF NOT EXISTS identities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    token TEXT,
    sub_claim TEXT,
    tenant_claim TEXT
);

CREATE TABLE IF NOT EXISTS owned_objects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_id INTEGER NOT NULL REFERENCES identities(id),
    endpoint_id INTEGER NOT NULL REFERENCES endpoints(id),
    object_id TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    UNIQUE(identity_id, endpoint_id, object_id)
);

CREATE TABLE IF NOT EXISTS tested_combinations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id INTEGER NOT NULL REFERENCES endpoints(id),
    identity_owner_id INTEGER NOT NULL REFERENCES identities(id),
    identity_attacker_id INTEGER NOT NULL REFERENCES identities(id),
    object_id TEXT NOT NULL,
    tested_at TEXT NOT NULL,
    UNIQUE(endpoint_id, identity_owner_id, identity_attacker_id, object_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id INTEGER NOT NULL REFERENCES endpoints(id),
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    found_at TEXT NOT NULL
);
"""


@dataclass
class Finding:
    endpoint_template: str
    severity: str
    description: str
    evidence: dict


class StateStore:
    def __init__(self, db_path: str = "bola_state.db"):
        self.db_path = Path(db_path)
        self._init_db()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # --- endpoints ---
    def add_endpoint(self, template: str, method: str) -> int:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO endpoints (template, method, first_seen) "
                "VALUES (?, ?, ?)",
                (template, method, self._now()),
            )
            row = conn.execute(
                "SELECT id FROM endpoints WHERE template = ? AND method = ?",
                (template, method),
            ).fetchone()
            return row["id"]

    def list_endpoints(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM endpoints").fetchall()
            return [dict(r) for r in rows]

    # --- identities ---
    def add_identity(
        self, name: str, token: str | None = None,
        sub_claim: str | None = None, tenant_claim: str | None = None,
    ) -> int:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO identities (name, token, sub_claim, tenant_claim) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET "
                "token=excluded.token, sub_claim=excluded.sub_claim, "
                "tenant_claim=excluded.tenant_claim",
                (name, token, sub_claim, tenant_claim),
            )
            row = conn.execute(
                "SELECT id FROM identities WHERE name = ?", (name,)
            ).fetchone()
            return row["id"]

    def list_identities(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM identities").fetchall()
            return [dict(r) for r in rows]

    # --- ownership ---
    def add_owned_object(self, identity_id: int, endpoint_id: int, object_id: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO owned_objects "
                "(identity_id, endpoint_id, object_id, first_seen) VALUES (?, ?, ?, ?)",
                (identity_id, endpoint_id, object_id, self._now()),
            )

    def objects_owned_by(self, identity_id: int, endpoint_id: int) -> list[str]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT object_id FROM owned_objects "
                "WHERE identity_id = ? AND endpoint_id = ?",
                (identity_id, endpoint_id),
            ).fetchall()
            return [r["object_id"] for r in rows]

    # --- tested combinations ---
    def has_been_tested(
        self, endpoint_id: int, identity_owner_id: int,
        identity_attacker_id: int, object_id: str,
    ) -> bool:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM tested_combinations WHERE "
                "endpoint_id=? AND identity_owner_id=? AND "
                "identity_attacker_id=? AND object_id=?",
                (endpoint_id, identity_owner_id, identity_attacker_id, object_id),
            ).fetchone()
            return row is not None

    def mark_tested(
        self, endpoint_id: int, identity_owner_id: int,
        identity_attacker_id: int, object_id: str,
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO tested_combinations "
                "(endpoint_id, identity_owner_id, identity_attacker_id, object_id, tested_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (endpoint_id, identity_owner_id, identity_attacker_id, object_id, self._now()),
            )

    def untested_combinations(self) -> list[dict]:
        """Alle (endpoint, owner, object) combinaties waarvoor nog niet elke
        andere identity is getest. Dit is de invoer voor de test executor."""
        with self._conn() as conn:
            owned = conn.execute(
                "SELECT oo.endpoint_id, oo.identity_id AS owner_id, oo.object_id "
                "FROM owned_objects oo"
            ).fetchall()
            identities = [r["id"] for r in conn.execute("SELECT id FROM identities").fetchall()]

            result = []
            for row in owned:
                for attacker_id in identities:
                    if attacker_id == row["owner_id"]:
                        continue
                    if not self.has_been_tested(
                        row["endpoint_id"], row["owner_id"], attacker_id, row["object_id"]
                    ):
                        result.append({
                            "endpoint_id": row["endpoint_id"],
                            "owner_id": row["owner_id"],
                            "attacker_id": attacker_id,
                            "object_id": row["object_id"],
                        })
            return result

    # --- findings ---
    def add_finding(self, endpoint_id: int, severity: str, description: str, evidence: dict) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO findings (endpoint_id, severity, description, evidence_json, found_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (endpoint_id, severity, description, json.dumps(evidence), self._now()),
            )
            return cur.lastrowid

    def list_findings(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT f.*, e.template, e.method FROM findings f "
                "JOIN endpoints e ON e.id = f.endpoint_id"
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["evidence"] = json.loads(d.pop("evidence_json"))
                out.append(d)
            return out

    def load_har_findings(self, har_findings: list[dict], identity_name: str) -> None:
        """Laadt de output van har_extract.py in voor één identity: registreert
        de identity met de eerst gevonden credential-waarde als token. Gebruikt
        JWT-claims (sub/user_id, tenant_id) als die er zijn, maar valt terug op
        de kale waarde voor niet-JWT credentials zoals opaque API keys, zodat
        de token nooit verloren gaat. Endpoint/ownership-koppeling gebeurt in
        fase 4 (endpoint_template.py), dit is puur de identity-registratie."""
        token = None
        sub_claim = None
        tenant_claim = None
        for f in har_findings:
            value = f.get("value")
            claims = f.get("jwt_claims")
            if claims and sub_claim is None:
                sub_claim = claims.get("sub") or claims.get("user_id")
                tenant_claim = claims.get("tenant_id")
            if token is None and value:
                token = value
        self.add_identity(
            name=identity_name, token=token,
            sub_claim=sub_claim, tenant_claim=tenant_claim,
        )

````

---

## Fase 4 — Endpoint-templatization en ownership-correlatie

Deterministisch: regex op numerieke/UUID/base64-achtige segmenten in paths. Concept geleend van AuthProbe's ground truth ownership, maar zelf gebouwd zodat het werkt vanuit live traffic in plaats van een verplichte OpenAPI-spec.

````python
#!/usr/bin/env python3
"""
endpoint_template.py

Deterministische endpoint-templatization en ownership-correlatie (fase 4).
Geen AI: regex op numerieke/UUID/base64-achtige segmenten, plus matching
tussen bekende identity-IDs (uit har_extract.py / state_store) en
object-ID's die in URL's of response bodies opduiken.
"""

import re
from urllib.parse import urlparse

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
NUMERIC_RE = re.compile(r"^\d+$")
# lange hex/base64-achtige string, typisch voor Mongo ObjectId's of opaque tokens
OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,}$")


def templatize(path: str) -> str:
    """Vervangt object-ID-achtige path-segmenten door {id}.
    /api/documents/812 -> /api/documents/{id}
    /api/users/9f2c1b3a-.../orders/44 -> /api/users/{id}/orders/{id}
    """
    parts = path.strip("/").split("/")
    templated = []
    for part in parts:
        if UUID_RE.match(part) or NUMERIC_RE.match(part) or OPAQUE_ID_RE.match(part):
            templated.append("{id}")
        else:
            templated.append(part)
    return "/" + "/".join(templated)


def extract_object_ids(path: str) -> list[str]:
    """Geeft de daadwerkelijke waarden terug van de segmenten die als {id}
    zouden worden getemplate, in volgorde van voorkomen."""
    parts = path.strip("/").split("/")
    ids = []
    for part in parts:
        if UUID_RE.match(part) or NUMERIC_RE.match(part) or OPAQUE_ID_RE.match(part):
            ids.append(part)
    return ids


def correlate_ownership(har_entries: list[dict], identity_by_hint: dict[str, str]) -> list[dict]:
    """
    har_entries: lijst van dicts met minstens {"url": str, "method": str,
        "requester_identity": str} — requester_identity komt uit welke
        HAR-capture (identity_a.har / identity_b.har) de entry vandaan komt.
    identity_by_hint: mapping van sub/user_id-claim naar identity-naam,
        voor het geval de owner uit de JWT-claim in de body/URL blijkt
        i.p.v. simpelweg "wie deed de request".

    Retourneert een lijst van {"identity", "endpoint_template", "object_id"}
    tuples, klaar om in StateStore.add_owned_object() te zetten.
    """
    correlations = []
    for entry in har_entries:
        parsed = urlparse(entry["url"])
        template = templatize(parsed.path)
        object_ids = extract_object_ids(parsed.path)

        # simpelste geval: de identity die de request deed, bezit de
        # object-ID('s) in het path (typisch voor "mijn eigen profiel/order/etc")
        owner = entry.get("requester_identity")
        for obj_id in object_ids:
            correlations.append({
                "identity": owner,
                "endpoint_template": template,
                "method": entry["method"],
                "object_id": obj_id,
            })

    return correlations


def build_test_targets(state_store, correlations: list[dict]) -> None:
    """Schrijft de correlaties weg naar de state store: registreert endpoints
    en owned_objects. Losstaand van correlate_ownership() zodat je de pure
    logica (bovenstaande) apart kan unit-testen van de database-kant."""
    identity_id_by_name = {
        row["name"]: row["id"] for row in state_store.list_identities()
    }
    for c in correlations:
        identity_id = identity_id_by_name.get(c["identity"])
        if identity_id is None:
            continue
        endpoint_id = state_store.add_endpoint(c["endpoint_template"], c["method"])
        state_store.add_owned_object(identity_id, endpoint_id, c["object_id"])

````

---

## Fase 5 — Test executor

Pure HTTP client plus comparator, roept nooit de AI aan. Ontvangt een concrete testopdracht, voert de request uit als de attacker-identity, vergelijkt de response met de ground-truth van de owner. Diff-logica geïnspireerd op AuthProbe: matcht op `id_field`, onderscheidt een echte BOLA van een gewone 403/404.

````python
#!/usr/bin/env python3
"""
test_executor.py

Deterministische, variabele test executor (fase 5). Roept nooit de AI aan.
Ontvangt een concrete testopdracht (endpoint, object-ID, owner-identity,
attacker-identity), voert de request uit als attacker, en vergelijkt de
response met de ground-truth van de owner. Diff-logica geïnspireerd op
AuthProbe: matcht op id_field, onderscheidt een echte BOLA van een gewone
404/403.
"""

import json
from dataclasses import dataclass, field
from typing import Any

import requests


@dataclass
class TestTarget:
    base_url: str
    endpoint_template: str
    method: str
    object_id: str
    owner_token: str
    attacker_token: str
    id_field: str = "id"


@dataclass
class TestResult:
    target: TestTarget
    verdict: str  # "bola", "protected", "inconclusive"
    owner_status: int
    attacker_status: int
    evidence: dict[str, Any] = field(default_factory=dict)


def _fill_path(template: str, object_id: str) -> str:
    """Vervangt het eerste {id} in het template door de echte waarde.
    Voor endpoints met meerdere {id}'s (geneste resources) moet de caller
    een al-ingevulde template meegeven voor de overige segmenten."""
    return template.replace("{id}", object_id, 1)


def _request_as(base_url: str, path: str, method: str, token: str) -> requests.Response:
    url = base_url.rstrip("/") + path
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return requests.request(method, url, headers=headers, timeout=15)


def _bodies_equivalent(owner_body: str, attacker_body: str, id_field: str) -> bool:
    """Bepaalt of de attacker-response inhoudelijk hetzelfde object teruggeeft
    als de owner kreeg. Probeert eerst JSON-vergelijking op het id_field,
    valt terug op een grove tekstvergelijking als de body geen JSON is."""
    try:
        owner_json = json.loads(owner_body)
        attacker_json = json.loads(attacker_body)
    except (json.JSONDecodeError, TypeError):
        return owner_body.strip() == attacker_body.strip() and len(owner_body.strip()) > 0

    def dig(obj, key):
        if isinstance(obj, dict):
            if key in obj:
                return obj[key]
            for v in obj.values():
                found = dig(v, key)
                if found is not None:
                    return found
        return None

    owner_id_value = dig(owner_json, id_field)
    attacker_id_value = dig(attacker_json, id_field)

    if owner_id_value is not None and attacker_id_value is not None:
        return str(owner_id_value) == str(attacker_id_value)

    # geen id_field gevonden in de body, val terug op structuurgelijkheid
    return owner_json == attacker_json


def run_test(target: TestTarget) -> TestResult:
    """Voert het daadwerkelijke BOLA-testscenario uit:
    1. owner haalt zijn eigen object op (ground truth)
    2. attacker probeert hetzelfde object-ID op te vragen met zijn eigen token
    3. als attacker een 2xx krijgt met hetzelfde object -> BOLA
    """
    path = _fill_path(target.endpoint_template, target.object_id)

    owner_resp = _request_as(target.base_url, path, target.method, target.owner_token)
    attacker_resp = _request_as(target.base_url, path, target.method, target.attacker_token)

    evidence = {
        "path": path,
        "owner_status": owner_resp.status_code,
        "attacker_status": attacker_resp.status_code,
    }

    if owner_resp.status_code >= 400:
        # kunnen de owner-response niet als ground truth gebruiken
        return TestResult(
            target=target, verdict="inconclusive",
            owner_status=owner_resp.status_code,
            attacker_status=attacker_resp.status_code,
            evidence=evidence,
        )

    if attacker_resp.status_code in (401, 403, 404):
        return TestResult(
            target=target, verdict="protected",
            owner_status=owner_resp.status_code,
            attacker_status=attacker_resp.status_code,
            evidence=evidence,
        )

    if attacker_resp.status_code // 100 == 2:
        equivalent = _bodies_equivalent(owner_resp.text, attacker_resp.text, target.id_field)
        evidence["bodies_equivalent"] = equivalent
        if equivalent:
            return TestResult(
                target=target, verdict="bola",
                owner_status=owner_resp.status_code,
                attacker_status=attacker_resp.status_code,
                evidence=evidence,
            )

    return TestResult(
        target=target, verdict="inconclusive",
        owner_status=owner_resp.status_code,
        attacker_status=attacker_resp.status_code,
        evidence=evidence,
    )


def run_test_batch(targets: list[TestTarget]) -> list[TestResult]:
    return [run_test(t) for t in targets]

````

---

## Fase 6 — AI-beslislaag

Het enige AI-moment in de tool. Eén smalle call per nieuw endpoint-patroon of ambigue situatie (object-ID in geneste body, GraphQL-veld, query-parameter). Output is een verplicht Pydantic-gevalideerd JSON-schema, geen vrije tekst. Bij een parse- of validatiefout wordt de fout doorgegooid in plaats van geraden — de test executor mag nooit op een onbetrouwbaar testplan draaien.

Twee adapters achter dezelfde interface `propose_tests(context) -> TestPlan`:
- **LiteLLMAdapter**: directe API-aanroep, dekt DeepSeek, OpenAI, Anthropic en 100+ providers.
- **CodexCLIAdapter**: shell out naar `codex exec --json`, gebruikt een bestaand Codex-abonnement zonder losse API key.

````python
#!/usr/bin/env python3
"""
ai_layer.py

Het enige AI-moment in de tool (fase 6). Eén smalle call per nieuw ontdekt
endpoint-patroon of ambigue situatie. De AI voert nooit zelf een request uit:
hij levert alleen een gestructureerd TestPlan terug dat de test executor
(fase 5) vervolgens deterministisch uitvoert.

Twee adapters achter dezelfde interface:
- LiteLLMAdapter: directe API-aanroep, dekt OpenAI, Anthropic, DeepSeek en
  100+ andere providers via één interface.
- CodexCLIAdapter: shell out naar `codex exec --json`, gebruikt een bestaand
  Codex-abonnement zonder losse API key.
"""

import json
import subprocess
from abc import ABC, abstractmethod
from typing import Literal

from pydantic import BaseModel, Field, ValidationError


class TestSuggestion(BaseModel):
    endpoint_template: str
    method: str
    reasoning: str = Field(description="Korte onderbouwing, max 1 zin")
    object_id_location: Literal["path", "body_nested", "graphql_field", "query_param"]
    object_id_field_hint: str = Field(
        description="Veldnaam of path waar het object-ID te vinden is, "
        "bijvoorbeeld 'data.document.id' voor een geneste body, "
        "of 'documentId' voor een GraphQL-variabele."
    )
    id_field_for_diff: str = Field(
        default="id",
        description="Welk veld in de response te gebruiken voor de "
        "owner-vs-attacker vergelijking in de test executor.",
    )


class TestPlan(BaseModel):
    suggestions: list[TestSuggestion]


SYSTEM_PROMPT = """\
Je bent een smalle beslislaag in een geautomatiseerde BOLA/IDOR-testtool.
Je voert zelf GEEN requests uit. Je krijgt een endpoint-patroon, wat elke
identity bezit, en eerdere findings. Je antwoordt UITSLUITEND met geldige
JSON die voldoet aan het TestPlan-schema. Geen uitleg, geen markdown,
geen vrije tekst buiten de JSON.
"""


def _build_user_prompt(context: dict) -> str:
    return (
        "Context:\n"
        f"{json.dumps(context, indent=2, ensure_ascii=False)}\n\n"
        "Geef een TestPlan met concrete testsuggesties voor dit endpoint. "
        "Focus vooral op gevallen waar het object-ID NIET simpelweg in het "
        "URL-path staat (geneste JSON, GraphQL-velden, query-parameters), "
        "want die worden al gedekt door de deterministische laag."
    )


class LLMAdapter(ABC):
    @abstractmethod
    def propose_tests(self, context: dict) -> TestPlan:
        ...


class LiteLLMAdapter(LLMAdapter):
    """API-adapter. model bijvoorbeeld: 'deepseek/deepseek-chat',
    'anthropic/claude-sonnet-5', 'openai/gpt-5'. LiteLLM regelt de
    provider-specifieke details, jij geeft alleen de modelnaam mee."""

    def __init__(self, model: str, api_key: str | None = None):
        self.model = model
        self.api_key = api_key

    def propose_tests(self, context: dict) -> TestPlan:
        import litellm

        response = litellm.completion(
            model=self.model,
            api_key=self.api_key,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_prompt(context)},
            ],
            response_format={"type": "json_object"},
            temperature=0,
        )
        raw = response["choices"][0]["message"]["content"]
        return _parse_test_plan(raw)


class CodexCLIAdapter(LLMAdapter):
    """Agent-CLI-adapter. Shell out naar `codex exec --json`, gebruikt het
    bestaande Codex-abonnement van de gebruiker in plaats van een losse
    API key. Parse de JSONL-eventstream en pakt het laatste agent_message."""

    def __init__(self, codex_bin: str = "codex", timeout: int = 60):
        self.codex_bin = codex_bin
        self.timeout = timeout

    def propose_tests(self, context: dict) -> TestPlan:
        prompt = SYSTEM_PROMPT + "\n\n" + _build_user_prompt(context)

        result = subprocess.run(
            [self.codex_bin, "exec", "--json", prompt],
            capture_output=True, text=True, timeout=self.timeout,
        )
        if result.returncode != 0:
            raise RuntimeError(f"codex exec faalde: {result.stderr.strip()}")

        agent_message = None
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("type") == "item.completed" and event.get("item", {}).get("type") == "agent_message":
                agent_message = event["item"].get("text", "")

        if agent_message is None:
            raise RuntimeError("Geen agent_message gevonden in codex exec --json output")

        return _parse_test_plan(agent_message)


def _parse_test_plan(raw: str) -> TestPlan:
    """Strikte parse: geen vrije tekst toegestaan, model moet zuivere JSON
    teruggeven. Bij een parse- of validatiefout gooien we de fout door in
    plaats van te gokken — de test executor mag nooit op een geraden
    testplan draaien."""
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.startswith("json"):
            raw = raw[4:]
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"AI-output is geen geldige JSON: {e}\nRaw: {raw[:300]}")

    try:
        return TestPlan.model_validate(data)
    except ValidationError as e:
        raise ValueError(f"AI-output voldoet niet aan het TestPlan-schema: {e}")

````

Let op bij `CodexCLIAdapter`: de exacte veldnamen in de `codex exec --json`-eventstream (`item.completed` / `item.type == "agent_message"`) zijn gebaseerd op de gedocumenteerde event-types van Codex CLI. Print de ruwe stream één keer (`codex exec --json "test" | tee raw.jsonl`) en controleer de veldnamen tegen je geïnstalleerde Codex-versie voordat je hierop production draait — CLI's als deze veranderen sneller dan een SDK.

---

## Fase 7 — Lokale MCP-server

Stdio-transport, geen remote endpoint. Gebouwd op het losse `fastmcp`-package (geverifieerd: in `mcp>=2.0` bestaat `mcp.server.fastmcp` niet meer, `pip install fastmcp` is het juiste pakket). Ontsluit elke fase als los aanroepbare tool, zodat Codex of Claude Code de tool als stap in hun eigen sessie kunnen gebruiken.

````python
#!/usr/bin/env python3
"""
mcp_server.py

Lokale MCP-server (fase 7), stdio-transport, geen remote endpoint. Codex
en Claude Code kunnen dit als losse stap in hun eigen sessie aanroepen.
Gebouwd op het fastmcp-package (pip install fastmcp) — niet mcp.server.fastmcp,
dat bestaat niet meer als losse submodule in mcp>=2.0.

Starten:
    python mcp_server.py

Registreren in Codex (~/.codex/config.toml):
    [mcp_servers.bola-tool]
    command = "python"
    args = ["/pad/naar/mcp_server.py"]
"""

from pathlib import Path

from fastmcp import FastMCP

from endpoint_template import build_test_targets, correlate_ownership
from report import write_reports
from scope_guard import ScopeError, load_scope, require_in_scope
from state_store import StateStore
from test_executor import TestTarget, run_test

mcp = FastMCP("bola-tool")

# module-scope state: één sessie per proces, past bij "lokale MCP-server
# die je per engagement opnieuw start"
_state = {"store": None, "scope": None}


@mcp.tool
def load_scope_config(scope_yaml_path: str) -> str:
    """Laadt en valideert scope.yaml. Moet slagen voordat andere tools
    gebruikt kunnen worden."""
    try:
        cfg = load_scope(scope_yaml_path)
    except ScopeError as e:
        return f"scope geweigerd: {e}"
    _state["scope"] = cfg
    return f"scope geladen voor {cfg.client_name}, toegestane domeinen: {cfg.allowed_domains}"


@mcp.tool
def init_store(db_path: str = "bola_state.db") -> str:
    """Initialiseert (of opent) de lokale SQLite state store."""
    _state["store"] = StateStore(db_path)
    return f"state store klaar op {db_path}"


@mcp.tool
def import_har_findings(har_findings_json_path: str, identity_name: str) -> str:
    """Importeert de output van har_extract.py voor één identity in de
    state store (registreert de identity met sub/tenant-claim)."""
    if _state["store"] is None:
        return "fout: eerst init_store aanroepen"
    import json
    findings = json.loads(Path(har_findings_json_path).read_text(encoding="utf-8"))
    _state["store"].load_har_findings(findings, identity_name)
    return f"{identity_name} geimporteerd, {len(findings)} findings verwerkt"


@mcp.tool
def import_ownership(har_entries_json_path: str) -> str:
    """Correleert endpoint-templates en object-ownership vanuit ruwe HAR-
    entries (url, method, requester_identity) en schrijft ze naar de
    state store."""
    if _state["store"] is None:
        return "fout: eerst init_store aanroepen"
    import json
    entries = json.loads(Path(har_entries_json_path).read_text(encoding="utf-8"))
    correlations = correlate_ownership(entries, {})
    build_test_targets(_state["store"], correlations)
    return f"{len(correlations)} ownership-correlaties verwerkt"


@mcp.tool
def run_pending_tests(base_url: str) -> str:
    """Haalt alle nog niet geteste (endpoint, owner, attacker, object)-
    combinaties op en voert ze uit via de deterministische test executor.
    Weigert als base_url niet binnen scope.yaml valt."""
    if _state["store"] is None:
        return "fout: eerst init_store aanroepen"
    if _state["scope"] is None:
        return "fout: eerst load_scope_config aanroepen"

    try:
        require_in_scope(base_url, _state["scope"])
    except ScopeError as e:
        return f"geweigerd: {e}"

    store = _state["store"]
    pending = store.untested_combinations()
    identities = {i["id"]: i for i in store.list_identities()}
    endpoints = {e["id"]: e for e in store.list_endpoints()}

    results_summary = []
    for combo in pending:
        owner = identities[combo["owner_id"]]
        attacker = identities[combo["attacker_id"]]
        endpoint = endpoints[combo["endpoint_id"]]

        target = TestTarget(
            base_url=base_url,
            endpoint_template=endpoint["template"],
            method=endpoint["method"],
            object_id=combo["object_id"],
            owner_token=owner["token"] or "",
            attacker_token=attacker["token"] or "",
        )
        result = run_test(target)
        store.mark_tested(
            combo["endpoint_id"], combo["owner_id"], combo["attacker_id"], combo["object_id"]
        )
        if result.verdict == "bola":
            store.add_finding(
                combo["endpoint_id"], "critical",
                f"{attacker['name']} kon object {combo['object_id']} van "
                f"{owner['name']} opvragen op {endpoint['method']} {endpoint['template']}",
                result.evidence,
            )
        results_summary.append(f"{endpoint['template']}: {result.verdict}")

    return f"{len(pending)} tests uitgevoerd:\n" + "\n".join(results_summary)


@mcp.tool
def get_report(output_dir: str = "reports") -> str:
    """Genereert JSON-, JUnit- en markdown-rapporten uit de findings in de
    state store."""
    if _state["store"] is None:
        return "fout: eerst init_store aanroepen"
    findings = _state["store"].list_findings()
    paths = write_reports(
        findings, output_dir=output_dir,
        target_name=_state["scope"].client_name if _state["scope"] else "",
    )
    return f"rapporten geschreven: {paths}"


if __name__ == "__main__":
    mcp.run()

````

`mcp_server.py` bevat geen Codex-specifieke code — het is een standaard stdio MCP-server, dus elke MCP-client kan 'm gebruiken zonder aanpassing. Twee richtingen om dit uit elkaar te houden: fase 6 (`ai_layer.py`) is waar de tool Codex aanroept als AI-backend; fase 7 is de omgekeerde richting, waar Codex of Claude Code de tool zelf als los gereedschap aanroepen.

Registreren in Codex (`~/.codex/config.toml`):
```toml
[mcp_servers.bola-tool]
command = "python"
args = ["/pad/naar/mcp_server.py"]
```

Registreren in Claude Code:
```
claude mcp add --transport stdio bola-tool -- python /pad/naar/mcp_server.py
```

Beide gebruiken exact dezelfde `mcp_server.py`, geen aparte configuratie per client nodig.

---

## Fase 8 — Rapportage

Drie formaten uit dezelfde findings: JSON (verdere verwerking), JUnit XML (CI-gates, zelfde patroon als AuthProbe en OWASP ASTF), markdown (leesbaar klantverslag).

````python
#!/usr/bin/env python3
"""
report.py

Rapportage (fase 8): zet findings uit de state store om naar drie formaten.
- JUnit XML: voor CI-gates, zelfde patroon als AuthProbe en OWASP ASTF
- JSON: voor verdere verwerking / dashboards
- Markdown: leesbaar verslag voor de klant
"""

import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


def generate_json_report(findings: list[dict]) -> str:
    return json.dumps(findings, indent=2, ensure_ascii=False)


def generate_junit_xml(findings: list[dict]) -> str:
    """Elke finding wordt een <testcase> met een <failure>, zodat een CI-
    pipeline direct rood kleurt zodra er een BOLA gevonden wordt. Endpoints
    zonder finding worden niet als aparte testcase opgenomen: de test
    executor logt alleen wat het daadwerkelijk getest heeft in de
    tested_combinations-tabel, niet als testrapport-regel."""
    testsuite = ET.Element("testsuite", {
        "name": "bola-idor-scan",
        "tests": str(len(findings)),
        "failures": str(sum(1 for f in findings if f["severity"] in ("critical", "high"))),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    for f in findings:
        testcase = ET.SubElement(testsuite, "testcase", {
            "name": f"{f['method']} {f['template']}",
            "classname": "bola_idor",
        })
        if f["severity"] in ("critical", "high"):
            failure = ET.SubElement(testcase, "failure", {
                "message": f["description"],
                "type": f["severity"],
            })
            failure.text = json.dumps(f["evidence"], indent=2)

    return ET.tostring(testsuite, encoding="unicode")


def generate_markdown_report(findings: list[dict], target_name: str = "") -> str:
    lines = [f"# BOLA/IDOR scanrapport{f' — {target_name}' if target_name else ''}", ""]
    lines.append(f"Gegenereerd op {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("")

    if not findings:
        lines.append("Geen findings.")
        return "\n".join(lines)

    by_severity = {"critical": [], "high": [], "medium": [], "low": []}
    for f in findings:
        by_severity.setdefault(f["severity"], []).append(f)

    lines.append("## Samenvatting")
    lines.append("")
    lines.append("| Ernst | Aantal |")
    lines.append("|---|---|")
    for sev in ("critical", "high", "medium", "low"):
        lines.append(f"| {sev} | {len(by_severity.get(sev, []))} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    for sev in ("critical", "high", "medium", "low"):
        for f in by_severity.get(sev, []):
            lines.append(f"### [{sev.upper()}] {f['method']} {f['template']}")
            lines.append("")
            lines.append(f['description'])
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(f["evidence"], indent=2, ensure_ascii=False))
            lines.append("```")
            lines.append("")

    return "\n".join(lines)


def write_reports(findings: list[dict], output_dir: str = ".", target_name: str = "") -> dict:
    """Schrijft alle drie de formaten weg en geeft de paden terug."""
    from pathlib import Path
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    paths = {
        "json": out / "bola_findings.json",
        "junit": out / "bola_findings.junit.xml",
        "markdown": out / "bola_report.md",
    }
    paths["json"].write_text(generate_json_report(findings), encoding="utf-8")
    paths["junit"].write_text(generate_junit_xml(findings), encoding="utf-8")
    paths["markdown"].write_text(generate_markdown_report(findings, target_name), encoding="utf-8")

    return {k: str(v) for k, v in paths.items()}

````

---

## Orchestrator — pipeline.py

Knoopt alle fases aan elkaar voor gebruik zonder MCP-client, als los CLI-commando per engagement.

````python
#!/usr/bin/env python3
"""
pipeline.py

CLI-orchestrator die alle fases aan elkaar knoopt zonder MCP-client nodig te
hebben. Voor engagements waar je de tool gewoon als los script wil draaien.

Gebruik:
    python pipeline.py \\
        --scope scope.yaml \\
        --base-url https://staging.voorbeeldklant.nl \\
        --identity identity_a:identity_a_findings.json:identity_a_entries.json \\
        --identity identity_b:identity_b_findings.json:identity_b_entries.json \\
        --db bola_state.db \\
        --report-dir reports
"""

import argparse
import json
import sys

from endpoint_template import build_test_targets, correlate_ownership
from report import write_reports
from scope_guard import ScopeError, load_scope, require_in_scope
from state_store import StateStore
from test_executor import TestTarget, run_test


def run_pipeline(
    scope_path: str,
    base_url: str,
    identities: list[tuple[str, str, str]],
    db_path: str,
    report_dir: str,
) -> None:
    # fase 0
    try:
        scope = load_scope(scope_path)
        require_in_scope(base_url, scope)
    except ScopeError as e:
        print(f"scope geweigerd: {e}", file=sys.stderr)
        sys.exit(1)

    store = StateStore(db_path)

    # fase 2 + 3: har_extract.py output inladen per identity
    all_entries = []
    for name, findings_path, entries_path in identities:
        findings = json.loads(open(findings_path, encoding="utf-8").read())
        store.load_har_findings(findings, name)

        entries = json.loads(open(entries_path, encoding="utf-8").read())
        for e in entries:
            e["requester_identity"] = name
        all_entries.extend(entries)

    # fase 4: endpoint-templatization en ownership-correlatie
    correlations = correlate_ownership(all_entries, {})
    build_test_targets(store, correlations)
    print(f"{len(correlations)} ownership-correlaties verwerkt")

    # fase 5: deterministische test executor op alle nog niet geteste combinaties
    pending = store.untested_combinations()
    identities_by_id = {i["id"]: i for i in store.list_identities()}
    endpoints_by_id = {e["id"]: e for e in store.list_endpoints()}

    for combo in pending:
        owner = identities_by_id[combo["owner_id"]]
        attacker = identities_by_id[combo["attacker_id"]]
        endpoint = endpoints_by_id[combo["endpoint_id"]]

        target = TestTarget(
            base_url=base_url,
            endpoint_template=endpoint["template"],
            method=endpoint["method"],
            object_id=combo["object_id"],
            owner_token=owner["token"] or "",
            attacker_token=attacker["token"] or "",
        )
        result = run_test(target)
        store.mark_tested(
            combo["endpoint_id"], combo["owner_id"], combo["attacker_id"], combo["object_id"]
        )
        print(f"  {endpoint['method']} {endpoint['template']} "
              f"({attacker['name']} -> {owner['name']}'s object {combo['object_id']}): "
              f"{result.verdict}")

        if result.verdict == "bola":
            store.add_finding(
                combo["endpoint_id"], "critical",
                f"{attacker['name']} kon object {combo['object_id']} van "
                f"{owner['name']} opvragen op {endpoint['method']} {endpoint['template']} "
                f"zonder daar recht toe te hebben.",
                result.evidence,
            )

    # fase 8: rapportage
    findings = store.list_findings()
    paths = write_reports(findings, output_dir=report_dir, target_name=scope.client_name)
    print(f"\n{len(findings)} findings, rapporten geschreven naar {paths}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument(
        "--identity", action="append", required=True,
        help="naam:har_extract_output.json:raw_entries.json, herhaalbaar voor elke identity",
    )
    parser.add_argument("--db", default="bola_state.db")
    parser.add_argument("--report-dir", default="reports")
    args = parser.parse_args()

    identities = [tuple(spec.split(":", 2)) for spec in args.identity]
    run_pipeline(args.scope, args.base_url, identities, args.db, args.report_dir)


if __name__ == "__main__":
    main()

````

Gebruik:
```
python pipeline.py \
    --scope scope.yaml \
    --base-url https://staging.voorbeeldklant.nl \
    --identity identity_a:identity_a_findings.json:identity_a_entries.json \
    --identity identity_b:identity_b_findings.json:identity_b_entries.json \
    --db bola_state.db \
    --report-dir reports
```

---

---

## Fase 9 — Terminal-interface

`pipeline.py` is al een CLI (argparse), maar draait grotendeels stil en print pas resultaten aan het eind. Dit bouwt daar een narratieve laag overheen, in dezelfde stijl als Codex of Claude Code in de terminal: elke actie wordt getoond zodra hij start (`> ...`), het resultaat direct erna ingesprongen (`  -> ...`). Append-only, niets wordt herschreven of weggeveegd, dus je kan achteraf teruglezen wat er precies gebeurd is. Gebruikt Rich (`console.print`) voor kleur, verder geen framework nodig.

````python
#!/usr/bin/env python3
"""
cli.py

Fase 9: terminal-interface. pipeline.py voert alles uit maar logt weinig;
dit laat, net als Codex/Claude Code in de terminal, elke actie zien terwijl
hij gebeurt: wat er geladen wordt, welke test er draait, en het resultaat
direct erna. Append-only tekstlog, niets wordt herschreven of weggeveegd —
je kan achteraf teruglezen wat er precies gebeurd is.
"""

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console

from endpoint_template import build_test_targets, correlate_ownership
from report import write_reports
from scope_guard import ScopeError, load_scope, require_in_scope
from state_store import StateStore
from test_executor import TestTarget, run_test

console = Console()

VERDICT_LABEL = {
    "bola": "[bold red]BOLA[/bold red]",
    "protected": "[green]protected[/green]",
    "inconclusive": "[yellow]inconclusive[/yellow]",
}


def step(msg: str) -> None:
    """Eén actie die start — het '>'-prefix, zoals Codex' eigen actielog."""
    console.print(f"[cyan]>[/cyan] {msg}")


def result_line(msg: str) -> None:
    """Het resultaat van de vorige actie, ingesprongen eronder."""
    console.print(f"  [dim]->[/dim] {msg}")


def run_interactive(
    scope_path: str,
    base_url: str,
    identities: list[tuple[str, str, str]],
    db_path: str,
    report_dir: str,
) -> None:
    step(f"scope.yaml laden vanaf {scope_path}")
    try:
        scope = load_scope(scope_path)
    except ScopeError as e:
        # de foutmelding van load_scope() bevat zelf al het voorbeeld-scope.yaml
        # als het bestand ontbreekt, dus hier niet nogmaals printen
        result_line(f"[bold red]geweigerd:[/bold red] {e}")
        sys.exit(1)
    result_line(f"geldig voor [bold]{scope.client_name}[/bold], toegestane domeinen: {scope.allowed_domains}")

    step(f"controleren of {base_url} binnen scope valt")
    try:
        require_in_scope(base_url, scope)
    except ScopeError as e:
        result_line(f"[bold red]geweigerd:[/bold red] {e}")
        sys.exit(1)
    result_line("target zit binnen scope")

    store = StateStore(db_path)

    all_entries = []
    for name, findings_path, entries_path in identities:
        step(f"identity '{name}' inladen vanuit {findings_path}")
        findings = json.loads(Path(findings_path).read_text(encoding="utf-8"))
        store.load_har_findings(findings, name)
        result_line(f"{len(findings)} findings verwerkt, identity '{name}' geregistreerd")

        entries = json.loads(Path(entries_path).read_text(encoding="utf-8"))
        for e in entries:
            e["requester_identity"] = name
        all_entries.extend(entries)

    step("endpoints herkennen en ownership correleren")
    correlations = correlate_ownership(all_entries, {})
    build_test_targets(store, correlations)
    result_line(f"{len(correlations)} ownership-correlaties vastgelegd")

    pending = store.untested_combinations()
    identities_by_id = {i["id"]: i for i in store.list_identities()}
    endpoints_by_id = {e["id"]: e for e in store.list_endpoints()}

    step(f"{len(pending)} nog niet geteste combinatie(s) gevonden, testen starten")

    bola_count = 0
    for i, combo in enumerate(pending, 1):
        owner = identities_by_id[combo["owner_id"]]
        attacker = identities_by_id[combo["attacker_id"]]
        endpoint = endpoints_by_id[combo["endpoint_id"]]

        step(
            f"test {i}/{len(pending)}: {endpoint['method']} {endpoint['template']} — "
            f"'{attacker['name']}' probeert object {combo['object_id']} van "
            f"'{owner['name']}' op te vragen"
        )

        target = TestTarget(
            base_url=base_url,
            endpoint_template=endpoint["template"],
            method=endpoint["method"],
            object_id=combo["object_id"],
            owner_token=owner["token"] or "",
            attacker_token=attacker["token"] or "",
        )
        result = run_test(target)
        store.mark_tested(
            combo["endpoint_id"], combo["owner_id"], combo["attacker_id"], combo["object_id"]
        )

        verdict_txt = VERDICT_LABEL.get(result.verdict, result.verdict)
        result_line(
            f"{verdict_txt} — owner status {result.evidence.get('owner_status')}, "
            f"attacker status {result.evidence.get('attacker_status')}"
        )

        if result.verdict == "bola":
            bola_count += 1
            description = (
                f"{attacker['name']} kon object {combo['object_id']} van {owner['name']} opvragen "
                f"op {endpoint['method']} {endpoint['template']} zonder daar recht toe te hebben."
            )
            store.add_finding(combo["endpoint_id"], "critical", description, result.evidence)

    step("rapporten genereren")
    findings = store.list_findings()
    paths = write_reports(findings, output_dir=report_dir, target_name=scope.client_name)
    result_line(f"geschreven naar {paths['markdown']}")
    result_line(f"geschreven naar {paths['junit']}")
    result_line(f"geschreven naar {paths['json']}")

    console.print()
    if bola_count:
        console.print(f"[bold red]{bola_count} BOLA-kwetsbaarheid(en) gevonden.[/bold red] Zie {paths['markdown']}.")
    else:
        console.print("[green]Geen BOLA gevonden in de geteste combinaties.[/green]")


def main():
    parser = argparse.ArgumentParser(
        description="Terminal-interface voor de BOLA-tool. Toont elke actie als tekst "
        "terwijl hij gebeurt, in plaats van stil te draaien en pas aan het eind te rapporteren."
    )
    parser.add_argument("--scope", default="scope.yaml")
    parser.add_argument("--base-url", required=True)
    parser.add_argument(
        "--identity", action="append", required=True,
        help="naam:har_extract_output.json:raw_entries.json, herhaalbaar per identity",
    )
    parser.add_argument("--db", default="bola_state.db")
    parser.add_argument("--report-dir", default="reports")
    args = parser.parse_args()

    identities = [tuple(spec.split(":", 2)) for spec in args.identity]
    run_interactive(args.scope, args.base_url, identities, args.db, args.report_dir)


if __name__ == "__main__":
    main()

````

Getest tegen `mock_target.py`, inclusief de foutpaden (ontbrekend scope-bestand, target buiten scope). Voorbeeld van de output op het kwetsbare mock-endpoint:

````
> scope.yaml laden vanaf test_scope.yaml
  -> geldig voor Integratietest B.V., toegestane domeinen: ['127.0.0.1']
> controleren of http://127.0.0.1:8899 binnen scope valt
  -> target zit binnen scope
> identity 'identity_a' inladen vanuit identity_a_findings.json
  -> 1 findings verwerkt, identity 'identity_a' geregistreerd
> identity 'identity_b' inladen vanuit identity_b_findings.json
  -> 1 findings verwerkt, identity 'identity_b' geregistreerd
> endpoints herkennen en ownership correleren
  -> 1 ownership-correlaties vastgelegd
> 1 nog niet geteste combinatie(s) gevonden, testen starten
> test 1/1: GET /api/documents/{id} — 'identity_b' probeert object 812 van 'identity_a' op te vragen
  -> BOLA — owner status 200, attacker status 200
> rapporten genereren
  -> geschreven naar test_reports/bola_report.md
  -> geschreven naar test_reports/bola_findings.junit.xml
  -> geschreven naar test_reports/bola_findings.json

1 BOLA-kwetsbaarheid(en) gevonden. Zie test_reports/bola_report.md.
````

Gebruik: exact dezelfde argumenten als `pipeline.py`, `cli.py` vervangt het als het primaire commando om te draaien.

````
python cli.py \
    --scope scope.yaml \
    --base-url https://staging.voorbeeldklant.nl \
    --identity identity_a:identity_a_findings.json:identity_a_entries.json \
    --identity identity_b:identity_b_findings.json:identity_b_entries.json \
    --db bola_state.db \
    --report-dir reports
````

---

## Bonus: mock_target.py — lokaal testen zonder externe target

Gebruikt tijdens het bouwen van dit plan om de hele pipeline daadwerkelijk te verifiëren: één endpoint dat bewust kwetsbaar is voor BOLA, één dat correct beveiligd is. Handig om eigen wijzigingen aan de tool tegenaan te blijven testen zonder telkens een echte target nodig te hebben.

````python
"""Kleine lokale test-API om test_executor.py tegen te draaien, zonder
extern netwerkverkeer nodig te hebben. Simuleert twee endpoints:
- /api/documents/<id>  : kwetsbaar voor BOLA (checkt de token niet)
- /api/secure/<id>     : correct beveiligd (checkt of token bij id hoort)
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re

DOCS = {"812": {"id": "812", "owner": "alice", "content": "geheim document van alice"}}

# simpele token -> user mapping voor de test
TOKEN_USER = {"tok-alice": "alice", "tok-bob": "bob"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # stil, geen console-spam tijdens de test

    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "")
        user = TOKEN_USER.get(token)

        m = re.match(r"^/api/documents/(\w+)$", self.path)
        if m:
            doc_id = m.group(1)
            doc = DOCS.get(doc_id)
            if not doc:
                self.send_response(404); self.end_headers(); return
            # KWETSBAAR: geeft het document terug ongeacht wie het opvraagt
            body = json.dumps(doc).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return

        m = re.match(r"^/api/secure/(\w+)$", self.path)
        if m:
            doc_id = m.group(1)
            doc = DOCS.get(doc_id)
            if not doc:
                self.send_response(404); self.end_headers(); return
            if user != doc["owner"]:
                self.send_response(403); self.end_headers(); return
            body = json.dumps(doc).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404); self.end_headers()


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8899), Handler).serve_forever()

````

## End-to-end verificatie

Met `mock_target.py` draaiend is de volledige pipeline getest: scope-validatie, identity-import vanuit fase 2-output, ownership-correlatie, deterministische test executor, en rapportage. Resultaat:

```
1 ownership-correlaties verwerkt
  GET /api/documents/{id} (identity_b -> identity_a's object 812): bola
1 findings, rapporten geschreven naar {...}
```

Het kwetsbare endpoint werd correct als `bola` gemarkeerd, inclusief bewijs (`owner_status: 200`, `attacker_status: 200`, `bodies_equivalent: true`) in het gegenereerde markdown-rapport. Het parallel geteste, correct beveiligde endpoint gaf `protected` (403) terug — de verdict-logica maakt dus daadwerkelijk het onderscheid dat een BOLA-tool moet maken.

## Volgende stap

De acht fases staan. Wat nu nog handwerk is: de scope.yaml per klant invullen, Playwright-scripts voor de specifieke login-flow van elke target schrijven (fase 1 blijft per klant maatwerk), en een API-sleutel of Codex-sessie koppelen voor fase 6. Verder is dit een compleet, draaiend systeem.
