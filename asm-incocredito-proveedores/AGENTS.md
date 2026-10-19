# AGENTS.md — Blueprint de ASM-Informe-Proveedores

Documento heredable: sirve como **base de referencia** para reutilizar este proyecto en otro similar.
Describe arquitectura, stack, flujo de escaneo, generación de reportes, despliegue como servicio Windows y convenciones.

---

## 1. Propósito

Pipeline de **ASM** (Attack Surface Management) por proveedor tercero. Realiza un escaneo (pasivo → activo), recopila
hallazgos en un `asm_report.json` y genera **informes en HTML/PDF** listos para entrega, servidos por un dashboard HTTPS.

El pipeline **no interactúa con la fuente primaria directamente** en modo pasivo; en modo activo sí sondea puertos,
rathes, banners y WAF.

---

## 2. Stack

- **Lenguaje**: Python 3.11 (`C:\Program Files\Python311\python.exe`).
- **Web**: `FastAPI` + `uvicorn` (dashboard). `pydantic` para modelos.
- **Renderer PDF**: `playwright` (Chromium) — solo se usa en el backend server (el entorno local no tiene `python-multipart`,
  por lo que regenerar PDF a mano se hace con un script Playwright directo).
- **Networking**: `requests`, `dnspython` (resolución DNS/CNAME).
- **Escáner externo**: `FinalRecon` (CLI, salida XML/JSON) — `finalrecon_runner.py`.
- **DB VULN**: CSV locales en `vulndb/` + EPSS (`api.first.org`) + CISA KEV — `vuln_lookup.py`.

### Dependencias clave (requirements.txt)
```
requests>=2.28.0
dnspython>=2.4.0
```
Uso real en runtime: `fastapi, pydantic, uvicorn, async_playwright` (dashboard_server.py).

---

## 3. Arquitectura de módulos (raíz del repo)

**Orquestación / scanner:**
- `asm_scan.py` — **entrypoint de escaneo**. Modelos (`ProviderASM`, etc.), `_scan_provider`, `run_all`, CLI, escribe
  `asm_report.json` + HTML.
- `scan_from_list.py` — escanea lote de dominios desde una lista.
- `ip_pivot.py` — pivotaje IP ↔ dominio.
- `proxy_rotation.py`, `log_utils.py` — utilidades.

**Recolección de datos (por módulo):**
- `api_discovery.py`, `subdomain_brute.py`, `banner_grab.py`, `port_scanner.py`, `ip_pivot.py`.
- `finalrecon_runner.py` — orquesta FinalRecon (subdominios, correos, DNS, GeoIP).
- `vuln_lookup.py` — CVEs (vulndb CSVs + EPSS + CISA KEV).
- Regla correo/DNS al apex (`apex_of` en `asm_scan.py:resolve_dns`): MX/SPF/DMARC/DKIM/NS se consultan sin el `www.` (preguntar al host da falsos ausentes). `TLSProbe.chain_issue` + reintento con certificado (cadena incompleta vs TLS caído); `HTTPProbe.verified` + reintento sin validar para estado/cabeceras reales.
- `external_sources.py` — **OSINT + fuentes externas**: `run_all(domain)` devuelve dict con claves
  `whois, dnsdumpster, shodan, censys, theharvester, internetdb, shodan_exposure, scanned_at`. Integra Shodan InternetDB
  (sin API key, `https://internetdb.shodan.io/{ip}`) y una heurística de "exposure".
- `prism_integration.py` — **enriquecimiento Prism** (https://github.com/NovaCode37/Prism-platform, OSINT Toolkit v2.6)
  por nivel: N1 pasivo `leak_lookup, onion_checker, gravatar, github_recon`; N2 semi-activo + `website_analyzer`;
  N3/N4 activo/invasivo + `smtp_verify, virustotal, abuseipdb` (SKIPPED tolerante sin API keys). Alimenta los emails
  desde `_collect_emails(external_data)` (raíz + whois/theharvester) y las IPs desde `dns.ipv4`. Módulos vendorizados en
  `prism_osint/`.
- `kumo_integration.py`, `kumo_engine.py` — **KUMO-Domain-Recon-Tool** (Wayback, breach intel, robots, favicon, JS
  secrets, content intelligence, API fuzzer, Nuclei) por nivel; emails alimentan breach intel.
- `strix_integration.py` — **enriquecimiento Strix** (https://github.com/usestrix/strix, agente IA de pentesting,
  Apache-2.0). CLI Python>=3.12, requiere Docker corriendo + LLM API key (`STRIX_LLM` + `LLM_API_KEY`, costo $ por
  scan, controlable con `--max-budget`). **NO existe modo pasivo** (herramienta activa). Niveles: pasivo (1) -> no
  corre (SKIPPED por diseño); semi-activo (2) -> `--scan-mode quick`; activo (3) -> `standard`; invasivo (4) ->
  `deep`. Skips tolerantes si falta binario `strix`/Docker/LLM key. `run_strix(domain, test_level)` invoca
  `strix -n --target https://<domain> --scan-mode <m>` en headless y parsea `strix_runs/<run>/vulnerabilities.json`
  (hallazgos: id/title/severity/cvss/cve/cwe/endpoint/remediation_steps/evidence/poc_script_code) + `run.json`
  (status, scan_results, llm_usage total_cost_usd). Alimenta `ProviderASM.strix`, propagado a `asm_report.json`
  vía `dataclasses.asdict()`.
- `claude_osint_integration.py` — **enriquecimiento Claude-OSINT**
  (https://github.com/elementalsouls/Claude-OSINT, biblioteca de skills markdown + 2 scripts Python; aquí solo se
  ejecutan las capacidades keyless accionables de valor incremental). Niveles: N1 pasivo `m365_fingerprint`
  (tenant Azure/Entra vía getuserrealm.srf + OIDC + Autodiscover), `spf_supply_chain` (verdict SPF/DMARC composite +
  conteo recursivo de lookups/voids RFC 7208, dead-includes), `org_attribution` (GLEIF LEI + direct-children, crt.sh
  `O=` CT-org pivot), `cti_chatter` (ransomwatch + ransomware.live + HN), `passive_dns_extra` (CertSpotter/OTX/
  ThreatMiner/URLScan/AnubisDB), `cloud_native_fp` (fingerprint CNAME de cloud prov), `h1_reference` (GraphQL
  HackerOne sin key); N2 semi-activo + `saml_oidc_probe`, `secret_scan` (catálogo 80-patterns en HTML público); N3/N4
  + `credential_validators` (SKIPPED tolerante sin secretos). Entrada: emails/IPs/org reutilizadas del bloque Prism,
  SPF/DMARC desde `dns_p.spf_record`/`dmarc_record` (presentes en el apex; ausentes en `www.` prototípicamente).
  Scripts vendorizados en `claude_osint_scripts/`. Llamado desde `_scan_provider` tras Prism.
- `social_osint.py`, `proxy_rotation.py` (SOlOSINT social).
- `webwaf_detect.py` — detección disocrea de WAF/CDN (adaptado de Raccoon MIT).
- `cloud_storage_scan.py` — detección de buckets/cloud storage (adaptado de Raccoon MIT).

**Reportes (multi-brand):**
- `pasivo_canon.py` — **set canónico de items pasivos (nivel 1) compartido por los generadores vivos con canon (B5-B6)**.
  `collect_pasive_items(p)` (typo "pasive" intencional) devuelve la lista canónica ordenada con estado explícito por item
  (`ok|vacio|sinclave|error|sinDatos`) y 10 grupos: DNS apex completo (IPv4/MX/NS/SPF/DMARC/DKIM/DNSSEC/CAA/MTA-STS/
  TLS-RPT/BIMI), Subdominios CT, leaks, typosquatting, DNSBL/URLhaus, OSINT externo (WHOIS/DNSDumpster/Shodan/Censys/
  theHarvester/InternetDB/Exposure), KUMO N1, Prism N1, Claude-OSINT N1 y Social OSINT. Los generadores filtran
  `status=="ok"` (solo items con dato) para que en modo "pasivo" los 5 informes muestren exactamente el MISMO set de
  items, cada uno con su estilo: TPRA `pasivo_canon_block` tras `_external_block`; B5-B6 `<h4>Pasivo · grupo</h4>`
  y hallazgo resumen `Panorama pasivo canonico` (evidencia con detalle por grupos, truncado a 3000).
  (Estilos retirados: PP filas `fc-row`, GC/BC `<h4>`, S3 `_pasivo_canon_span`, B1/B2 hallazgo.)
- `semi_canon.py` — **set canónico de items semi-activos (nivel 2) compartido por los generadores vivos con canon (B5-B6)**.
  `collect_semi_active_items(p)` devuelve los items adicionales al pasivo en modo "semi-activo" (mismo estado
  `ok|vacio|sinclave|error`): Servicios (Puerto 443/TLS/Certificado/SAN), HTTPS (HTTP status/fingerprint/redirección),
  Cabeceras de seguridad (HSTS/CSP/XFO/XCTO/Referrer-Policy/Permissions-Policy), Superficie web (rutas públicas/WAF/
  cloud), Mantenimiento (patching/supply chain/CSP findings/cookies), KUMO N2 (favicon hash), Prism N2
  (Website Analyzer) y Claude-OSINT N2 (SSO/OIDC probe/secret scan). Render por estilo análogo al pasivo: TPRA
  `semi_canon_block` tras `pasivo_canon_block`; B5-B6 `<h4>Semi-activo · grupo</h4>` y hallazgo
  `Panorama semi-activo canonico`. El detalle por grupo NO trunca por grupo (usa todos los items del grupo, solo topa a 3000 chars).
- `generate_socradar_style_report.py` — informe **TPRA** principal (activo). Bloques por proveedor incl. WAF/cloud,
  `kumo_block`, `prism_block` y `claude_osint_block`, y secciones `Shodan InternetDB` / `Shodan Internet Exposure`.
- **RETIRADOS 2026-10-13** (generador ausente en disco, endpoints dados de baja): `generate_ppasivo_report.py`,
  `generate_bancolombia_report.py`, `generate_scor3bank_report.py`. No se construyen ni se descargan; la UI solo ofrece SARIF/OpenVEX en su lugar.
- **RETIRADOS 2026-10-14**: `generate_cibest_report.py` (GC), `generate_beta1_report.py` (B1),
  `generate_b2_scorecard_report.py` (B2).
- **RETIRADOS 2026-10-14**: `generate_socradar_style_report.py` (TPRA, "PDF Generic"). Sin dependencias de otros formatos; endpoints y botones dados de baja.
- **RETIRADOS 2026-10-15**: `generate_b3_unified_report.py` (B3) y `generate_b4_unified_report.py` (B4). B5 ya era
  superconjunto estricto de ambos; el dashboard importa `domain_score`/`compute_factores` desde `generate_b5_unified_report.py`.
  Endpoints `/api/download/{pdf,html}-b3|b4` y `/api/history/{id}/{pdf,html}-b3|b4` dados de baja (fallbacks de historial
  ahora `(6, 7, 5)`); botones y documentacion de la UI solo ofrecen B5-B7.
- Generadores vivos (5): `generate_b5/b6_unified_report.py`, `generate_b7_unified_report.py` (B7),
  `generate_asm_passive_active_report.py`. Los clasicos (B5-B6)
  integran Prism y Claude-OSINT (`claude_osint_block`/`prism_block`; B5-B6 como hallazgos/bloques),
  `collect_pasive_items(p)` y `collect_semi_active_items(p)` para los panoramas homologados, y **Strix** solo si su
  `status=="ok"` (B5-B6 hallazgo). B7 (SSC-style) consume `kumo.breachintel` y
  `claude_osint.cti_chatter` dentro de `collect_issues`, mas issues OWASP Agentic/Web (`appsec`). Passive-active solo
  grid OWASP propio, sin Prism/Strix por diseno.
- Exportaciones: `generate_sarif_export.py`, `generate_vex_export.py` (OpenVEX 0.2.0, explotabilidad), `generate_openapi_export.py`, `generate_dast_config.py`.
- `owasp_web.py` — espejo de `owasp_agentic.py` contra OWASP Web Top 10 2025 (W-01..W-10); `_scan_provider` lo evalua a `m["owasp_web"]` junto a `m["owasp"]`. Renderizado junto al bloque Agentic en B5-B6 (`<h4>`) y passive-active (grid) + B7 como issues `appsec` (Agentic y Web con impacto -3.0/-1.5/-0.5 por grado).
- `severity.py` — severidades canonicas CRITICAL/HIGH/MEDIUM/LOW/INFO (hve-core security-reviewer-formats) + `sarif_level/normalize/rank`. Cableado en `generate_sarif_export.py` (`_issue_to_result`) y en B5/B6 (`import severity`; comparaciones `== "high"/"medium"`, orden de Strix y mapa CSP via `normalize`, identico en datos EN). VEX no tiene eje de severidad por spec.
- Descargas del dashboard: `/api/download/sarif`, `/api/download/vex` (+ `/api/history/{id}/sarif|vex`), generadas al vuelo desde `asm_report.json` via `build_sarif_log/build_vex_doc`; `/api/download/sbom` (CycloneDX del producto, sin variante de historial por ser estatico).
- B6 tres metricas con motor propio, en orden (B6-v3.1, 2026-10-16): Overall = benchmark B7 (`b7_provider_scores()`, sec. 4); Domain = higiene B5/B6 (`domain_score` por proveedor, sec. 5); Factor = consolidacion B5/B6 (`compute_factores` 10 factores, sec. 6). Sin doble deduccion entre metricas; la trazabilidad heuristica audita el Factor Score y la auditoria B7 (sec. 4.1) el Overall. `_B6_SSC` queda como catalogo canonico de los 10 nombres (orden + test).
- `generate_sbom_export.py` — SBOM CycloneDX 1.5 del producto (`requirements*.txt` como purls + 8 vendorizados/externos). Cubre skill hve-core supply-chain-security a nivel inventario.
- `llm_guardrails.py` — guardarrailes OWASP LLM 2025 para Strix: LLM10 presupuesto (`STRIX_BUDGET_USD`, default 5.0), LLM06 modo atado al nivel, LLM02 redaccion de secretos en stdout/stderr. `run_strix` adjunta `guardrails` en `status=="ok"`.
- `tests/` — suite `unittest` stdlib (23 tests: severity, owasp_web, owasp_agentic, exports, guardrails). Corre con `python -m unittest discover -s tests` en ambos interpretes; paso en `pr-validation.yml`.
- `docs/risks/` — `risk-register.md` + `risk-mitigation-plan.md` (matriz P×I, skill hve-core risk-register).

**Servidor / entrega:**
- `dashboard_server.py` — **servidor FastAPI** (HTTPS 8765) que ejecuta escaneos bajo demanda y sirve
  reportes/descargas/edeaa. El historial (`/api/history`) agrega por escaneo Sector (autodetectado
  precia o `sector`/`industry`/`industria` en providers.json), Score (overall precia), Riesgos
  (conteo por severidad mayor) y Estado (Bueno >=90, Atencion >=80, si no Revisar).

---

## 4. Datos y salidas

- `asm_report.json` — **intermedio canónico** que consumen todos los generadores de reportes. Se genera SIEMPRE;
  en dashboard no se expone su descarga (endpoints JSON deshabilitados).
- `dashboard_workspace/last/` — último escaneo (asm_report.json, HTML, PDFs).
- `salida_test/` — salidas de prueba.
- `static/` — assets del dashboard.
- `vulndb/` — bases CSV de vulnerabilidades.

---

## 5. Cómo correr (CLI)

### Escaneo
```
python asm_scan.py --providers providers.json --out-json salida_test/asm_report.json --out-html salida_test/informe.html --test-type activo
```
- `--test-type`: `pasivo | semi-activo | activo | invasivo` (default `activo`).
- `--no-subdomains`, `--no-public-paths`: omiten partes opciones del escaneo.

### Generar un reporte (por separado, desde un asm_report.json existente)
```
# TPRA (SOCRadar-style)
python generate_socradar_style_report.py --asm <asm_report.json> --out <informe.html>
# SARIF + OpenVEX
python generate_sarif_export.py --input <asm_report.json> --output <asm_sarif.json>
python generate_vex_export.py --input <asm_report.json> --output <asm_vex.json>
```
> Todos los generadores vivos y exportes usan `--asm/--input` y `--out/--output` (`--asm` en TPRA/GC/B1-B7; `--input` en SARIF/VEX). Revisar `--help` de cada uno.

### Servidor
```
python dashboard_server.py --host 0.0.0.0 --port 8765 --ssl
```
Usa TLS de `C:\ProgramData\ASM-Dashboard\` (`ASM_TLS_CERT`/`ASM_TLS_KEY`) para HTTPS. Usa envs `ASM_DASHBOARD_HOST/PORT`.
Escritura API con bearer (`ASM_API_TOKEN` o `api_token.txt` generado al primer arranque); ver `SECURITY.md`.

---

## 6. Servicio Windows (NSSM)

- **Nombre**: `ASM-Dashboard`
- **Proveedor**: OPSSM (`sc.exe` para detener/arrancar) desde PowerShell:
  ```
  sc.exe stop ASM-Dashboard; Start-Sleep 2; sc.exe start ASM-Dashboard
  ```
- Comando real: `C:\Program Files\Python311\python.exe dashboard_server.py --port 8765 --host 0.0.0.0 --ssl`
- Verificación:
  ```
  curl.exe -sk -o NUL -w "%{http_code}\n" https://127.0.0.1:8765/            # dashboard → 200
  curl.exe -sk -o NUL -w "%{http_code}\n" https://127.0.0.1:8765/api/history  → 200
  sc.exe query ASM-Dashboard | findstr STATE PID
  ```
- **Cuándo reiniciar**: solo si cambia `dashboard_server.py` (o HTML/CSS que sirva desde caché). Los cambios en
  `asm_scan.py`, `external_sources.py` y los `generate_*.py` se aplican en cada nuevo escaneo (se leen del dashbèse subproceso) → **no requieren reinicio**.

---

## 7. Convenciones / modos comunes del proyecto

- **Idioma**: el código y los informes usan español (mensajes, etiquetas). Los IDs/keys en JSON (quebe) en inglés.
- **Identación**: 4 espacios. Strings de reportes con `f"""..."""` multilinea.
- **Mocks**: nunca se usa `&&` enbash (PowerShell 5.1 no lo soporta); encadenar con `; if ($?) { ... }`.
- **Emojis/PDF**: evita emojis Unicode en reportos (se ven como `?` en el PDF). Usa ASCII (`--`, `->`, `sin datos`).
- **`<h4>` vs `<h3>`**: usa `h4` en bloques de `_external_block` (cambiar por error rompe la indentación).
- **Sin comentar**: se agregan archivos/modificaciones sin comentario innecesario.

---

## 8. Patrón de integración heredable (ejemplo reusado 3 veces: KUMO, Prism, Claude-OSINT)

1. **Añadir campos** al dataclass del proveedor (`ProviderASM` en `asm_scan.py`) y generarlos desde esa clase.
2. **Conectarlo** en `_scan_provider` (por nivel de test, ej. HTML>=2).
3. **Exponer** la data en `asm_report.json` (idem). `dataclasses.asdict()` ya lo propaga.
4. **Mostrarlo** en cada generador: funciones `*_block` (TPRA) o `fc-row` (Ppipasivo) condicionadas a que exista data.
5. **Validar** con escaneo real o JSON sintético; compilar con `python -m py_compile`.

---

## 9. Fuentes externas/OSINT — estado (importante al heredar)

- `internetdb.shodan.io` — integrada, **sin API key**: `run_internetdb` + `run_shodan_exposure`.
- `exposure/exploits/honeyscore/faviconmap/geonet.shodan.io` — **NO integrables** (sin API pública estable / 4xx).
- `api.shodan.io` (oficial) requiere `SHODAN_API_KEY`.
- Raccoon (`evyatarmeged/Raccoon`, MIT, Python) — integrado selectivamente (WAF + cloud storage). No se copió el
  fuzzei de 6k paths (solapa con `probe_public_paths` + `api_discovery`).

---

## 10. SSC Scorecard - Base de conocimiento (Septiembre 2026)

Fuente: `C:\Users\Administrator\Documents\ASM\Septiembre` (8 PDFs Alcuadrado 62, AXA 91, Comfama 74 etc, 8-10 sep 2026 GrupoCibest). Guardado completo en `docs/SSC_SCORECARD_KNOWLEDGE.md`.

**Estructura fija 23-37p:** P1 portada UTC + P2 Que es SSC (A-F, C/D/F 5.4x breach, AppSec 10x) + 4 pasos (cuenta/huella/hallazgos/corrija 3d) + P3 Vision general (score 0-100 + 10 factores + historial 30d vs Our Industry) + P4-5 Elementos de accion (impacto -10.0 a <-0.1) + 10 modulos detalle con tabla evidencia `DOMINIO|URL FINAL|SHA-256|SERIAL|EVIDENCIA ["825d >=398d"]`.

**10 Factores fijos:** AppSec | Cubit | DNS | Endpoint | Hacker Chatter | IP Reputation | Info Leak | Network | Patching Cadence | Social. Scoring granular decimal ordenado por impacto (ej -10.0 TLS, -8.3 cookie, -0.7 CSP).

**Sugerencias P0 para ASM:** mapear `pasivo_canon/semi_canon -> 10 factores`, impacto decimal `IMPACT_MAP`, tabla evidencia forense por hallazgo, historial vs industria + huella digital, storytelling P2. No copiar Cubit caja negra ni pasivo-only (ASM ventaja activa).

---

## 11. Regenerate PDF a mano
El backend genera PDF con Playwright. En entorno local (sin `python-multipart`), regenerar HTML sirve con un script
Playwright directo:
```python
import asyncio
from playwright.async_api import async_playwright
async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch(); pg = await b.new_page()
        await pg.goto('file:///.../informe.html'); await pg.pdf(path='informe.pdf', format='A4', print_background=True)
        await b.close()
asyncio.run(main())
```

---

## 12. Regla Vibe Coding / opencode (2026-10-08: limpieza 148 -> 44 py)

- **Prohibido** crear `check_*.py, fix_*.py, move_*.py, find_*.py, add_*.py, remove_*.py, insert_*.py, debug_*.py` en raiz. Van a `C:\Users\ADMINI~1\AppData\Local\Temp\2\opencode` y se borran al terminar.
- Un solo `repro.py` por tarea, nunca 10 variantes.
- Pedir cambios por archivo + linea (`solo generate_b6_unified_report.py: salto de pagina antes de X`), no "arregla todo".
- `opencode.json:watcher.ignore` excluye `.venv, dashboard_workspace, salida_test, logs, vulndb, tools/_archive, *.html`. `tools/_archive/**` denegado en `permission`.
- `tools/_archive/` en `.gitignore`: no se versiona ni se indexa.

---

## 13. Auditoria - Modelo, subagentes y skills (2026-10-08)

- **Principal**: `opencode/muse-spark-1.3-contributor-free` (Muse Spark 1.3).
- **Subagentes via `Task`**: `explore` (busqueda rapida solo-lectura) y `general` (tareas complejas multi-paso). Mas `threat-detection-engineer` (read-only: `bash: deny, edit: deny` en `Workflow/.opencode/agents/threat-detection-engineer.md`).
- **Skill activo en proyecto (1)**: `threat-detection-engineer` en `Workflow/.opencode/skills/threat-detection-engineer/SKILL.md` (Sigma + ATT&CK + tuning, MIT).
- **Libreria global bajo demanda (818, no instalados)**: `C:\Users\Administrator\.agents\skills\` (origen `mukul975/Anthropic-Cybersecurity-Skills`). Se cargan por nombre con `skill`, nunca todos en `opencode.json:instructions`.
- **Subset curado para auditar este ASM** (usar solo estos, el resto solapa):
  `implementing-attack-surface-management, performing-subdomain-enumeration-with-subfinder, performing-ssl-tls-security-assessment, performing-security-headers-audit, implementing-secret-scanning-with-gitleaks, detecting-typosquatting-packages, performing-cve-prioritization-with-kev-catalog, implementing-epss-score-for-vulnerability-prioritization, performing-dns-enumeration-and-zone-transfer, analyzing-typosquatting-domains-with-dnstwist, performing-network-packet-capture-analysis, triaging-vulnerabilities-with-ssvc-framework`.
- **Respuesta oficial para auditoria**: "Principal Muse Spark 1.3 contributor-free, subagentes explore/general (+ threat-detection-engineer read-only), 818 skills disponibles bajo demanda, 1 skill activo."