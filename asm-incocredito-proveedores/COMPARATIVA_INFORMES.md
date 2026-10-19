# Comparativa de Contenido por Informe

> **RETIRADOS 2026-10-14**: Cibest, Beta1 y B2 Scorecard (mismo motivo).
> **RETIRADOS 2026-10-13**: Bancolombia, Scor3Bank y Ppasivo (generador ausente en disco,
> endpoints dados de baja en `dashboard_server.py`). Sus columnas/filas abajo se conservan
> como referencia historica. B4/B5/B6 comparten la base de B3 (misma cobertura); B7 es
> SSC-style (ver `generate_b7_unified_report.py:collect_issues`) y no esta tabulado aqui.

Leyenda: ✅ = Incluye | ❌ = No incluye | ~ = Parcial

| # | Item Evaluado | SOCRadar | Bancolombia | Cibest | Scor3Bank | Beta1 | B2 SC | B3 Unif | PA | Ppasivo |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | DNS (SPF/DMARC/DKIM/MX/NS) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 2 | DNSSEC | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 3 | CAA Records | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 4 | DANE/TLSA | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ~ |
| 5 | MTA-STS | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 6 | TLS-RPT | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 7 | BIMI | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 8 | STARTTLS | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ~ |
| 9 | TLS Negociation | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|10 | HTTP Headers (HSTS/CSP/XFO) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|11 | HTTPS Status / Redirects | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|12 | Port 80/443 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|13 | Open Ports (400+) | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ |
|14 | Subdomains (DNS prefixes) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|15 | Subdomains (CT logs) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|16 | Subdomains (Brute force) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|17 | SAN List | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|18 | Public Paths | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|19 | CVE Banner Grab | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|20 | Banner Grab (services) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|21 | API Endpoints / Shadow API | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|22 | OSV.dev Vulnerabilities | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|23 | Credential Leaks | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|24 | Typosquatting | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|25 | Subdomain Takeover | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|26 | CSP Findings | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|27 | Cookie Findings | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|28 | URLhaus | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|29 | IP Reputation (DNSBL) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|30 | Social OSINT | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|31 | WHOIS / External Sources | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|32 | FinalRecon (crawling) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|33 | IP Pivot | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|34 | Patching / EOL | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
|35 | Supply Chain | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|36 | OWASP Compliance | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|37 | Domain Score (heuristic) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|38 | EPSS Score (enrichment) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|39 | CISA KEV (enrichment) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
|40 | Risk Score compuesto | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |

## Totales

| Informe | Items incluidos | Items excluidos | Cobertura |
|---|---|---|---|
| **SOCRadar** | 38 | 2 | 95.0% |
| **Bancolombia** (RETIRADO) | 38 | 2 | 95.0% |
| **Cibest** (RETIRADO) | 38 | 2 | 95.0% |
| **Scor3Bank** (RETIRADO) | 36 | 4 | 90.0% |
| **Beta1** (RETIRADO) | 37 | 3 | 92.5% |
| **B2 Scorecard** (RETIRADO) | 37 | 3 | 92.5% |
| **B3 Unified** | 37 | 3 | 92.5% |
| **PA (Passive/Active)** | 38 | 2 | 95.0% |
| **Ppasivo** (RETIRADO) | 19 | 21 | 47.5% |

## Items excluidos por informe

| Informe | Excluye |
|---|---|
| **SOCRadar** | — |
| **Bancolombia** (RETIRADO) | — |
| **Cibest** (RETIRADO) | — |
| **Scor3Bank** (RETIRADO) | OWASP |
| **Beta1** (RETIRADO) | (ninguno — cobertura completa) |
| **B2 SC** (RETIRADO) | (ninguno — cobertura completa) |
| **B3 Unif** | (ninguno — cobertura completa) |
| **PA** | — |
| **Ppasivo** (RETIRADO) | Banner Grab, CVE, API Endpoints, TLS, HTTP, Ports, CSP, Cookies, FinalRecon, Brute Subs, SAN, Supply Chain, Social, OWASP, EPSS/KEV, Public Paths |

## Notas

- **Public Paths** — incluido en los 8 informes activos; excluido de Ppasivo por ser dato activo (HEAD)
- **Ppasivo** excluye deliberadamente todo lo que requiera interacción activa con el objetivo
- **SOCRadar** y **PA** tienen la cobertura más completa (92.5%)
- **Scor3Bank** tiene su propio sistema de factores
- Los enriquecimientos **EPSS**, **CISA KEV** y **Risk Score** están presentes en los 8 informes activos pero no en Ppasivo (derivados de banner grabbing activo)
