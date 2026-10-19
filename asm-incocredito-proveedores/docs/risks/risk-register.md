# Registro de riesgos — ASM-Informe-Proveedores

Metodologia: matriz cualitativa Probabilidad x Impacto (Bajo=1, Medio=2, Alto=3).
Score numerico = P x I. Orden descendente. Revisar cada escaneo.

## Resumen ejecutivo

Riesgo dominante: exposicion TLS/DNS y cadena de suministro de terceros en
proveedores (impacto directo en factores SSC: Network, DNS, Patching, IP Reputation).
El pipeline ASM mitiga con escaneo por niveles + canon pasivo/semi-activo +
exportes SARIF/VEX.

## Vision del proyecto

Pipeline ASM por proveedor tercero: escaneo pasivo→activo, `asm_report.json`
canonico, 8 generadores HTML/PDF, dashboard HTTPS 8765 (servicio NSSM
ASM-Dashboard), exportes SARIF 2.1 + OpenVEX.

## Tabla general

| ID | Titulo | Descripcion (Causa -> Evento -> Impacto) | Prob. | Impacto | Score | Num |
|----|--------|------------------------------------------|-------|---------|-------|-----|
| R-001 | TLS obsoleto en proveedor | Cert/TLS sin 1.3-only -> negociacion degradada -> interceptacion/deteccion SSC Network | Alta | Alta | Alta x Alta | 9 |
| R-002 | SPF/DMARC ausente | DNS sin autenticacion de correo -> suplantacion de proveedor -> BEC/fraude | Alta | Alta | Alta x Alta | 9 |
| R-003 | CVE con KEV/EPSS alto | Banner con version vulnerable explotada en campo -> compromiso de proveedor -> impacto cadena | Media | Alta | Media x Alta | 6 |
| R-004 | Shadow API expuesta | Endpoint no documentado con 200/401 -> acceso no autorizado -> fuga/dato integro | Media | Alta | Media x Alta | 6 |
| R-005 | Subdomain takeover | Registro CNAME colgado -> atacante reclama subdominio -> phishing con marca | Media | Alta | Media x Alta | 6 |
| R-006 | Falsos positivos CVE | Banner coincide sin ruta alcanzable -> remediacion desperdiciada -> fatiga operativa | Alta | Media | Alta x Media | 6 |
| R-007 | Caida dashboard NSSM | Servicio Windows detenido/error cert -> sin escaneos ni entregas -> SLA incumplido | Media | Media | Media x Media | 4 |
| R-008 | Costo Strix/LLM descontrolado | Escaneos deep sin budget -> gasto API LLM -> sobrecosto | Media | Media | Media x Media | 4 |
| R-009 | Deriva de generadores | 8 informes divergen en severidades -> entregables inconsistentes -> reproceso | Media | Media | Media x Media | 4 |

## Detalle

### R-001 TLS obsoleto en proveedor
- Probabilidad Alta (proveedores con TLS 1.2 aun comunes), Impacto Alto.
- Categoria: tecnica. Mitigacion: `tls13_only_ok` + mapeo W-04/ASI-07, hallazgo con evidencia y recomendacion. Contingencia: excepcion temporal documentada + re-escaneo. Disparador: `negotiated_version` sin 1.3. Dueno: analista ASM. Estado: abierto.

### R-002 SPF/DMARC ausente
- Probabilidad Alta, Impacto Alto. Categoria: tecnica/proceso.
- Mitigacion: `spf_supply_chain` (Claude-OSINT) + W-06, veredicto spoofeable. Contingencia: regla de gateway + notificacion a proveedor. Disparador: `SPF:missing/DMARC:-`. Dueno: analista ASM. Estado: abierto.

### R-003 CVE con KEV/EPSS alto
- Probabilidad Media, Impacto Alto. Categoria: tecnica.
- Mitigacion: `vuln_lookup.py` (KEV+EPSS) + SARIF `error` + VEX `affected/action_statement`. Contingencia: aislamiento/WAF virtual. Disparador: `in_kev=true o risk>=7`. Dueno: analista ASM. Estado: abierto.

### R-004 Shadow API expuesta
- Probabilidad Media, Impacto Alto. Categoria: tecnica.
- Mitigacion: `api_discovery.py` + SARIF `SHADOW/api` + W-01. Contingencia: bloqueo en WAF + revision con proveedor. Disparador: `is_shadow=true`. Dueno: analista ASM. Estado: abierto.

### R-005 Subdomain takeover
- Probabilidad Media, Impacto Alto. Categoria: tecnica.
- Mitigacion: deteccion takeover + W-03/ASI-04/ASI-10 peso 0.7. Contingencia: baja del DNS + quarentena. Disparador: `takeover_risks.vulnerable`. Dueno: analista ASM. Estado: abierto.

### R-006 Falsos positivos CVE
- Probabilidad Alta, Impacto Medio. Categoria: operativa.
- Mitigacion: VEX `not_affected` con `vulnerable_code_not_in_execute_path` + `under_investigation` por defecto. Contingencia: validacion manual. Disparador: CVE sin evidencia de ruta. Dueno: analista ASM. Estado: abierto.

### R-007 Caida dashboard NSSM
- Probabilidad Media, Impacto Medio. Categoria: operativa.
- Mitigacion: healthcheck `curl -sk https://127.0.0.1:8765/` + reinicio solo si cambia `dashboard_server.py`. Contingencia: `sc.exe stop/start ASM-Dashboard`. Disparador: HTTP != 200. Dueno: operador. Estado: abierto.

### R-008 Costo Strix/LLM descontrolado
- Probabilidad Media, Impacto Medio. Categoria: financiera.
- Mitigacion: `--max-budget` + skip tolerante sin key/Docker + costo en `asm_report.json`. Contingencia: forzar `quick` o desactivar. Disparador: `total_cost_usd` sobre umbral. Dueno: operador. Estado: abierto.

### R-009 Deriva de generadores
- Probabilidad Media, Impacto Medio. Categoria: calidad.
- Mitigacion: `pasivo_canon.py`/`semi_canon.py` + `severity.py` canonico + `owasp_web.py`/`owasp_agentic.py` espejo. Contingencia: `py_compile` + JSON sintetico por generador. Disparador: diff de severidades entre informes. Dueno: dev ASM. Estado: abierto.
