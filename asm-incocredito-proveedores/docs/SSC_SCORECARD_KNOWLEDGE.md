# SSC Scorecard - Base de Conocimiento (Septiembre 2026)
> Fuente: `C:\Users\Administrator\Documents\ASM\Septiembre` (8 PDFs) - Alcuadrado 62, AXA 91, Comfama 74, Contentful 92, etc.
> Generados 8-10 sep 2026 por GrupoCibest (Bancolombia). Validado 2026-09-22.

## 1. Estructura fija SSC (23-37 paginas)
1. **Portada**: `INFORME DETALLADO Scorecard para {empresa}` + `Generado {fecha} UTC por {analista@bancolombia.com.co}` + disclaimer `No es pentest` + footer `powered by Informe detallado de {domain} - Preparado el {fecha} | X de Y`
2. **Pagina 2 - Que es SecurityScorecard**: Sistema A (max) a F (min) + estadistica `C/D/F = 5.4x mas prob breach vs A/B` + `AppSec/Patching F vs A = 10x` + **Proximos pasos** (4):
   1. Cree cuenta (acceso gratuito, self-monitoring continuo, historial, CSV)
   2. Valide su huella digital (activos atribuidos, solicitar eliminacion/adicion IPs)
   3. Examine los hallazgos
   4. Corrija y mejore score (resolucion 3 dias habiles via Support Portal)
3. **Pagina 3 - Vision general**: `Puntuacion seguridad 0-100` + letra grande + `DOMINIO: {dominio principal}` + `SECTOR: {industria}` + **10 Factores** con score 0-100 + `N INCIDENCIAS` + **Historial 30d** (grafico 60-100, escala F/D/C/B/A, linea dominio vs `Our Industry`)
4. **Paginas 4-5 - Elementos de accion**: Tabla `FACTOR | GRAVEDAD IMPACTO EN EL SCORE | PROBLEMAS DETECTADOS` con descripcion 5 lineas por issue, ordenado por impacto desc
5. **Paginas 6-37 - Detalle por factor (10 modulos)**: Por cada factor ver §3

## 2. Los 10 Factores (orden fijo SSC)
| # | Factor SSC | Que mide | Fuente SSC |
|---|------------|----------|------------|
|1| SEGURIDAD DE APLICACION WEB | Vulns web, CSP/HSTS, SRI, redirect, headers | CVE whitehat/blackhat + search engine indexing |
|2| CUBIT SCORE | Misconfigs variadas, IPs flagged | Threat intel DBs publicas (patentado) |
|3| ESTADO DE DNS (DNS Health) | DNS config, SPF/DMARC, DNS pasivo malicioso | DNS datasets |
|4| SEGURIDAD DE PUNTOS DE CONEXION (Endpoint) | OS/browser/plugins outdated | Metadata fingerprinting |
|5| HACKER CHATTER | Menciones en foros/IRC/darkweb | Sensores chatter clandestino |
|6| REPUTACION DE IP (IP Reputation) | Sinkhole C2, PVA | Sinkhole + OSINT malware feeds |
|7| FILTRACION DE INFORMACION (Information Leak) | Creds filtradas 0-120d, infostealer | DeepWeb + infostealer logs (Vidar etc) |
|8| SEGURIDAD DE RED (Network Security) | Puertos inseguros, TLS debil, cert issues | Public datasets puertos/TLS |
|9| CADENCIA DE APLICACION DE REVISIONES (Patching Cadence) | Velocidad patch vs peers, CVEs >30d | CVE + banner version inferencia |
|10| INGENIERIA SOCIAL (Social Engineering) | Susceptibilidad phishing | Social networks + breach data |

## 3. Detalle por factor - Patron
- Header: `81 SEGURIDAD DE APLICACION WEB` (score grande) + descripcion 3 lineas del modulo + `GRAVEDAD ALTA/MEDIA/BAJA` con conteo (ej `Falta Secure cookie 1 | CSP 2 | HSTS 1`)
- Por cada issue:
  - Titulo + `IMPACTO EN EL SCORE: -8.3 / -0.7 / <-0.1` (granular decimal, `<-0.1` = ruido despreciable)
  - `Descripcion` (riesgo, exploit)
  - `Recomendacion` (bullets concretos: habilitar HTTPS, `Strict-Transport-Security: max-age=31536000; includeSubDomains`, etc)
  - **Tabla evidencia**: `DOMINIO | ESQUEMA | OBSERVACIONES | URL FINAL | FECHA ULTIMA OBSERVACION` o `IP | PUERTO | HUELLA SHA-256 | SERIAL | OBSERVACIONES | EVIDENCIA ["825d >=398d"]` o `VULNERABILIDAD | IP | PUERTO | CVE PUBLISH DATE | LAST OBSERVED`

Ejemplos reales:
- Alcuadrado NET 57: `RDP 177.253.146.194:9991 -4.0`, `TLS protocolo debil -10.0`, `cipher debil -5.1`, `cert autofirmado -2.4`, `sin CRL/OCSP -2.6`
- Comfama 74: `SRI faltante -3.6`, `Redirect HTTP -1.9`, `CSP unsafe-inline -1.1`, `SPF missing 10 dominios <-0.1`, `Patching 47 CVE >30d -1.8`

## 4. Modelo de Scoring
- Factor 0-100, Overall 0-100 = ponderado (no promedio simple). SSC pondera AppSec y Patching mas alto (10x breach likelihood).
- Issue impacto fraccional, no binario PASS/FAIL. Top impactos: TLS protocolo debil 10.0, Secure cookie 8.3, SRI 3.6, SPF 0.1. Permite priorizacion real.
- Escala letras: `90-100 A | 80-89 B | 70-79 C | 60-69 D | 0-59 F` (inferido de 91=A, 74=C, 62=D)

## 5. Gaps ASM vs SSC y Sugerencias priorizadas
### P0 - Mapear ASM a 10 factores SSC (compatibilidad 1:1)
```
SSC AppSec      <- ASM CSP/HSTS/XCTO/headers (pasivo_canon)
SSC Cubit       <- ASM typosquatting + supply chain
SSC DNS         <- ASM dns_health (SPF/DMARC/DKIM/DNSSEC)
SSC Endpoint    <- ASM endpoint (a implementar)
SSC Hacker      <- ASM ransomwatch/ransomware.live + HN
SSC IP Rep      <- ASM Shodan InternetDB + sinkhole
SSC Info Leak   <- ASM leaks (haveibeenpwned) + Prism
SSC Network     <- ASM TLS/certs/ports (port_scanner/banner_grab)
SSC Patching    <- ASM vuln_lookup (CVE + EPSS + KEV) separar >30d vs last_obs
SSC Social      <- ASM social_osint
```
Renderizar en `generate_b2_scorecard_report.py` 10 tarjetas `Score | N issues` en lugar de 11 factores genericos.

### P0 - Impacto decimal
Definir `IMPACT_MAP = {"tls_weak_proto":10.0, "secure_cookie":8.3, "rpd_expuesto":4.0, "sri":3.6, "csp_missing":0.7}` y ordenar `Elementos de accion` por impacto desc.

### P1 - Tabla evidencia forense
Exponer `all_ips`, `sha256`, `serial`, `final_url`, `last_observed` en tablas por hallazgo. Diferenciador clave SSC.

### P1 - Historial vs industria + Huella digital
Grafico `dominio vs Our Industry` (promedio sector 74 Financiero) + seccion `Valide su huella digital: {total_ips} IPs, {total_subs} subs - solicitar eliminacion/adicion`.

### P1 - Pagina 2 storytelling
Copiar literal `Que es ASM Scorecard? A-F, C/D/F 5.4x, AppSec 10x` + 4 pasos SSC.

### P2 - Patching doble metrica
Separar `Vuln en ultima observacion` (CVE hoy) vs `Patching >30d` (deuda tecnica).

## 6. Que NO copiar
- SSC es 100% pasivo (no toca target). ASM es pasivo->activo (sonda puertos/banners) -> vender como `SSC + Activo` es ventaja, no gap.
- Cubit es caja negra patentada; ASM puede sustituir con `typosquatting + supply chain + cloud`.

## 7. Archivos ASM a tocar para implementar
- `generate_b2_scorecard_report.py` - 10 tarjetas + impacto
- `generate_beta1_report.py` / `generate_a1_report.py` - tabla evidencia
- `precia_scorecard.py:217` - ponderacion Overall (alinear pesos SSC: AppSec/Network/Patching alto)
- `dashboard_workspace/scan_history.db` - serie industria
- `semi_canon.py` / `pasivo_canon.py` - mapear a 10 factores

---
*Guardado 2026-09-22 - listo para reutilizar en regeneracion de informes B1/B2/A1*
