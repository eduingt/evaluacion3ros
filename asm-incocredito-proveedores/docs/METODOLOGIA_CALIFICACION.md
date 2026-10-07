# Metodología de Calificación de Seguridad — Guía para No Técnicos

**Versión:** 1.0  
**Fecha:** 2026  
**Proyecto:** ASM-Informe-Proveedores (Attack Surface Management)

---

## 1. Resumen Ejecutivo

Este documento explica **cómo calculamos la puntuación de seguridad** de cada proveedor tercerizado, en lenguaje sencillo para que cualquier stakeholder (directivos, auditores, compras, legal) pueda entender qué significa un "98/100" o una "Calificación A".

**En una frase:** Medimos qué tan bien protege el proveedor su superficie de ataque visible desde Internet, usando estándares internacionales reconocidos.

---

## 2. ¿Qué se Evalúa? (El "Domain Score" 0–100)

La puntuación base (**Domain Score**) evalúa **25 controles de seguridad** agrupados en 6 categorías. Cada control suma puntos si está bien configurado; si falta o es débil, no suma.

| Categoría | Qué mide | Puntos máximos |
|---|---|---|
| **Acceso Web (HTTPS/TLS)** | ¿El sitio carga seguro? ¿Certificado válido? ¿TLS 1.3? | 48 |
| **Cabeceras de Seguridad** | ¿Protege contra clicks maliciosos, inyección de código, framing? | 32 |
| **Correo Electrónico (DNS)** | ¿Evita suplantación de identidad (phishing)? SPF, DMARC, DKIM, MTA-STS, TLS-RPT | 30 |
| **Infraestructura / Red** | ¿Puertos expuestos? ¿Reputación de IPs? ¿URLhaus? | 21 |
| **Mantenimiento / Parches** | ¿Software obsoleto (EOL)? ¿Vulnerabilidades conocidas? | 13 |
| **Superficie de Ataque** | ¿Subdominios extraños? ¿Typosquatting? ¿Takeovers? ¿Supply chain? | 26 |
| **TOTAL TEÓRICO** |  | **~170** → **capado a 100** |

**Interpretación simple:**
- **90–100** = Excelente (A) — Postura sólida, riesgo bajo
- **75–89** = Bueno (B) — Postura aceptable, mejoras menores
- **60–74** = Regular (C) — Gaps importantes, requiere plan de acción
- **45–59** = Deficiente (D) — Riesgo alto, acción prioritaria
- **30–44** = Crítico (E) — Exposición severa
- **<30** = Muy Crítico (F) — Incumplimiento generalizado

---

## 3. Estándares y Referencias Utilizadas

Nos basamos **exclusivamente en estándares abiertos, guías gubernamentales y marcos de la industria**. No usamos criterios propietarios.

| Área | Estándar / Guía | Qué valida |
|---|---|---|
| **TLS / Certificados** | [RFC 5246](https://datatracker.ietf.org/doc/html/rfc5246), [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) (TLS 1.2/1.3), [Mozilla SSL Config](https://ssl-config.mozilla.org/) | Versiones seguras, suites criptográficas, caducidad |
| **HSTS** | [RFC 6797](https://datatracker.ietf.org/doc/html/rfc6797), [OWASP HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) | Forzar HTTPS, max-age ≥ 1 año, includeSubDomains |
| **CSP** | [CSP Level 3](https://www.w3.org/TR/CSP3/), [OWASP CSP](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) | script-src, object-src, base-uri, nonces/hashes |
| **Cookies** | [RFC 6265bis](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis), [OWASP Secure Cookies](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) | Secure, HttpOnly, SameSite=Lax/Strict |
| **SPF** | [RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208), [DMARC.org](https://dmarc.org/) | `-all` (rechazo), límites de lookups (≤10), sin voids |
| **DMARC** | [RFC 7489](https://datatracker.ietf.org/doc/html/rfc7489) | `p=reject` o `p=quarantine`, alineación SPF/DKIM |
| **DKIM** | [RFC 6376](https://datatracker.ietf.org/doc/html/rfc6376) | Claves ≥ 2048 bits, rotación periódica |
| **MTA-STS / TLS-RPT** | [RFC 8461](https://datatracker.ietf.org/doc/html/rfc8461), [RFC 8460](https://datatracker.ietf.org/doc/html/rfc8460) | Política de transporte seguro, reporte de fallos |
| **DNSSEC** | [RFC 4033/4034/4035](https://datatracker.ietf.org/doc/html/rfc4033) | Cadena de confianza validada |
| **CAA** | [RFC 8659](https://datatracker.ietf.org/doc/html/rfc8659) | Autorización de emisión de certificados |
| **Vulnerabilidades** | [OSV.dev](https://osv.dev/), [NVD](https://nvd.nist.gov/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [EPSS](https://www.first.org/epss/) | CVE confirmados, explotados activamente, probabilidad de explotación |
| **Reputación IP** | [Spamhaus ZEN](https://www.spamhaus.org/zen/), [AbuseIPDB](https://www.abuseipdb.com/), [URLhaus](https://urlhaus.abuse.ch/) | Listados en blocklists, malware hosting, C2 |
| **Typosquatting** | [ICANN SSR](https://www.icann.org/resources/pages/ssr-2014-01-16-en), [DNSTwist](https://github.com/elceef/dnstwist) | Variantes registradas que imitan la marca |
| **Subdomain Takeover** | [OWASP Subdomain Takeover](https://owasp.org/www-project-subdomain-takeover/) | CNAMEs apuntando a servicios sin reclamar (S3, GitHub Pages, Azure, etc.) |
| **Supply Chain** | [OWASP SCVS](https://owasp.org/www-project-software-component-verification-standard/), [SLSA](https://slsa.dev/) | Dependencias de terceros en CSP/scripts, integridad |

---

## 4. Cómo se Calcula Cada Control (Ejemplos)

### Ejemplo 1: **HSTS (HTTP Strict Transport Security)**
| Estado | Puntos | Qué significa |
|---|---|---|
| Presente, `max-age≥31536000`, `includeSubDomains` | +12 | ✅ Óptimo |
| Presente pero `max-age` corto o sin subdominios | +6 | ⚠️ Mejorable |
| Ausente | +0 | ❌ Riesgo: SSL stripping posible |

**Referencia:** RFC 6797 + OWASP Cheat Sheet

---

### Ejemplo 2: **SPF (Sender Policy Framework)**
| Estado | Puntos | Qué significa |
|---|---|---|
| `v=spf1 ... -all` (rechazo estricto) | +10 | ✅ Óptimo: solo IPs autorizadas envían correo |
| `v=spf1 ... ~all` (softfail) | +5 | ⚠️ Aceptable pero permite entrega dudosa |
| Ausente o `+all` | +0 | ❌ Cualquiera puede suplantar el dominio |

**Referencia:** RFC 7208 + DMARC.org Best Practices

---

### Ejemplo 3: **TLS 1.3 Only**
| Estado | Puntos | Qué significa |
|---|---|---|
| Negocia TLS 1.3 y **rechaza** 1.0/1.1/1.2 | +6 | ✅ Solo protocolo moderno |
| Negocia 1.3 pero acepta 1.2 | +0 (base +14 por TLS OK) | ⚠️ Funciona pero permite downgrade |
| Error TLS / Certificado inválido | +0 | ❌ No seguro |

**Referencia:** RFC 8446 + Mozilla Modern Config

---

### Ejemplo 4: **Vulnerabilidades (OSV.dev + CISA KEV + EPSS)**
| Hallazgo | Impacto en score |
|---|---|
| 0 vulnerabilidades | +8 |
| 1–3 (ninguna KEV, EPSS < 0.1) | +4 |
| ≥1 KEV (explotada activamente) | 0 (resta implícita por gravedad en hallazgos) |
| EPSS > 0.5 (alta probabilidad explotación) | Peso mayor en reporte de riesgos |

**Referencia:** OSV Schema, CISA KEV Catalog, FIRST EPSS

---

## 5. Del Domain Score al "Score General" y Calificación

### Domain Score (por proveedor)
- Heurística técnica 0–100 (promedio ponderado de los 25 controles)
- Un proveedor = un Domain Score

### Score General (organizacional)
- **Promedio simple** de los Domain Scores de todos los proveedores escaneados
- Ejemplo: 3 proveedores con 95, 92, 88 → **Score General = 91.7 → 92/100**

### Calificación (Letra)
| Score | Letra | Significado negocio |
|---|---|---|
| ≥90 | **A** | Proveedor de confianza, monitoreo rutinario |
| 75–89 | **B** | Aceptable, mejoras planificadas |
| 60–74 | **C** | Requiere plan de remediación (30–90 días) |
| 45–59 | **D** | Riesgo alto, acción prioritaria (≤30 días) |
| 30–44 | **E** | Crítico, escalar a dirección |
| <30 | **F** | Bloquear / reemplazar proveedor |

---

## 6. Niveles de Prueba (Qué se Escanea Según Profundidad)

| Nivel | Qué incluye | Tiempo aprox. | Uso recomendado |
|---|---|---|---|
| **1. Pasivo** | Solo consultas públicas: DNS, CT logs, WHOIS, Shodan InternetDB, brechas conocidas | 30–60 seg | Screening inicial, onboarding |
| **2. Semi-activo** | + TLS, cabeceras, rutas web, WAF, Nuclei (plantillas seguras), Gobuster (directorios comunes) | 2–5 min | Evaluación periódica trimestral |
| **3. Activo** | + Subdominios (fuerza bruta), takeover, port-scan completo, FinalRecon, API discovery, Nuclei (CVE/vulns), Gobuster (DNS) | 10–20 min | Auditoría anual, proveedores críticos |
| **4. Invasivo** | + Banner grab, CVE lookup (vulndb/EPSS/KEV), IP pivot, Strix AI Pentest (con PoC) | 20–40 min | Red team, validación de incidentes |

> **Nota:** Los informes indican claramente qué nivel se ejecutó. Un "Score 98 Nivel 2" no es comparable directo con "Score 85 Nivel 3" (este último es más exhaustivo).

---

## 7. Qué NO Mide Este Score

| No mide | Por qué |
|---|---|
| Seguridad interna (red privada, AD, endpoints) | Solo visibilidad externa (Internet-facing) |
| Configuración de servidores (hardening OS, patch management interno) | Requiere acceso con credenciales / agente |
| Procesos humanos (phishing a empleados, ingeniería social real) | Requiere campañas autorizadas |
| Cumplimiento normativo completo (ISO 27001, PCI-DSS, GDPR) | Son marcos amplios; esto es **superficie de ataque técnica** |
| Código fuente / SAST / DAST interno | Fuera de alcance ASM pasivo/activo externo |

---

## 8. Cómo Leer el Informe (Cheat Sheet)

| Sección | Qué buscar | Pregunta clave |
|---|---|---|
| **Score General + Letra** | Número grande + A/B/C/D/E/F | ¿Está en zona verde (≥75)? |
| **Domain Score por proveedor** | Tabla o tarjetas individuales | ¿Hay algún proveedor < 60? |
| **Factores de Riesgo (Risk Rows)** | Tabla con "Impacto" (peso 0–1) | ¿Los riesgos altos tienen hallazgos? |
| **Hallazgos Detallados** | Lista con Prioridad P1/P2/P3 | ¿Hay P1 abiertos? ¿Cuántos? |
| **Histórico / Tendencia** | Gráfico de línea (últimos 5 escaneos) | ¿Mejora, empeora o estable? |
| **Matriz de Riesgo** | Heatmap Probabilidad × Impacto | ¿Hay zona roja (Muy Alta)? |

---

## 9. Preguntas Frecuentes (FAQ)

**P: "¿Por qué mi proveedor tiene 100/100?"**  
R: Significa que **todos los controles visibles desde Internet pasan**. No significa "seguridad perfecta" — solo que no hay hallazgos en la superficie externa escaneada. Revisar si el nivel de prueba fue suficiente (Nivel 3/4 para proveedores críticos).

**P: "¿El score sube si arreglo un hallazgo?"**  
R: Sí. Al siguiente escaneo, el control pasa y suma sus puntos. La tendencia histórica lo muestra.

**P: "¿Puedo comparar proveedores de distintos sectores?"**  
R: El score es **técnico y normalizado** (mismos 25 controles para todos). Sí es comparable, pero contextualice: un banco y un proveedor de marketing tienen distinta criticidad de negocio.

**P: "¿Qué pasa si el proveedor bloquea el escaneo?"**  
R: Los controles que requieren conexión (TLS, cabeceras, puertos) marcarán "error/timeout" y no sumarán puntos. El reporte lo indicará explícitamente.

**P: "¿Esto sustituye una auditoría penetración (pentest)?"**  
R: **No.** ASM = descubrimiento y evaluación continua de superficie. Pentest = validación manual profunda con explotación controlada. Son complementarios.

---

## 10. Glosario Rápido

| Término | Definición simple |
|---|---|
| **ASM** | Attack Surface Management — Gestión de la superficie de ataque |
| **Superficie de ataque** | Todo lo "visible" desde Internet: dominios, IPs, puertos, servicios, certificados |
| **Pasivo** | Solo consultas a bases de datos públicas, sin tocar los sistemas del proveedor |
| **Activo** | Conexiones reales al proveedor (HTTPS, DNS, puertos) para verificar configuración |
| **CVE** | Vulnerabilidad conocida con identificador estándar (ej. CVE-2024-12345) |
| **KEV** | Known Exploited Vulnerability — CISA confirma que se está explotando **ahora** |
| **EPSS** | Probabilidad 0–1 de que una vulnerabilidad sea explotada en 30 días |
| **Typosquatting** | Dominios parecidos al original para engañar (ej. `inc0credito.com`) |
| **Subdomain Takeover** | Subdominio apuntando a servicio externo no reclamado (riesgo de control total) |
| **Supply Chain** | Dependencias de terceros que carga la web (scripts, CDNs, fuentes, APIs) |
| **DNSBL** | Lista de IPs con mala reputación (spam, malware, botnet) |

---

## 11. Contacto y Soporte

- **Equipo responsable:** Seguridad de la Información / ASM Team
- **Frecuencia de escaneo:** Configurable (diario/semanal/mensual/trimestral)
- **Escalación de hallazgos P1:** Automática a [Slack/Email/Jira] + dueño del proveedor
- **Próxima revisión metodológica:** Trimestral (alineación con nuevas CVEs, RFCs, guías OWASP)

---

**Fin del documento**  
*Este documento es vivo y se actualiza con cada release del motor de escaneo.*