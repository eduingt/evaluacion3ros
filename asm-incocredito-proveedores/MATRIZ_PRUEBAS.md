# Matriz de pruebas ejecutadas en el pipeline ASM

Clasificación según el nivel de interacción con el objetivo. Las pruebas **Invasivas** requieren autorización explícita del proveedor auditado.

## Conteo total por nivel

| Nivel | # Pruebas | Acumulado |
|---|---|---|
| **Pasivo** | 13 | 13 |
| **Semi-activo** | +10 | 23 |
| **Activo** | +4 | 27 |
| **Invasivo** | +2 | 29 |

## Tabla de clasificación

| Pasivo (13) | Semi-activo (+10 = 23) | Activo (+4 = 27) | Invasivo (+2 = 29) |
|---|---|---|---|
| 1. DNS pasivo vía CT logs (crt.sh, Hackertarget, Rapiddns) | 14. HTTP probe GET al dominio (cabeceras, redirects, cookies) | 24. Escaneo TCP de puertos comunes (~300 puertos) | 28. Reverse DNS brute sobre prefijo de IP (barrido /24, IPs vecinas) |
| 2. WHOIS (registrante, fechas, NS, emails) | 15. Handshake TLS (negociación, TLS 1.3-only, cert, SAN) | 25. Banner grabbing en puertos abiertos (SSH, FTP, SMTP, HTTP) | 29. PROPFIND (WebDAV) en API discovery |
| 3. Shodan (hosts, puertos, vulns históricos) | 16. HEAD a rutas públicas (robots.txt, security.txt, health, openapi, swagger, actuator, OIDC) | 26. Fuerza bruta de subdominios (773 nombres vía DNS) | |
| 4. Censys (certificados, hosts) | 17. STARTTLS en servidores MX (SMTP) | 27. IP pivot (PTR, crt.sh por IP, RDAP, reverse DNS) | |
| 5. DNSDumpster (hosts, registros) | 18. Evaluación OWASP (análisis de datos ya recolectados) | | |
| 6. theHarvester (emails y subdominios públicos) | 19. CVE/OSV query (vulnerabilidades según tecnologías) | | |
| 7. OSINT social (Instagram, TikTok, X, Twitch, Telegram, GitHub) | 20. Patching cadence (evaluación de parches según tecnologías) | | |
| 8. URLhaus (reputación de URLs) | 21. Supply chain (cabeceras, dependencias) | | |
| 9. Fugas de credenciales (LEAK_API) | 22. CSP security (Content-Security-Policy) | | |
| 10. Typosquatting (dominios similares) | 23. Cookie security (Set-Cookie, Secure, HttpOnly) | | |
| 11. Reputación IP / DNSBL / supply chain | | | |
| 12. CVE lookup (EPSS/KEV + matching contra banners) | | | |
| 13. Registros DNS (SPF, DMARC, DKIM, DNSSEC, DANE, CAA, MTA-STS, TLS-RPT, BIMI, MX, NS) | | | |

## Definición por nivel

- **Pasivo**: no se contacta al objetivo; solo terceros, fuentes públicas y registros DNS. Sin riesgo y sin permiso.
- **Semi-activo**: interacción mínima y estándar con servicios públicos (GET/HEAD/TLS). No genera carga ni impacto.
- **Activo**: interacción directa y no destructiva con el objetivo (puertos, banners, brute de subdominios, crawling). Requiere autorización del proveedor.
- **Invasivo**: alta intensidad o métodos no estándar (barrido de IPs vecinas, WebDAV, crawling profundo, DAST). Solo con autorización escrita y ventana definida.

## Notas

- El pipeline actual ejecuta todas las pruebas de las columnas **Pasivo**, **Semi-activo** y **Activo** automáticamente por dominio.
- De la columna **Invasivo**, el pipeline ejecuta el barrido de puertos y el reverse DNS brute; el **DAST** solo genera configuraciones (ZAP/Burp/Caido) que se ejecutan fuera del pipeline con autorización.
- El informe Ppasivo ejecuta únicamente pruebas **Pasivas** (sin banner, CVE, API, TLS, HTTP, puertos, cookies, FinalRecon, supply, social, EPSS-KEV).
