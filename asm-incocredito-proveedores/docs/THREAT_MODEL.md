# Modelo de amenazas — ASM-Incocredito-Proveedores

Metodo: STRIDE. Alcance: codigo, dependencias y CI de este repo.
Supuestos marcados con [S]; verificar antes de darlos por hechos.

## 1. Arquitectura y datos sensibles

| Componente            | Que hace                                              | Datos sensibles                          |
|-----------------------|-------------------------------------------------------|------------------------------------------|
| `dashboard_server.py` | FastAPI HTTPS 8765 + HTTP 8766, lanza escaneos, sirve | API keys (archivo config), `cert/key.pem`|
| `asm_scan.py`         | Orquesta escaneo pasivo->activo, escribe reportes     | Resultados, credenciales en memoria      |
| Generadores HTML/PDF  | Playwright Chromium a PDF                             | Contenido de informes de terceros        |
| `providers.json`      | Lista de objetivos                                    | Dominios cliente                         |
| `dashboard_workspace/`| `last/`, historial, `scan_history.db`                | Historial de escaneos                    |
| `vulndb/`             | CSVs + KEV local                                      | Ninguno (datos publicos)                 |
| CI (`.github/`)       | pip-audit, CodeQL, gitleaks, ZAP, provenance          | `GITHUB_TOKEN` minimo                    |

## 2. Fronteras de confianza

1. Navegador operador <-> dashboard (TLS en 8765; 8766 solo loopback/CI).
2. Dashboard <-> proveedores objetivo (escaneo ACTIVO: puertos,
   banners, paths — solo contra dominios con autorizacion).
3. Dashboard <-> APIs OSINT (Shodan, Censys, GreyNoise, SecurityTrails
   con API keys del archivo de configuracion).
4. Servicio Windows (NSSM, SYSTEM?) <-> filesystem (keys, pem, db).

## 3. STRIDE

| # | Categoria (ejemplo concreto) | Riesgo | Mitigacion (estado) |
|---|------------------------------|--------|---------------------|
| T1 | Spoofing: [S] endpoints del dashboard sin auth alcanzables en red | Alto | Exponer 8765 solo a red de gestion; 8766 solo localhost; verificar auth (gap) |
| T2 | Tampering: `providers.json` modificado -> escaneo a objetivo no autorizado | Alto | CODEOWNERS + branch protection (proceso); pendiente: allowlist de dominios (gap) |
| T3 | Tampering: `asm_report.json` intermedio alterado antes de generar PDF | Medio | Generar y firmar en el mismo job (provenance cubre SBOM, no el informe: gap) |
| T4 | Repudiation: escaneo activo sin registro de quien/autorizacion | Medio | `scan_history.db` + logs; agregar campo operario+ticket (gap) |
| T5 | Info disclosure: API keys en archivo config en claro en el servidor | Alto | Permisos NTFS estrictos + DPAPI/secret store (gap); gitleaks evita subirlas |
| T6 | Info disclosure: `cert.pem/key.pem` + `*.key` en disco | Medio | `.gitignore` los excluye (ok); backup cifrado (gap) |
| T7 | DoS: escaneo + Playwright consumen CPU/RAM; ZAP CI incluido | Medio | Concurrency/limites en CI; rate-limit escaneos concurrentes (gap) |
| T8 | Elevation: dashboard ejecuta subprocesos (FinalRecon, theHarvester) | Alto | Servicio con cuenta de minimos privilegios, no SYSTEM (verificar: gap) |
| T9 | Supply chain: dependencia comprometida (tj-actions/changie-files style) | Alto | Pins ==, pip-audit, dependency-review, provenance (ok) |
| T10 | Spoofing: webhook/issue de ZAP con `allow_issue_writing` | Bajo | Desactivado en CI (`false`) (ok) |

## 4. Top 3 y accion

1. T8 cuenta del servicio + T1 superficie de red del dashboard —
   endurecer despliegue NSSM y binding (antes del proximo escaneo).
2. T5 keys en claro — mover a almacen de secretos del SO.
3. T2 autorizacion de objetivos — allowlist + registro de ticket.

## 5. Fuera de alcance

Seguridad de los proveedores escaneados (esto los evalua, no los
protege), endurecimiento del SO/Windows, y red perimetral del cliente.
