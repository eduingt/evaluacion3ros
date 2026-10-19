# Politica de seguridad

## Reporte de vulnerabilidades

No abras un issue publico para reportar una vulnerabilidad.

Canales, en orden:

1. GitHub Security Advisories (reporte privado) en
   `https://github.com/eduingt/evaluacion3ros/security/advisories/new`.
2. Correo al contacto del proyecto: `admin@incocredito.com`
   (solo si el canal anterior no esta disponible).

Incluye: descripcion, impacto, pasos para reproducir, versiones
afectadas y, si aplica, PoC y referencia CVE.

## Alcance

Este repositorio contiene un pipeline ASM por proveedor (escaneo,
generadores de informe HTML/PDF y dashboard FastAPI). El reporte cubre
el codigo de este repositorio, sus dependencias y sus workflows de CI.

## Respuesta

- Acuse de recibo: maximo 3 dias habiles.
- Evaluacion y plan de correccion: segun severidad
  (ver `docs/VULN_SLA.md`).
- Divulgacion coordinada: se publica el fix y luego el detalle.

## Modelo operativo del dashboard

- Red: servicio LAN sin autenticacion de red; no exponer a internet sin
  proxy inverso con autenticacion delante.
- API de escritura (`POST /api/scan*`, borrado de historial, `PUT /api/config`)
  exige `Authorization: Bearer <token>`. El token vive en
  `C:\ProgramData\ASM-Dashboard\api_token.txt` (generado al primer arranque)
  o en la variable `ASM_API_TOKEN`. Las lecturas (reportes, historial)
  quedan abiertas por diseno en LAN.
- TLS: `cert.pem/key.pem` fuera del repo en `C:\ProgramData\ASM-Dashboard\`
  (`ASM_TLS_CERT`/`ASM_TLS_KEY` para otras rutas). Rotado el 2026-10-14
  (autofirmado local). Nunca versionar claves: `*.pem`/`*.key` estan en
  `.gitignore`.

## Versiones soportadas

| Version      | Soporte          |
|--------------|------------------|
| main (actual)| Si               |
| tags viejos  | Solo criticas    |

Python soportado: 3.11.
