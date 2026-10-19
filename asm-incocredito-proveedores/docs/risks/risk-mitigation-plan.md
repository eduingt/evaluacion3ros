# Plan de mitigacion — ASM-Informe-Proveedores

Derivado de `risk-register.md`. Foco en scores 9 y 6.

## Riesgos prioritarios (score 9)
- **R-001 TLS obsoleto:** exigir TLS 1.3-only a proveedores criticos; re-escaneo mensual; evidencia TLS en informe.
- **R-002 SPF/DMARC ausente:** solicitar `p=quarantine→reject`; verificar con `spf_supply_chain`; seguimiento a 30 dias.

## Respuesta (score 6)
- **R-003 CVE KEV:** SLA por severidad (`VULN_SLA.md`); VEX `affected` + SARIF en Code Scanning.
- **R-004 Shadow API:** inventario API + revision trimestral con proveedor.
- **R-005 Takeover:** monitoreo CT/crt.sh continuo; baja inmediata si `vulnerable=true`.
- **R-006 FP CVE:** todo CVE sin evidencia nace `under_investigation`; solo `affected` con prueba.

## Recursos
- Analista ASM (triage y notificacion a proveedores), operador (servicio NSSM), dev (canon y exportes).

## Comunicacion
- Interno: historial `dashboard_workspace/history` + `scan_history.db`.
- Proveedor: informe PDF + tabla de accion (impacto, evidencia, recomendacion, plazo).

## Reevaluacion
- Por escaneo (riesgos tecnicos) y mensual (operativos). Cierre solo con re-escaneo que confirme remediacion.
