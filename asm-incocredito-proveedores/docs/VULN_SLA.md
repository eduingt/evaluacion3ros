# SLA de remediacion de vulnerabilidades

Alcance: codigo propio, dependencias (`requirements*.txt`) y workflows
de CI de este repositorio.

## Plazos por severidad

| Severidad | Plazo maximo | Fuente                          |
|-----------|--------------|---------------------------------|
| Critica   | 14 dias      | CVSS >= 9.0 o CISA KEV activo   |
| Alta      | 30 dias      | CVSS 7.0-8.9 o EPSS >= 0.5      |
| Media     | 60 dias      | CVSS 4.0-6.9                    |
| Baja      | 90 dias      | CVSS 0.1-3.9                    |

El conteo inicia al publicarse el hallazgo (CodeQL, pip-audit,
dependency-review, gitleaks o reporte privado). Un CVE en CISA KEV
sube automaticamente a Critica aunque su CVSS sea menor.

## Proceso

1. Triage en maximo 3 dias habiles (severidad + alcance).
2. Fix en rama + PR con revision (CODEOWNERS).
3. Verificacion: el scan que lo detecto debe salir limpio.
4. Dependencias: se acepta el PR de Dependabot si el CI pasa.

## Excepciones

Si un plazo no se puede cumplir (fix upstream pendiente, falso
positivo), se registra en el PR/issue con justificacion, riesgo
residual y fecha de revision. Sin excepcion abierta no hay cierre.
