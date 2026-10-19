# Gobernanza

Proyecto unipersonal con revision obligatoria. Todo cambio entra por
PR a `main`, con revision de CODEOWNERS y CI en verde.

## Roles

| Rol        | Quien     | Alcance                                  |
|------------|-----------|------------------------------------------|
| Owner      | @eduingt  | Decision final, releases, accesos        |
| Reviewer   | @eduingt  | Toda PR (ver `.github/CODEOWNERS`)       |

Sin comite ni elecciones: el owner decide. Si el proyecto crece, esta
tabla se amplia con maintainers por area (scanner, informes, dashboard).

## Como contribuir

1. Rama desde `main`, un cambio por PR.
2. Commits convencionales (`feat:`, `fix:`, `chore(deps):`, ...).
   Requerido para release-please cuando se active.
3. CI debe pasar: pr-validation, CodeQL, pip-audit,
   dependency-review, gitleaks, dependency-pinning.
4. Sin secretos en el codigo (gitleaks lo verifica).
5. Dependencias pineadas con `==` (dependency-pinning lo verifica).

## Seguridad

- Reporte privado: ver `SECURITY.md` (no abrir issues publicos).
- Plazos de correccion: `docs/VULN_SLA.md` (14/30/60/90 dias).
- Amenazas y supuestos por verificar: `docs/THREAT_MODEL.md`.

## Decisiones y conflictos

Propone en una PR o issue; el owner decide en maximo 7 dias.
Lo decidido queda en el historial de la PR/issue.

## OpenSSF Best Practices Badge

- Estado: alta pendiente en `https://www.bestpractices.dev/`.
- Passing: alcanzable con lo actual (LICENSE, SECURITY.md, CI,
  CodeQL). Dar de alta el proyecto y completar el cuestionario.
- Silver: objetivo declarado. Gaps conocidos: releases firmados
  (proceso manual hoy, release-please pendiente), cobertura de
  tests automatizada mas alla de compilacion + fuzz smoke.
- Gold: fuera de alcance por ahora (auditoria externa, verificacion
  formal).
