#!/usr/bin/env python3
"""
Genera configuraciones para herramientas DAST (ZAP, Burp Suite, Caido)
a partir de asm_report.json. Produce:
  - ZAP: archivo de contexto (.context) + script de automatización
  - Burp Suite: archivo de configuración de alcance (target scope)
  - Caido: lista de URLs para importar
"""

from __future__ import annotations

import argparse
import json
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent


def _get_targets(asm: dict[str, Any]) -> list[dict[str, str]]:
    providers = asm.get("providers") or []
    targets: list[dict[str, str]] = []
    seen_domains: set[str] = set()
    for p in providers:
        domain = p.get("domain", "")
        name = p.get("name", domain)
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            targets.append({"domain": domain, "name": name, "url": f"https://{domain}"})
    return targets


def _get_context_paths(asm: dict[str, Any], domain: str) -> list[str]:
    providers = asm.get("providers") or []
    for p in providers:
        if p.get("domain") == domain:
            api_eps = p.get("api_endpoints") or []
            return sorted({ep["path"] for ep in api_eps if ep.get("path") and ep.get("is_shadow") or (ep.get("status_code") and ep["status_code"] not in (404,))})
    return []


def _get_cve_context(cve: dict[str, Any]) -> str:
    risk = cve.get("risk_score")
    epss = cve.get("epss_score")
    in_kev = cve.get("in_kev", False)
    parts = [cve.get("id", "?")]
    if risk is not None:
        parts.append(f"Risk:{risk:.1f}")
    if epss is not None:
        parts.append(f"EPSS:{epss*100:.1f}%")
    if in_kev:
        parts.append("KEV")
    return " [" + "/".join(parts) + "]"


def generate_zap_script(asm: dict[str, Any]) -> str:
    targets = _get_targets(asm)
    gen_time = asm.get("generated_utc", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))

    paths_by_domain: dict[str, list[str]] = {}
    for p in asm.get("providers") or []:
        domain = p.get("domain", "")
        paths = _get_context_paths(asm, domain)
        if paths:
            paths_by_domain[domain] = paths

    script = textwrap.dedent(f"""\
    # ZAP Automation Script — generado desde ASM-Incocredito-Proveedores
    # {gen_time}
    # Importar en ZAP: Tools → Scripts Console → New Script → Automation
    #
    # Uso en línea de comandos:
    #   zap.sh -cmd -script {Path(__file__).name} -cmd

    import org.zaproxy.clientapi.gen.ClientApiException
    import groovy.json.JsonOutput

    def main() {{
        println "[ASM] Iniciando escaneo DAST guiado por ASM..."

        // Configurar contexto con alcance definido
        def contextName = "ASM-Proveedores"
        def contextId = org.parosproxy.paros.model.Model().session.getNewContext(contextName).getId()

        // URLs objetivo del escaneo ASM
        def targets = {json.dumps([t["url"] for t in targets], indent=2)}

        targets.each {{ url ->
            try {{
                // Incluir en alcance
                model.getSession().getContext(contextId).addIncludeInContextRegex("\\\\Q" + url + "\\\\E.*")
                println "[ASM] Incluido en alcance: " + url

                // Spider pasivo
                def spiderScanId = api.spider.scan(url, null, null, null, contextName)
                println "[ASM] Spider iniciado: ID " + spiderScanId

                // Esperar a que termine
                while (!api.spider.getStatus(spiderScanId.toString()).equals("100")) {{
                    sleep(5000)
                }}

                // Escaneo activo
                def ascanScanId = api.ascan.scan(url, "true", "false", null, null, contextName)
                println "[ASM] Active Scan iniciado: ID " + ascanScanId

                while (!api.ascan.getStatus(ascanScanId.toString()).equals("100")) {{
                    sleep(5000)
                }}
                println "[ASM] Escaneo completo: " + url

            }} catch (ClientApiException e) {{
                println "[ASM] Error en " + url + ": " + e.getMessage()
            }}
        }}

        println "[ASM] Todos los escaneos completados."
        println "[ASM] Revisar alertas en ZAP UI o exportar con:"
        println "[ASM]   zap.sh -cmd -openreport /tmp/asm_report.html"
    }}

    main()
    """)

    # Append path hints if available
    if paths_by_domain:
        script += "\n// Rutas de alta prioridad por dominio (descubiertas por ASM)\n"
        script += "// Incluir como URLs contextuales para escaneo dirigido:\n"
        for domain, paths in paths_by_domain.items():
            script += f"//   {domain}:\n"
            for path in paths[:10]:
                script += f"//     {path}\n"
            if len(paths) > 10:
                script += f"//     ... y {len(paths) - 10} más\n"

    return script


def generate_burp_scope_config(asm: dict[str, Any]) -> str:
    targets = _get_targets(asm)
    gen_time = asm.get("generated_utc", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))

    # Target scope configuration for Burp Suite (XML Project file fragment)
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f"<!-- Burp Suite Target Scope — generado desde ASM-Incocredito-Proveedores {gen_time} -->",
        "<!-- Importar: Target Scope → Paste URL (o importar XML) -->",
        "<burp-version>2024</burp-version>",
        "<target>",
        "  <scope>",
        "    <scope_type>Include</scope_type>",
    ]

    # Add CVE context as inline comments
    for p in asm.get("providers") or []:
        domain = p.get("domain", "")
        cves = p.get("cve_findings") or []
        if cves:
            lines.append(f"    <!-- {domain}: {len(cves)} CVE(s) detectados -->")
            for c in cves[:5]:
                lines.append(f"    <!--   {_get_cve_context(c)} -->")
            if len(cves) > 5:
                lines.append(f"    <!--   ... y {len(cves) - 5} más -->")

    for t in targets:
        escaped = t["domain"].replace(".", "\\.")
        lines.append(f'    <url><regex>^https?://[^/]*{escaped}.*</regex></url>')

    lines.append("  </scope>")
    lines.append("</target>")

    # Add API endpoint hints as a separate comment section
    has_hints = False
    for p in asm.get("providers") or []:
        paths = _get_context_paths(asm, p.get("domain", ""))
        if paths:
            if not has_hints:
                lines.append("")
                lines.append("<!-- Rutas API de alta prioridad por dominio -->")
                has_hints = True
            lines.append(f"<domain:{p.get('domain', '')}>")
            for path in paths[:15]:
                lines.append(f"  <!-- {path} -->")
            if len(paths) > 15:
                lines.append(f"  <!-- ... y {len(paths) - 15} más -->")
            lines.append(f"</domain:{p.get('domain', '')}>")

    return "\n".join(lines)


def generate_caido_urls(asm: dict[str, Any]) -> str:
    targets = _get_targets(asm)
    lines: list[str] = []
    for t in targets:
        lines.append(t["url"])
        lines.append(f"{t['url']}/")  # root
        # Add discovered API paths
        for p in asm.get("providers") or []:
            if p.get("domain") == t["domain"]:
                for ep in p.get("api_endpoints") or []:
                    if ep.get("status_code") and ep["status_code"] not in (404,):
                        method = ep.get("method", "GET")
                        path = ep.get("path", "/")
                        lines.append(f"{t['url']}{path}  [{method}]  # {ep.get('category', '?')} shadow={ep.get('is_shadow', False)}")
    return "\n".join(lines)


def generate_zap_context(asm: dict[str, Any]) -> str:
    targets = _get_targets(asm)
    gen_time = asm.get("generated_utc", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))

    parts: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?">',
        f"<!-- ZAP Context — generado desde ASM-Incocredito-Proveedores {gen_time} -->",
        "<context>",
        "  <name>ASM-Proveedores</name>",
        "  <desc>Contexto generado automáticamente desde escaneo ASM de proveedores Incocredito.</desc>",
        "  <inscope>true</inscope>",
    ]

    for t in targets:
        escaped = t["domain"].replace(".", "\\.")
        parts.append(f'  <url><pattern>https?://[^/]*{escaped}.*</pattern><type>INCLUDE</type></url>')

    parts.append("  <tech>")
    for tech in ["Db", "Language", "OS", "WS"]:
        parts.append(f"    <{tech}>true</{tech}>")
    parts.append("  </tech>")

    parts.append("</context>")

    return "\n".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Genera configuraciones DAST desde asm_report.json")
    parser.add_argument("--input", default=ROOT / "asm_report.json", type=Path, help="Ruta a asm_report.json")
    parser.add_argument("--output-dir", default=ROOT / "dast", type=Path, help="Directorio de salida")
    args = parser.parse_args()

    if not args.input.exists():
        print(f"Error: no se encuentra {args.input}")
        raise SystemExit(1)

    asm = json.loads(args.input.read_text(encoding="utf-8"))
    args.output_dir.mkdir(parents=True, exist_ok=True)

    # ZAP Automation Script
    zap_script = generate_zap_script(asm)
    (args.output_dir / "zap_automation.groovy").write_text(zap_script, encoding="utf-8")
    print(f"ZAP script:    {args.output_dir / 'zap_automation.groovy'}")

    # ZAP Context
    zap_ctx = generate_zap_context(asm)
    (args.output_dir / "zap_context.context").write_text(zap_ctx, encoding="utf-8")
    print(f"ZAP context:   {args.output_dir / 'zap_context.context'}")

    # Burp Scope
    burp_scope = generate_burp_scope_config(asm)
    (args.output_dir / "burp_scope.xml").write_text(burp_scope, encoding="utf-8")
    print(f"Burp scope:    {args.output_dir / 'burp_scope.xml'}")

    # Caido URLs
    caido_urls = generate_caido_urls(asm)
    (args.output_dir / "caido_urls.txt").write_text(caido_urls, encoding="utf-8")
    print(f"Caido URLs:    {args.output_dir / 'caido_urls.txt'}")

    n_targets = len(_get_targets(asm))
    print(f"\nConfiguración DAST generada para {n_targets} objetivo(s) en {args.output_dir}")


if __name__ == "__main__":
    main()
