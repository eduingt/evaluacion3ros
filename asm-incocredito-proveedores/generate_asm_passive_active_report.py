#!/usr/bin/env python3
"""
generate_asm_passive_active_report.py
Report con separacion visual entre ANALISIS PASIVO y ANALISIS ACTIVO.
v2 - Tipografia grande, evidencia detallada por hallazgo.
"""

from __future__ import annotations

import argparse
import html
from precia_scorecard import render_precialike_block
from toc_helper import render_toc
from score_legend import render_score_legend
from resumen_ejecutivo import render_resumen_ejecutivo
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent


def esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


def grade_letter(score: float) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 45: return "D"
    if score >= 30: return "E"
    return "F"


def grade_color(g: str) -> str:
    return {"A": "#10b981", "B": "#22c55e", "C": "#eab308", "D": "#f97316", "E": "#ef4444", "F": "#dc2626"}.get(g, "#6b7280")


def _evidence_block(items: list[str], title: str = "Evidencia") -> str:
    if not items:
        return ""
    lines = "".join(f"<span class='ev-line'>{esc(i)}</span>\n" for i in items if i)
    return f"<div class='ev-body'><div class='ev-title'>{esc(title)} ({len(items)})</div>{lines}</div>"


def _evidence_text(text: str, title: str = "Evidencia") -> str:
    if not text:
        return ""
    return f"<div class='ev-body'><div class='ev-title'>{esc(title)}</div><span class='ev-line'>{esc(text)}</span></div>"


def _evidence_dict(d: dict[str, Any], title: str = "Evidencia") -> str:
    if not d:
        return ""
    lines = "".join(f"<span class='ev-line'><strong>{esc(k)}:</strong> {esc(v)}</span>\n" for k, v in d.items() if v is not None)
    if not lines:
        return ""
    return f"<div class='ev-body'><div class='ev-title'>{esc(title)}</div>{lines}</div>"


_DESC_REC: dict[str, tuple[str, str]] = {}

def _dr(key: str, desc: str, rec: str) -> None:
    _DESC_REC[key] = (desc, rec)

_dr("passive/A IPv4",
    "El dominio tiene registros A que resuelven a direcciones IPv4, permitiendo la comunicacion directa "
    "con los servidores de alojamiento. Esta es la capa base de la infraestructura de red y el punto "
    "de entrada principal para cualquier ataque contra la disponibilidad del servicio.",
    "Verificar que las IPs pertenezcan a infraestructura propia o de proveedores confiables. "
    "Monitorear cambios no autorizados. Considerar el uso de listas de control de acceso (ACL) "
    "para restringir trafico solo a los puertos necesarios. Auditar periodicamente que ninguna IP "
    "obsoleta siga activa en los registros DNS.")

_dr("passive/AAAA IPv6",
    "El dominio tiene registros AAAA que lo hacen accesible a traves de IPv6. Si no se cuenta con "
    "una estrategia de seguridad IPv6, esta superficie de ataque podria estar desprotegida, ya que "
    "muchos firewalls y sistemas de deteccion no monitorean el trafico IPv6 con la misma rigurosidad.",
    "Asegurar que las reglas de firewall y los controles de acceso aplicados a IPv4 tambien cubran "
    "IPv6. Realizar escaneos de puertos y vulnerabilidades sobre ambas pilas. Si no se usa IPv6, "
    "deshabilitarlo y eliminar los registros AAAA.")

_dr("passive/MX",
    "Los registros MX definen los servidores de correo encargados de recibir los emails del dominio. "
    "Un MX mal configurado o ausente puede provocar perdida de correo electronico, suplantacion de "
    "identidad (spoofing) y filtracion de informacion sensible. Cada servidor MX debe estar "
    "correctamente asegurado, actualizado y configurado con STARTTLS obligatorio.",
    "Configurar al menos dos servidores MX para redundancia. Habilitar STARTTLS en todos los MX. "
    "Verificar que los servidores no acepten relays abiertos. Monitorear la reputacion de las IPs "
    "de los MX en listas DNSBL. Implementar autenticacion SPF, DKIM y DMARC.")

_dr("passive/NS",
    "Los servidores de nombres (NS) son responsables de la resolucion DNS del dominio. Son un "
    "objetivo critico: si un atacante compromete los NS, puede redirigir todo el trafico del dominio "
    "sin necesidad de vulnerar los servidores web o de correo.",
    "Usar servidores DNS redundantes en distintas redes. Mantenerlos actualizados y con DNSSEC "
    "habilitado. Restringir las transferencias de zona solo a servidores autorizados. "
    "Monitorear la integridad de los registros NS y configurar alertas ante cambios.")

_dr("passive/SPF",
    "SPF (Sender Policy Framework) autoriza que servidores pueden enviar correo en nombre del dominio. "
    "Sin una politica restrictiva (-all), los atacantes pueden falsificar la identidad del dominio "
    "en correos de phishing (spoofing). Una politica debil (~all o ?all) permite que servidores "
    "no autorizados envien correo sin ser rechazados de forma explicita.",
    "Configurar SPF con -all (hard fail) siempre que sea posible. Incluir solo los servidores "
    "de correo autorizados. Mantener el registro por debajo del limite de 10 consultas DNS. "
    "Combinar con DKIM y DMARC para una proteccion completa contra spoofing.")

_dr("passive/DMARC",
    "DMARC define que hacer con los correos que fallan autenticacion SPF/DKIM. Sin DMARC, los "
    "atacantes pueden enviar correos falsificados sin consecuencias. Con DMARC en p=reject, "
    "el dominio queda protegido contra spoofing. La politica quarantine ofrece proteccion parcial "
    "al enviar correos sospechosos a spam.",
    "Configurar DMARC con politica p=reject lo antes posible. Comenzar con p=none, monitorear "
    "informes agregados (rua), luego escalar a p=quarantine y finalmente p=reject. "
    "Incluir una direccion de correo en rua para recibir informes de los proveedores de email.")

_dr("passive/DKIM",
    "DKIM permite firmar criptograficamente los correos salientes, garantizando que no fueron "
    "alterados en transito. Sin DKIM, los correos son mas vulnerables a suplantacion y "
    "manipulacion de contenido. Cada selector DKIM representa una clave publica que los "
    "receptores usan para verificar la firma.",
    "Generar claves DKIM de 2048 bits como minimo. Rotar las claves periodicamente "
    "(cada 6-12 meses). Implementar multiple-Selector Rotation para evitar interrupciones. "
    "Monitorear la caducidad de los selectores y mantener un registro de claves antiguas.")

_dr("passive/DNSSEC",
    "DNSSEC protege la integridad de las respuestas DNS mediante firmas criptograficas, evitando "
    "que un atacante envenene la cache DNS (DNS spoofing). Sin DNSSEC, los usuarios pueden ser "
    "redirigidos a servidores maliciosos sin ser detectados.",
    "Habilitar DNSSEC en el registrador de dominios y configurar la cadena de confianza "
    "desde la zona raiz. Renovar las firmas RRSIG antes de su vencimiento. "
    "Verificar periodicamente que la cadena DNSSEC este completa y sin errores.")

_dr("passive/DANE/TLSA",
    "DANE/TLSA permite vincular un certificado TLS a un nombre de dominio mediante registros DNS, "
    "sin depender exclusivamente de Autoridades de Certificacion (CA). Esto proporciona una capa "
    "adicional de seguridad contra CA comprometidas o emisiones fraudulentas de certificados.",
    "Configurar registros TLSA siguiendo la RFC 7671. Usar el modo 3 1 1 (certificado de confianza "
    "ancla) o 2 1 1 (certificado de extremo) segun el nivel de control. Asegurar que DNSSEC este "
    "habilitado (DANE depende de DNSSEC). Monitorear la caducidad de los certificados y los registros TLSA.")

_dr("passive/CAA",
    "CAA (Certification Authority Authorization) restringe que Autoridades de Certificacion pueden "
    "emitir certificados para el dominio. Sin CAA, cualquier CA puede emitir un certificado para "
    "el dominio, lo que aumenta el riesgo de emision fraudulenta o no autorizada.",
    "Crear registros CAA que autoricen solo las CA de confianza. Incluir un registro iodef "
    "para recibir notificaciones de emision. Auditar periodicamente los registros CAA y "
    "mantenerlos sincronizados con la politica de certificados de la organizacion.")

_dr("passive/MTA-STS",
    "MTA-STS (SMTP MTA Strict Transport Security) obliga el uso de TLS en las conexiones entre "
    "servidores de correo, previniendo ataques de degradacion (downgrade) y MITM en el transporte "
    "del correo electronico.",
    "Publicar un archivo de politica MTA-STS en https://mta-sts.<dominio>/.well-known/mta-sts.txt "
    "con modo enforce. Configurar el registro TXT _mta-sts.<dominio> con id de politica. "
    "Monitorear la caducidad de la politica y renovar antes del vencimiento.")

_dr("passive/TLS-RPT",
    "TLS-RPT (TLS Reporting) permite recibir informes sobre fallos en conexiones TLS entre "
    "servidores de correo, facilitando la deteccion temprana de problemas de configuracion o "
    "ataques MITM contra MTA-STS.",
    "Configurar un registro TXT _smtp._tls.<dominio> con la direccion de correo donde recibir "
    "los informes. Revisar los informes periodicamente para detectar fallos de conexion o "
    "intentos de downgrade.")

_dr("passive/BIMI",
    "BIMI (Brand Indicators for Message Identification) muestra el logo de la marca junto a los "
    "correos autenticados en clientes de email compatibles, reforzando la confianza del destinatario "
    "y reduciendo la efectividad de ataques de phishing contra la marca.",
    "Asegurar que SPF, DKIM y DMARC con p=reject esten configurados antes de implementar BIMI. "
    "Publicar el logo en formato SVG y obtener un Verified Mark Certificate (VMC) si es necesario. "
    "Monitorear la correcta visualizacion en los principales proveedores de correo.")

_dr("passive/DNSBL",
    "Una o mas direcciones IP del dominio aparecen listadas en listas de reputacion DNSBL, lo que "
    "indica posible actividad maliciosa, compromiso previo o configuracion incorrecta. Esto afecta "
    "la capacidad de envio de correo y la reputacion general del dominio.",
    "Identificar la causa del listado (spam, malware, relay abierto). Contactar al operador de la "
    "DNSBL para solicitar la deslistacion una vez corregido el problema. Implementar monitoreo "
    "continuo de reputacion IP. Verificar que los servidores MX no sean relays abiertos.")

_dr("passive/URLhaus",
    "El dominio ha sido reportado en URLhaus como distribuidor de malware, URLs maliciosas o "
    "command & control. Esto indica compromiso activo o pasado del dominio o de algun servicio "
    "asociado.",
    "Investigar la causa del reporte: revisar el contenido alojado en el dominio en busca de "
    "malware, redirecciones maliciosas o scripts inyectados. Eliminar el contenido malicioso y "
    "solicitar la deslistacion en URLhaus. Revisar los logs del servidor web para identificar "
    "el origen del compromiso.")

_dr("passive/CT Logs",
    "Los registros de Certificate Transparency revelan subdominios descubiertos a traves de la "
    "emision de certificados SSL/TLS. Esto expone subdominios que podrian estar olvidados o "
    "mal configurados, ampliando la superficie de ataque.",
    "Auditar todos los subdominios listados y eliminar los que no esten en uso. Asegurar que "
    "los subdominios activos tengan la misma postura de seguridad que el dominio principal. "
    "Considerar el uso de wildcard certificates solo cuando sea estrictamente necesario.")

_dr("passive/Typosquatting",
    "Se encontraron dominios similares (typosquatting) registrados activamente. Estos dominios "
    "se utilizan tipicamente para phishing, suplantacion de identidad, distribucion de malware "
    "o competencia desleal. Cada variante registrada representa un riesgo para la marca y los "
    "usuarios.",
    "Evaluar la legalidad de los dominios y considerar acciones de reclamacion (UDRP, disputa). "
    "Implementar monitoreo continuo de registros de dominios similares. Notificar al equipo de "
    "seguridad y marketing. Considerar registrar preventivamente las variantes mas probables.")

_dr("passive/CVE OSV",
    "Se detectaron vulnerabilidades conocidas (CVE) asociadas a las tecnologias identificadas en "
    "el dominio, segun la base de datos Open Source Vulnerabilities (OSV). Cada CVE representa "
    "un riesgo de explotacion remota, fuga de informacion o denegacion de servicio.",
    "Priorizar el parcheo de las vulnerabilidades segun su severidad (CVSS). Actualizar las "
    "bibliotecas, frameworks y servicios a las versiones parcheadas mas recientes. "
    "Establecer un proceso de parcheo con SLAs definidos para vulnerabilidades criticas y altas.")

_dr("passive/CVE Banner Grab",
    "Se detectaron potenciales vulnerabilidades (CVEs) mediante correlacion de banners de servicio "
    "con las bases de datos de vulnerabilidades de vulscan (CVE, Exploit-DB). Estas coincidencias "
    "indican que los servicios expuestos podrian tener vulnerabilidades conocidas. Requieren "
    "verificacion manual para confirmar explotabilidad.",
    "Verificar manualmente cada CVE en la base de datos NVD. Actualizar los servicios a sus "
    "versiones mas recientes. Implementar WAF, segmentacion de red y parcheo prioritario.")

_dr("active/Banner Grab",
    "El banner grabbing revelo servicios y versiones especificas corriendo en puertos abiertos del "
    "dominio. La divulgacion de versiones exactas facilita a los atacantes la busqueda de "
    "vulnerabilidades conocidas especificas para esas versiones.",
    "Configurar los servicios para que muestren banners genericos o minimos, sin revelar versiones. "
    "Mantener todos los servicios actualizados. Deshabilitar servicios innecesarios.")

_dr("passive/Cred. Leaks",
    "Se encontraron filtraciones de credenciales (breaches) que involucran al dominio o a cuentas "
    "asociadas. Esto expone contraseñas, correos electronicos y posiblemente datos sensibles de "
    "empleados, clientes o sistemas internos.",
    "Exigir cambio de contraseñas inmediato para todas las cuentas afectadas. Implementar "
    "autenticacion multifactor (MFA) obligatoria. Verificar que las credenciales filtradas no "
    "se reutilicen en otros servicios. Monitorear la dark web para nuevas filtraciones.")

_dr("passive/WHOIS",
    "Los datos WHOIS revelan informacion administrativa y tecnica del dominio: registrador, "
    "fechas de creacion y expiracion, y datos del titular. Esta informacion puede ser utilizada "
    "por atacantes para ingenieria social, identificacion de contactos clave y planeacion de ataques.",
    "Usar servicios de privacidad WHOIS (redaccion de datos personales) si estan disponibles. "
    "Mantener actualizados los datos de contacto administrativo y tecnico. Configurar renovacion "
    "automatica para evitar la expiracion del dominio. Monitorear la fecha de expiracion.")

_dr("passive/Shodan",
    "Shodan expone los puertos abiertos, servicios y vulnerabilidades detectadas en la infraestructura "
    "del dominio. Esta informacion es utilizada por atacantes para identificar vectores de ataque "
    "sin necesidad de escanear directamente los sistemas objetivo.",
    "Reducir al minimo los puertos y servicios expuestos publicamente. Implementar firewalls de "
    "aplicacion web (WAF). Mantener todos los servicios actualizados. Revisar periodicamente el "
    "perfil del dominio en Shodan para identificar exposiciones no deseadas.")

_dr("passive/Censys",
    "Censys cataloga los certificados SSL/TLS y hosts asociados al dominio, permitiendo a terceros "
    "identificar la infraestructura, las CA emisoras y potenciales debilidades en la cadena de "
    "confianza SSL.",
    "Revisar los certificados expuestos y revocar los que no esten en uso. Asegurar que todos los "
    "certificados usen claves de 2048 bits o superior. Monitorear la aparicion de certificados "
    "no autorizados. Verificar que no haya certificados auto-firmados en produccion.")

_dr("passive/theHarvester",
    "theHarvester recolecta correos electronicos y subdominios del dominio desde fuentes publicas "
    "(buscadores, redes sociales, GPG keyservers). Los correos expuestos pueden ser usados para "
    "phishing, mientras que los subdominios revelan infraestructura oculta.",
    "Revisar los correos expuestos y notificar a los afectados. Implementar politicas de "
    "publicacion de correos en GitHub, foros y redes sociales. Monitorear la exposicion de "
    "subdominios y reducir la superficie de ataque.")

_dr("passive/DNSDumpster",
    "DNSDumpster mapea la infraestructura DNS del dominio incluyendo subdominios, registros MX y "
    "direcciones IP asociadas. Este reconocimiento pasivo revela la topologia de red y puede "
    "exponer sistemas internos o servidores olvidados.",
    "Revisar los registros expuestos y eliminar los que no esten en uso. Segmentar la red para "
    "que los servidores de distintos propositos (web, correo, DNS) esten en subredes separadas. "
    "Minimizar la informacion publica del DNS.")

_dr("passive/Social",
    "Se encontraron perfiles en redes sociales asociados al dominio o a cuentas corporativas. "
    "Estos perfiles pueden ser utilizados para ingenieria social, recoleccion de informacion "
    "de empleados y planeacion de ataques dirigidos.",
    "Revisar la configuracion de privacidad de los perfiles corporativos. Establecer politicas "
    "claras para la informacion que los empleados publican en redes sociales. "
    "Monitorear la aparicion de perfiles falsos que suplanten la identidad corporativa.")

_dr("DNSBL (passive)",
    "Una o mas direcciones IP del dominio aparecen listadas en listas de reputacion DNSBL, lo que "
    "indica posible actividad maliciosa o compromiso previo. Esto afecta la capacidad de envio "
    "de correo y la reputacion general del dominio.",
    "Identificar la causa del listado. Contactar al operador de la DNSBL para deslistar una vez "
    "corregido. Implementar monitoreo continuo de reputacion IP.")

_dr("URLhaus (passive)",
    "El dominio ha sido reportado en URLhaus como distribuidor de malware o URLs maliciosas. "
    "Esto indica compromiso activo o pasado del dominio o de algun servicio asociado.",
    "Investigar la causa del reporte. Revisar el contenido alojado. Eliminar contenido malicioso "
    "y solicitar deslistacion. Revisar logs del servidor para identificar el origen del compromiso.")

# --- ACTIVE descriptions ---
_dr("active/Puerto 80",
    "El puerto 80 (HTTP) esta abierto. Si no redirige inmediatamente a HTTPS mediante "
    "redireccion 301/302, las credenciales y datos transmitidos viajan en texto plano y "
    "pueden ser interceptados por atacantes en la misma red (MITM). Incluso con redireccion, "
    "la conexion inicial es insegura.",
    "Redirigir todo el trafico HTTP a HTTPS mediante redireccion 301 permanente. "
    "Implementar HSTS con max-age elevado y preload para eliminar la posibilidad de conexiones "
    "HTTP. Considerar cerrar el puerto 80 si no es necesario.")

_dr("active/Puerto 443",
    "El puerto 443 (HTTPS) es el puerto seguro para las comunicaciones web. Debe estar "
    "correctamente configurado con TLS 1.2 o superior, certificados validos y cabeceras "
    "de seguridad adecuadas.",
    "Mantener el puerto 443 accesible y correctamente asegurado con TLS 1.2/1.3. "
    "Verificar la validez del certificado y renovar antes de la expiracion. "
    "Implementar HSTS y las demas cabeceras de seguridad recomendadas.")

_dr("active/TLS version",
    "La version de TLS negociada determina la seguridad de la comunicacion cifrada. "
    "TLS 1.3 es la version mas segura y rapida. TLS 1.2 es aceptable pero debe configurarse "
    "excluyendo cifrados debiles. Versiones inferiores (TLS 1.1, 1.0, SSL 3.0) son inseguras "
    "y vulnerables a ataques como POODLE, BEAST y Lucky13.",
    "Deshabilitar TLS 1.0 y 1.1. Priorizar TLS 1.3. Si se requiere TLS 1.2, asegurar que "
    "solo se usen cifrados fuertes (ECDHE, GCM, CHACHA20). Revisar la configuracion SSL/TLS "
    "con herramientas como SSL Labs o testssl.sh.")

_dr("active/Certificado TLS",
    "El certificado TLS del servidor web es la base de la confianza en la conexion HTTPS. "
    "Un certificado caducado, emitido por una CA no confiable, o con datos incorrectos "
    "provoca errores de validacion en el navegador y expone a los usuarios a ataques MITM.",
    "Renovar el certificado antes de la fecha de expiracion. Usar certificados de una CA "
    "confiable (Let's Encrypt, DigiCert, Sectigo, etc.). Configurar la renovacion automatica "
    "si es posible. Revisar la cadena de certificacion completa (incluyendo certificados intermedios).")

_dr("active/SAN list",
    "Los Subject Alternative Names (SAN) son dominios y subdominios adicionales cubiertos por "
    "el mismo certificado SSL. Cada SAN adicional amplia la superficie de ataque: un compromiso "
    "en cualquiera de los SAN puede requerir la revocacion de todo el certificado.",
    "Limitar los SAN a los dominios estrictamente necesarios. No incluir dominios internos o "
    "de pruebas. Revisar periodicamente la lista de SAN para detectar inclusiones no autorizadas. "
    "Considerar certificados separados para servicios con distintos niveles de riesgo.")

_dr("active/HTTP status",
    "El codigo de estado HTTP indica como responde el servidor web. Codigos 4xx y 5xx pueden "
    "indicar problemas de configuracion, autenticacion, o errores internos que exponen "
    "informacion sobre la arquitectura o vulnerabilidades.",
    "Verificar que las URL devuelvan los codigos de estado esperados. Personalizar las paginas "
    "de error 404 y 403 para no revelar informacion del servidor. Corregir los errores 5xx "
    "que puedan indicar problemas de configuracion o codigo.")

_dr("active/Redirect chain",
    "La cadena de redirecciones HTTP muestra la secuencia de URLs que sigue el navegador "
    "hasta llegar a la pagina final. Cadenas largas o redirecciones a traves de multiples "
    "dominios aumentan la latencia y pueden exponer informacion en los headers Referer.",
    "Minimizar el numero de redirecciones. Usar redirecciones 301 (permanentes) en lugar de "
    "302 (temporales). Verificar que todas las redirecciones internas vayan a HTTPS. "
    "Eliminar redirecciones innecesarias o encadenadas.")

_dr("active/HSTS",
    "HSTS (HTTP Strict Transport Security) obliga a los navegadores a conectar siempre via HTTPS, "
    "eliminando la posibilidad de ataques SSL stripping. Sin HSTS, un atacante en la misma red "
    "puede interceptar la primera solicitud HTTP y redirigirla a un sitio malicioso.",
    "Configurar HSTS con max-age de al menos 6 meses (15768000 segundos), includeSubDomains "
    "y preload. Enviar el header en todas las respuestas HTTPS. Solicitar la inclusion en el "
    "preload list de los navegadores una vez configurado correctamente.")

_dr("active/CSP",
    "CSP (Content Security Policy) define que fuentes de contenido (scripts, estilos, imagenes) "
    "estan autorizadas a cargar en el navegador. Sin CSP, cualquier vulnerabilidad XSS puede "
    "ser explotada para inyectar scripts maliciosos, robar sesiones o redirigir usuarios.",
    "Configurar CSP con politicas restrictivas: evitar 'unsafe-inline' y 'unsafe-eval'. "
    "Usar nonces o hashes para scripts inline. Incluir report-uri o report-to para monitorear "
    "violaciones. Probar la politica en modo report-only antes de enforce.")

_dr("active/X-Frame-Options",
    "X-Frame-Options controla si el sitio puede ser incrustado en iframes de otros dominios. "
    "Sin esta proteccion, un atacante puede cargar el sitio en un iframe transparente y engañar "
    "al usuario para que haga clic en elementos sobrepuestos (clickjacking).",
    "Configurar X-Frame-Options: DENY o SAMEORIGIN segun las necesidades del negocio. "
    "Para sitios que requieren iframes de terceros, considerar frame-ancestors de CSP. "
    "Verificar que no haya servicios internos accesibles sin esta proteccion.")

_dr("active/X-Content-Type-Options",
    "X-Content-Type-Options: nosniff evita que los navegadores realicen MIME sniffing, "
    "forzando que interpreten los archivos segun el Content-Type declarado. Sin esto, un "
    "atacante puede subir un archivo con extension .jpg que contenga JavaScript y ejecutarlo "
    "en el contexto del sitio.",
    "Configurar X-Content-Type-Options: nosniff en todas las respuestas. Verificar que todos "
    "los archivos servidos tengan el Content-Type correcto. Esto es especialmente importante "
    "en sitios que permiten subida de archivos.")

_dr("active/Referrer-Policy",
    "Referrer-Policy controla cuanta informacion de la URL actual se envia en el header Referer "
    "al navegar a otros sitios. Sin una politica definida, los navegadores pueden enviar la URL "
    "completa, exponiendo parametros sensibles (tokens, IDs de sesion) a terceros.",
    "Configurar Referrer-Policy: strict-origin-when-cross-origin como minimo. "
    "Para sitios con datos sensibles en la URL, usar same-origin o no-referrer. "
    "Revisar que ninguna funcionalidad del sitio dependa del envio de Referer.")

_dr("active/Permissions-Policy",
    "Permissions-Policy (antes Feature-Policy) controla que APIs del navegador (camara, "
    "microfono, geolocalizacion, notificaciones) pueden ser utilizadas por el sitio y sus "
    "iframes. Sin esta politica, cualquier script podria solicitar acceso a sensores del "
    "dispositivo del usuario sin restriccion explicita.",
    "Configurar Permissions-Policy para deshabilitar APIs que no sean necesarias para el "
    "funcionamiento del sitio. Por ejemplo: camera=(), microphone=(), geolocation=(). "
    "Revisar periodicamente que nuevas APIs no queden expuestas sin control.")

_dr("active/COOP",
    "Cross-Origin-Opener-Policy (COOP) aísla el contexto de navegacion del sitio respecto a "
    "ventanas abiertas por otros origenes, previniendo ataques de tipo cross-origin information "
    "leaks (Spectre, XS-Leaks).",
    "Configurar COOP: same-origin para sitios que manejan datos sensibles. "
    "Verificar que no rompa funcionalidades que requieren interaccion entre ventanas de "
    "distintos origenes. Combinar con COEP (Cross-Origin-Embedder-Policy) para proteccion "
    "completa contra ataques de canal lateral.")

_dr("active/Security Headers",
    "Las cabeceras de seguridad HTTP son la primera linea de defensa contra ataques web "
    "comunes (XSS, clickjacking, MIME sniffing, SSL stripping). Cada cabecera ausente o "
    "mal configurada representa un riesgo especifico que puede ser explotado por un atacante.",
    "Implementar todas las cabeceras de seguridad recomendadas por OWASP: HSTS, CSP, "
    "X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP. "
    "Usar herramientas como securityheaders.com para verificar la cobertura.")

_dr("active/STARTTLS",
    "STARTTLS en servidores MX es necesario para cifrar la transmision de correo entre "
    "servidores SMTP. Sin STARTTLS, los correos viajan en texto plano entre organizaciones "
    "y pueden ser interceptados (ataque MITM en el transporte del correo electronico).",
    "Configurar STARTTLS obligatorio en todos los servidores MX. Usar MTA-STS para reforzar "
    "la politica de cifrado. Monitorear las conexiones TLS de los MX con TLS-RPT. "
    "Verificar que ningun MX acepte conexiones en texto plano.")

_dr("active/Takeover",
    "Un subdominio cuyo CNAME apunta a un servicio externo (S3, CloudFront, Heroku, etc.) "
    "que ya no existe o no esta verificado puede ser tomado por un atacante. El atacante "
    "puede alojar contenido malicioso en el subdominio legitimo, realizando phishing o "
    "distribucion de malware con apariencia oficial.",
    "Verificar periodicamente los CNAME de todos los subdominios. Si un recurso externo "
    "se da de baja, eliminar el registro DNS correspondiente. Para servicios cloud, "
    "asegurar que los tokens de verificacion de dominio sigan activos. "
    "Implementar monitoreo automatizado de subdomain takeover.")

_dr("active/Patch/EOL",
    "Se detectaron tecnologias (lenguajes, frameworks, servidores) que han alcanzado su "
    "End of Life (EOL) o estan proximas a él. Las versiones EOL ya no reciben parches de "
    "seguridad, dejando vulnerabilidades conocidas sin correccion oficial y exponiendo "
    "el sistema a explotacion remota.",
    "Actualizar todas las tecnologias EOL a versiones soportadas. Si la actualizacion no "
    "es posible, implementar controles compensatorios (WAF, segmentacion de red, monitoreo "
    "intensificado). Establecer un inventario de tecnologias con fechas EOL y planificar "
    "actualizaciones antes de la fecha limite.")

_dr("active/Supply Chain",
    "La cadena de suministro incluye dependencias de terceros (CDN, analitica, fuentes, APIs) "
    "que se cargan desde dominios externos. Cada dependencia externa amplia la superficie de "
    "ataque: un compromiso del proveedor puede afectar la seguridad del sitio principal.",
    "Auditar regularmente las dependencias externas. Reemplazar las no esenciales con "
    "alternativas auto-alojadas. Aplicar Subresource Integrity (SRI) a los recursos cargados "
    "desde CDNs. Monitorear la reputacion de los proveedores externos.")

_dr("active/SC Rep/DNSBL",
    "Direcciones IP de terceros (CDN, proveedores) en la cadena de suministro aparecen listadas "
    "en DNSBL. Aunque el riesgo primario es del proveedor, la presencia del sitio web en "
    "infraestructura listada puede afectar la reputacion del dominio principal.",
    "Verificar la reputacion de los proveedores antes de integrarlos. Solicitar a los "
    "proveedores listados que resuelvan el problema. Monitorear periodicamente la reputacion "
    "de las IPs de terceros utilizadas.")

_dr("active/SC Rep/URLhaus",
    "Dominios de terceros en la cadena de suministro han sido reportados en URLhaus como "
    "distribuidores de malware. Esto representa un riesgo significativo de compromiso a traves "
    "de la suplantacion o infeccion del proveedor.",
    "Evaluar la urgencia de reemplazar al proveedor comprometido. Contactar al proveedor "
    "para informar del reporte. Mientras tanto, implementar reglas de CSP para restringir "
    "las URLs afectadas. Monitorear la resolucion del incidente.")

_dr("active/Server FP",
    "La huella digital del servidor (server fingerprint) revela el software y la version del "
    "servidor web. Los atacantes usan esta informacion para identificar vulnerabilidades "
    "conocidas especificas de esa version y dirigir ataques mas efectivos.",
    "Ocultar o personalizar la cabecera Server para no revelar la version exacta. "
    "Mantener el servidor web actualizado a la ultima version estable. "
    "Considerar el uso de un WAF o reverse proxy que filtre esta informacion.")

_dr("active/TLS 1.3-only",
    "El servidor acepta exclusivamente TLS 1.3, la version mas moderna y segura del protocolo "
    "TLS. TLS 1.3 elimina cifrados debiles, reduce la latencia de conexion y elimina "
    "vulnerabilidades de versiones anteriores como el downgrade forzado.",
    "Mantener la configuracion actual. Verificar compatibilidad con los clientes que necesitan "
    "acceder al servicio. Si se requiere soporte para clientes antiguos, habilitar TLS 1.2 "
    "con cifrados fuertes (ECDHE con GCM o CHACHA20) como alternativa.")


def classify_issues(m: dict[str, Any], p: dict[str, Any]) -> tuple[list[dict], list[dict]]:
    passive: list[dict] = []
    active: list[dict] = []

    def add(cat: str, label: str, sev: str, detail: str, dom: str = "", evidence: str = "",
            desc_override: str = "", rec_override: str = "") -> None:
        target = passive if cat == "passive" else active
        rec_key = cat + "/" + label
        dp, rc = _DESC_REC.get(rec_key, ("", ""))
        if cat == "passive" and label == "DNSBL":
            dp, rc = _DESC_REC.get("DNSBL (passive)", ("", ""))
        if cat == "passive" and label == "URLhaus":
            dp, rc = _DESC_REC.get("URLhaus (passive)", ("", ""))
        if desc_override:
            dp = desc_override
        if rec_override:
            rc = rec_override
        target.append({"label": label, "severity": sev, "detail": detail, "domain": dom,
                       "evidence": evidence, "descripcion": dp, "recomendacion": rc})

    domain = m.get("dominio", "")
    dns = p.get("dns", {})
    https = p.get("https", {})
    headers = https.get("headers", {})
    tls = p.get("tls", {})

    # --- PASSIVE ---
    if dns.get("ipv4"):
        add("passive", "A IPv4", "info", f"{len(dns['ipv4'])} registro(s)", domain,
            _evidence_block(dns['ipv4'], "Registros A"))
    if dns.get("ipv6"):
        add("passive", "AAAA IPv6", "info", f"{len(dns['ipv6'])} registro(s)", domain,
            _evidence_block(dns['ipv6'], "Registros AAAA"))
    mx = dns.get("mx_records", [])
    if mx:
        lines = [f"{m.get('preference','?')} {m.get('exchange','')}" for m in mx]
        add("passive", "MX", "info", f"{len(mx)} servidor(es)", domain,
            _evidence_block(lines, "Registros MX"))
    else:
        add("passive", "MX", "baja", "Sin servidores MX", domain)

    ns = dns.get("ns_records", [])
    if ns:
        lines = [m.get("nameserver", "") for m in ns]
        add("passive", "NS", "info", f"{len(ns)} servidor(es)", domain,
            _evidence_block(lines, "Nameservers"))

    spf = dns.get("spf_record")
    if spf:
        if "-all" in spf.replace(" ", "").lower():
            add("passive", "SPF", "info", "Hard-fail (-all) configurado", domain,
                _evidence_text(spf[:500], "Registro SPF"))
        elif "~all" in spf.lower():
            add("passive", "SPF", "media", "Soft-fail (~all)", domain,
                _evidence_text(spf[:500], "Registro SPF"))
        else:
            add("passive", "SPF", "baja", "Sin mecanismo de rechazo fuerte", domain,
                _evidence_text(spf[:500], "Registro SPF"))
    else:
        add("passive", "SPF", "alta", "SPF no configurado", domain)

    dmarc_pol = dns.get("dmarc_policy")
    dmarc_rec = dns.get("dmarc_record")
    if dmarc_rec:
        sev = "info" if dmarc_pol == "reject" else ("media" if dmarc_pol == "quarantine" else "alta")
        add("passive", "DMARC", sev, f"Politica: {dmarc_pol or 'desconocida'}", domain,
            _evidence_text(dmarc_rec[:500], "Registro DMARC"))
    else:
        add("passive", "DMARC", "alta", "DMARC no configurado", domain)

    dkim = dns.get("dkim_records", [])
    if dkim:
        lines = [f"{d['selector']}: {d['record'][:100]}" for d in dkim]
        add("passive", "DKIM", "info", f"{len(dkim)} registro(s)", domain,
            _evidence_block(lines, "Registros DKIM"))
    else:
        add("passive", "DKIM", "media", "Sin registros DKIM", domain)

    if dns.get("dnssec_ok"):
        add("passive", "DNSSEC", "info", "DNSSEC activo", domain)
    else:
        add("passive", "DNSSEC", "media", "DNSSEC no detectado", domain)

    dane = dns.get("dane_records", [])
    if dane:
        lines = [f"_{d['port']}._{d['protocol']}: usage={d['usage']} sel={d['selector']} type={d['mtype']}" for d in dane]
        add("passive", "DANE/TLSA", "info", f"{len(dane)} registro(s)", domain,
            _evidence_block(lines, "Registros DANE/TLSA"))
    else:
        add("passive", "DANE/TLSA", "media", "Sin registros DANE/TLSA", domain)

    caa = p.get("caa_records", [])
    if caa:
        lines = [f"{c.get('tag','')} {c.get('value','')}" for c in caa]
        add("passive", "CAA", "info", f"{len(caa)} registro(s)", domain,
            _evidence_block(lines, "Registros CAA"))
    else:
        add("passive", "CAA", "baja", "Sin registros CAA", domain)

    if p.get("mta_sts"):
        add("passive", "MTA-STS", "info", "Configurado", domain,
            _evidence_text(str(p.get("mta_sts","")), "MTA-STS"))
    else:
        add("passive", "MTA-STS", "baja", "No configurado", domain)
    if p.get("tls_rpt"):
        add("passive", "TLS-RPT", "info", "Configurado", domain,
            _evidence_text(str(p.get("tls_rpt","")), "TLS-RPT"))
    if p.get("bimi"):
        add("passive", "BIMI", "info", "Configurado", domain,
            _evidence_text(str(p.get("bimi","")), "BIMI"))

    ip_rep = dns.get("ip_reputation", [])
    if ip_rep:
        lines = [f"IP {r.get('ip','?')} listada en {r.get('dnsbl','?')}" for r in ip_rep]
        add("passive", "DNSBL", "alta", f"{len(ip_rep)} listado(s)", domain,
            _evidence_block(lines, "Listados DNSBL"))
    else:
        add("passive", "DNSBL", "info", "Sin listados en DNSBL", domain)

    uh = p.get("urlhaus", {})
    if uh.get("malicious"):
        lines = [f"URLs reportadas: {uh.get('url_count',0)}", f"Primer avistamiento: {uh.get('first_seen','?')}", f"Ultimo avistamiento: {uh.get('last_seen','?')}"] + [f"URL: {u}" for u in uh.get('urls',[])]
        add("passive", "URLhaus", "alta", f"Dominio reportado ({uh.get('url_count',0)} URLs)", domain,
            _evidence_block(lines, "URLhaus"))
    elif uh.get("error"):
        add("passive", "URLhaus", "info", f"API: {uh['error']}", domain)
    else:
        add("passive", "URLhaus", "info", "No reportado como malicioso", domain,
            _evidence_text("query_status: ok, url_count: 0", "URLhaus"))

    crt = p.get("crt_subdomains", [])
    if crt:
        add("passive", "CT Logs", "info", f"{len(crt)} subdominio(s)", domain,
            _evidence_block(crt, "Subdominios (Certificate Transparency)"))

    brute_subs = p.get("brute_subs", [])
    if brute_subs:
        lines = [f"{b.get('fqdn','?')} -> {', '.join(b.get('ips',[]) or [])}" for b in brute_subs]
        add("passive", "Subdominios (Brute)", "info", f"{len(brute_subs)} subdominio(s)", domain,
            _evidence_block(lines, "Subdominios descubiertos por fuerza bruta DNS"))

    pivot_res = p.get("pivot_results", [])
    if pivot_res:
        for r in pivot_res:
            ips = r.get("ptr", "")
            fqdns = r.get("fqdns_from_crt", [])
            rdap = r.get("rdap", {})
            items = []
            if ips: items.append(f"PTR: {ips}")
            if fqdns: items.append(f"FQDNs via crt.sh ({len(fqdns)}): {', '.join(fqdns[:10])}{'...' if len(fqdns)>10 else ''}")
            if rdap.get("org"): items.append(f"Org: {rdap['org']}")
            if rdap.get("net_range"): items.append(f"NetRange: {rdap['net_range']}")
            if items:
                add("passive", "IP Pivot", "info", f"{r.get('ip','?')} -> {fqdns[0] if fqdns else ips or '?'}", domain,
                    _evidence_block(items, f"Pivot IP: {r.get('ip','?')}"))

    typos = p.get("typosquatting", [])
    if typos:
        lines = [f"{t.get('domain','?')} -> {', '.join(t.get('ips',[]) or [])}" for t in typos]
        add("passive", "Typosquatting", "alta", f"{len(typos)} variante(s) registradas", domain,
            _evidence_block(lines, "Typosquatting"))

    vulns = p.get("vulnerabilities", [])
    if vulns:
        lines = [f"{v.get('cve_id','?')} - {v.get('summary','')[:120]}" for v in vulns]
        add("passive", "CVE OSV", "alta", f"{len(vulns)} vulnerabilidad(es)", domain,
            _evidence_block(lines, "Vulnerabilidades OSV"))

    cve_f = p.get("cve_findings") or []
    if cve_f:
        kev_count = sum(1 for c in cve_f if c.get("in_kev"))
        high_risk = sum(1 for c in cve_f if (c.get("risk_score") or 0) >= 7)
        extra = ""
        if high_risk:
            extra += f" ({high_risk} riesgo-alto"
            extra += f", {kev_count} KEV)" if kev_count else ")"
        elif kev_count:
            extra = f" ({kev_count} en CISA KEV)"
        def _cve_line(c2):
            base = f"{c2.get('id','?')} [{c2.get('type','?')}] {c2.get('title','')[:100]} (:{c2.get('port','?')})"
            parts = []
            rs = c2.get("risk_score")
            if rs is not None:
                parts.append(f"Risk:{rs:.1f}")
            epss = c2.get("epss_score")
            if epss is not None:
                parts.append(f"EPSS:{epss*100:.1f}%")
            if c2.get("in_kev"):
                parts.append("KEV")
            return base + (" [" + "/".join(parts) + "]" if parts else "")
        lines = [_cve_line(c) for c in cve_f]
        add("passive", "CVE Banner Grab", "media", f"{len(cve_f)} coincidencia(s){extra}", domain,
            _evidence_block(lines, "CVEs por banner grab (vulscan)"))

    banners = p.get("banner_grabs") or []
    service_banners = [b for b in banners if not b.get("error")]
    if service_banners:
        lines = [f"Puerto {b.get('port','?')} ({b.get('protocol','?')}): {b.get('product','?')}" + (f" v{b.get('version','')}" if b.get('version') else "") for b in service_banners]
        add("active", "Banner Grab", "info", f"{len(service_banners)} servicio(s)", domain,
            _evidence_block(lines, "Banners de servicio"))

    # API Endpoints
    api_eps = p.get("api_endpoints") or []
    api_non404 = [e for e in api_eps if e.get("status_code") and e["status_code"] != 404]
    api_shadow = [e for e in api_eps if e.get("is_shadow")]
    if api_non404:
        lines = [f"{e.get('method','?')} {e.get('path','?')} -> HTTP {e.get('status_code','?')} [{e.get('category','?')}] {'⚠ SHADOW' if e.get('is_shadow') else ''}" for e in api_non404]
        sev = "alta" if api_shadow else "media"
        add("active" if any(e.get("status_code") and e["status_code"] < 500 for e in api_non404) else "passive",
            "API Discovery", sev, f"{len(api_non404)} endpoints ({len(api_shadow)} shadow)", domain,
            _evidence_block(lines, "API endpoints descubiertos"))

    # Public Paths
    paths = p.get("public_paths") or []
    interesting = [x for x in paths if x.get("status_code") not in (None, 404)]
    if interesting:
        lines = [f"{x.get('path','')} -> HTTP {x.get('status_code','?')} [{x.get('method','HEAD')}]" for x in interesting]
        add("active", "Public Paths", "media", f"{len(interesting)} rutas accesibles", domain,
            _evidence_block(lines, "Rutas publicas que responden"))

    leaks = p.get("credential_leaks", [])
    clean_leaks = [l for l in leaks if "error" not in l]
    if clean_leaks:
        lines = [f"{l.get('breach','?')}: {l.get('records',0)} registros" for l in clean_leaks]
        add("passive", "Cred. Leaks", "alta", f"{len(clean_leaks)} breach(es)", domain,
            _evidence_block(lines, "Credential Leaks"))
    if any("error" in l for l in leaks):
        err = next((l.get("error","") for l in leaks if "error" in l), "")
        add("passive", "Cred. Leaks", "info", f"API: {err}", domain)

    social = p.get("social", {})
    for net, data in social.items():
        if data.get("error"):
            continue
        uname = data.get("username", "")
        if uname:
            lines = []
            for k in ("name", "description", "followers", "following", "posts", "url"):
                if data.get(k):
                    lines.append(f"{k}: {data[k]}")
            add("passive", f"Social/{net}", "info", f"@{uname}", domain,
                _evidence_block(lines, f"Perfil {net}"))

    ext = p.get("external") or {}
    whois = ext.get("whois") or {}
    if "error" not in whois:
        items = []
        if whois.get("registrar"): items.append(f"Registrar: {whois['registrar']}")
        if whois.get("registrant_organization"): items.append(f"Org: {whois['registrant_organization']}")
        if whois.get("registrant_country"): items.append(f"Pais: {whois['registrant_country']}")
        if whois.get("creation_date"): items.append(f"Creado: {whois['creation_date']}")
        if whois.get("expiration_date"): items.append(f"Expira: {whois['expiration_date']}")
        if items:
            add("passive", "WHOIS", "info", f"Registrado por {whois.get('registrar','?')}", domain,
                _evidence_block(items, "WHOIS"))
    shodan = ext.get("shodan") or {}
    if "error" not in shodan and shodan.get("hosts"):
        ports = list({p2 for h in shodan["hosts"] for p2 in h.get("ports", [])})
        vulns = list({v for h in shodan["hosts"] for v in h.get("vulns", [])})
        items = [f"Puertos: {', '.join(str(p) for p in sorted(ports))}"]
        if vulns:
            items.append(f"Vulnerabilidades: {', '.join(vulns)}")
        add("passive", "Shodan", "info", f"{len(ports)} puerto(s), {len(vulns)} CVE(s)", domain,
            _evidence_block(items, "Shodan"))
    censys = ext.get("censys") or {}
    if "error" not in censys:
        certs = censys.get("certificates") or []
        hosts = censys.get("hosts") or []
        items = []
        if certs: items.append(f"Certificados: {len(certs)}")
        if hosts: items.append(f"Hosts: {len(hosts)}")
        if items:
            add("passive", "Censys", "info", "; ".join(items), domain)
    th = ext.get("theharvester") or {}
    if "error" not in th:
        em = th.get("emails") or []
        sd = th.get("subdomains") or []
        items = []
        if em: items.append(f"Emails: {len(em)}")
        if sd: items.append(f"Subdominios: {len(sd)}")
        if items:
            add("passive", "theHarvester", "info", "; ".join(items), domain,
                _evidence_block((em if em else []) + (sd if sd else []), "theHarvester"))
    dnsd = ext.get("dnsdumpster") or {}
    if "error" not in dnsd and dnsd.get("host_records"):
        items = [f"{r[0]} ({', '.join(str(x) for x in r[1:])})" for r in dnsd["host_records"][:15]]
        add("passive", "DNSDumpster", "info", f"{len(dnsd['host_records'])} registro(s)", domain,
            _evidence_block(items, "DNSDumpster"))

    # --- ACTIVE ---
    p80 = p.get("port_80", {})
    p443 = p.get("port_443", {})
    if p80.get("open"):
        add("active", "Puerto 80", "media", "HTTP abierto (redireccion HTTPS?)", domain)
    else:
        err80 = p80.get("error","")
        add("active", "Puerto 80", "info", "Cerrado", domain,
            _evidence_text(err80, "Error al conectar") if err80 else "")
    if p443.get("open"):
        add("active", "Puerto 443", "info", "HTTPS abierto", domain)
    else:
        err443 = p443.get("error","")
        add("active", "Puerto 443", "alta", "HTTPS cerrado", domain,
            _evidence_text(err443, "Error al conectar") if err443 else "")

    open_ports = p.get("open_ports", [])
    open_filtered = [o for o in open_ports if o.get("state") == "open"]
    if open_filtered:
        lines = [f"Puerto {o.get('port','?')}: {o.get('service','?')}" for o in open_filtered]
        extra = ""
        if len(open_filtered) > 50:
            extra = f" ... y {len(open_filtered)-50} mas"
            lines.append(extra)
        add("active", "Puertos abiertos", "info", f"{len(open_filtered)} puerto(s) abierto(s){extra}", domain,
            _evidence_block(lines, "Puertos abiertos (scan completo)"))

    tls_ver = tls.get("negotiated_version")
    if tls_ver:
        sev = "info" if "1.3" in str(tls_ver) else ("media" if "1.2" in str(tls_ver) else "alta")
        add("active", "TLS version", sev, f"Negociado: {tls_ver}", domain)
    if tls.get("tls13_only_ok"):
        add("active", "TLS 1.3-only", "info", "Acepta solo TLS 1.3", domain)

    cert_subj = tls.get("cert_subject")
    cert_iss = tls.get("cert_issuer")
    cert_exp = tls.get("cert_expiry")
    cert_ser = tls.get("cert_serial")
    cert_ver = tls.get("cert_version")
    if cert_subj or cert_iss or cert_exp:
        lines = [f"Subject: {cert_subj}", f"Issuer: {cert_iss}", f"Expira: {cert_exp}", f"Serial: {cert_ser}", f"Version: {cert_ver}"]
        add("active", "Certificado TLS", "info", f"Expira: {cert_exp or '?'}", domain,
            _evidence_block([l for l in lines if l and not l.endswith(": ") and not l.endswith(": None")], "Certificado TLS"))

    san = tls.get("san_list", [])
    if san:
        add("active", "SAN list", "info", f"{len(san)} nombre(s) alternativo(s)", domain,
            _evidence_block(san, "Subject Alternative Names"))

    sc = https.get("status_code")
    furl = https.get("final_url")
    if sc:
        sev = "info" if 200 <= sc < 400 else "alta"
        add("active", "HTTP status", sev, f"HTTP {sc} -> {furl or ''}", domain)

    redirects = https.get("redirect_chain", [])
    if len(redirects) > 1:
        add("active", "Redirect chain", "info", f"{len(redirects)} salto(s)", domain,
            _evidence_block(redirects, "Cadena de redirecciones"))

    # All security headers as evidence
    sec_headers = {k: v for k, v in headers.items() if k in (
        "strict-transport-security", "content-security-policy", "content-security-policy-report-only",
        "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy",
        "cross-origin-opener-policy", "server", "x-powered-by", "set-cookie"
    )}

    hsts = headers.get("strict-transport-security")
    if hsts:
        add("active", "HSTS", "info", "Configurado", domain,
            _evidence_text(hsts, "Header HSTS"))
    else:
        add("active", "HSTS", "alta", "No configurado (riesgo SSL stripping)", domain)

    csp = headers.get("content-security-policy") or headers.get("content-security-policy-report-only")
    if csp:
        add("active", "CSP", "info", "Configurado", domain,
            _evidence_text(csp[:500], "Content-Security-Policy"))
    else:
        add("active", "CSP", "alta", "No configurado (riesgo XSS)", domain)

    csp_findings = p.get("csp_findings", [])
    for f in csp_findings:
        sev = f.get("severity", "media")
        rec = f.get("recommendation", "")
        desc = f.get("description", "")
        add("active", f"CSP: {f.get('directive','')}", sev, desc[:200], domain,
            desc_override=desc, rec_override=rec)

    cookie_findings = p.get("cookie_findings", [])
    for f in cookie_findings:
        sev = f.get("severity", "media")
        desc = f.get("description", "")
        rec = f.get("recommendation", "")
        add("active", f"Cookie: {f.get('cookie','')}", sev, desc[:200], domain,
            desc_override=desc, rec_override=rec)

    xfo = headers.get("x-frame-options")
    if xfo:
        add("active", "X-Frame-Options", "info", xfo, domain,
            _evidence_text(xfo, "Header X-Frame-Options"))
    else:
        add("active", "X-Frame-Options", "alta", "No configurado (clickjacking)", domain)

    xcto = headers.get("x-content-type-options")
    if xcto and "nosniff" in xcto.lower():
        add("active", "X-Content-Type-Options", "info", "nosniff configurado", domain,
            _evidence_text(xcto, "Header X-Content-Type-Options"))
    else:
        add("active", "X-Content-Type-Options", "media", "No configurado", domain)

    rp = headers.get("referrer-policy")
    if rp:
        add("active", "Referrer-Policy", "info", rp, domain,
            _evidence_text(rp, "Header Referrer-Policy"))
    else:
        add("active", "Referrer-Policy", "baja", "No configurado", domain)

    pp = headers.get("permissions-policy")
    if pp:
        add("active", "Permissions-Policy", "info", "Configurado", domain,
            _evidence_text(pp[:300], "Permissions-Policy"))
    coop = headers.get("cross-origin-opener-policy")
    if coop:
        add("active", "COOP", "info", coop, domain,
            _evidence_text(coop, "Cross-Origin-Opener-Policy"))

    # Show all security headers as block
    if sec_headers:
        add("active", "Security Headers", "info", f"{len(sec_headers)} cabecera(s)", domain,
            _evidence_dict(sec_headers, "Cabeceras de seguridad HTTP"))

    stls = dns.get("starttls_results", [])
    if stls:
        ok = all(s.get("starttls") for s in stls)
        lines = [f"{s.get('exchange','?')}: STARTTLS={'SI' if s.get('starttls') else 'NO'}{' error='+s.get('error','') if s.get('error') else ''}" for s in stls]
        add("active", "STARTTLS", "info" if ok else "alta",
            "Disponible en todos los MX" if ok else f"Falta en {sum(1 for s in stls if not s.get('starttls'))} MX", domain,
            _evidence_block(lines, "Resultados STARTTLS"))

    takeover = p.get("takeover_risks", [])
    for t in takeover:
        sev = "alta" if t.get("vulnerable") else "media"
        lines = [f"Host: {t.get('host','?')}", f"CNAME: {t.get('cname','?')}", f"Servicio: {t.get('service','?')}", f"Descripcion: {t.get('description','?')}"]
        add("active", "Takeover", sev, f"{t.get('host','?')} -> {t.get('cname','?')}", domain,
            _evidence_block(lines, "Subdomain Takeover"))

    patching = p.get("patching", [])
    for pt in patching:
        if pt.get("status") == "eol":
            add("active", "Patch/EOL", "alta", f"{pt['technology']} {pt.get('version','')}", domain,
                _evidence_text(pt.get('detail',''), f"{pt['technology']} EOL"))
        elif pt.get("status") == "ending":
            add("active", "Patch/EOL", "media", f"{pt['technology']} {pt.get('version','')}", domain,
                _evidence_text(pt.get('detail',''), f"{pt['technology']} ending"))

    supply = p.get("supply_chain", [])
    if supply:
        lines = [f"{s.get('domain','?')} [{s.get('source','?')}] - {', '.join(s.get('ips',[]) or [])}" for s in supply]
        add("active", "Supply Chain", "info", f"{len(supply)} dependencia(s)", domain,
            _evidence_block(lines, "Cadena de suministro"))

    scr = p.get("supply_chain_reputation", {})
    if scr.get("dnsbl_count", 0) > 0:
        lines = [f"{s.get('ip','?')} en {s.get('dnsbl','?')}" for s in scr.get("dnsbl",[])]
        add("active", "SC Rep/DNSBL", "alta", f"{scr['dnsbl_count']} IP tercero(s) listada(s)", domain,
            _evidence_block(lines, "Supply Chain DNSBL"))
    if scr.get("urlhaus_count", 0) > 0:
        lines = [f"{s.get('domain','?')} ({s.get('url_count',0)} URLs)" for s in scr.get("urlhaus",[])]
        add("active", "SC Rep/URLhaus", "alta", f"{scr['urlhaus_count']} dominio(s) tercero(s) en URLhaus", domain,
            _evidence_block(lines, "Supply Chain URLhaus"))

        fp = https.get("server_fingerprint")
        if fp:
            add("active", "Server FP", "info", fp, domain)

        fr = p.get("finalrecon") or {}
        if fr:
            fr_js = fr.get("javascripts") or []
            fr_wb = fr.get("wayback") or {}
            fr_wb_js = fr_wb.get("js_files") or []
            fr_wb_api = fr_wb.get("api_endpoints") or []
            fr_wb_params = fr_wb.get("juicy_params") or []
            fr_sitemap = fr.get("sitemap") or []
            fr_ext = fr.get("external_urls") or []
            all_js = list(dict.fromkeys(fr_js + fr_wb_js))
            if all_js:
                js_sample = "; ".join(all_js[:5])
                add("passive", "FinalRecon/JS", "media", f"{len(all_js)} archivos JS expuestos", domain,
                    _evidence_text(js_sample, f"JS expuestos ({len(all_js)})"),
                    "Los archivos JavaScript expuestos pueden revelar logica de negocio, endpoints internos o secretos embebidos como API keys.",
                    "Revisar archivos JS para evitar inclusion de secretos, API keys o endpoints internos.")
            if fr_ext:
                ext_sample = "; ".join(fr_ext[:5])
                add("passive", "FinalRecon/ExtLinks", "info", f"{len(fr_ext)} enlaces externos", domain,
                    _evidence_text(ext_sample, f"Enlaces externos ({len(fr_ext)})"),
                    "Los enlaces externos en la pagina web pueden revelar relaciones con terceros o CDNs que amplian la superficie de ataque.",
                    "Auditar los recursos externos y asegurar que sean de fuentes confiables.")
            if fr_sitemap:
                add("passive", "FinalRecon/Sitemap", "info", f"Sitemap: {len(fr_sitemap)} URLs", domain,
                    _evidence_text(f"Total URLs en sitemap: {len(fr_sitemap)}", "Sitemap expuesto"),
                    "El sitemap.xml expone todas las rutas del sitio, facilitando el reconocimiento a atacantes.",
                    "Verificar que el sitemap solo contenga URLs destinadas a indexacion publica.")
            if fr_wb_js:
                add("passive", "FinalRecon/WaybackJS", "media", f"{len(fr_wb_js)} JS historicos Wayback", domain,
                    _evidence_text("; ".join(fr_wb_js[:5]), f"JS historicos Wayback ({len(fr_wb_js)})"),
                    "Los archivos JS historicos en Wayback Machine pueden contener codigo sensible obsoleto o versiones anteriores con vulnerabilidades.",
                    "Revisar los JS historicos y considerar solicitar su eliminacion de Wayback Machine si contienen datos sensibles.")
            if fr_wb_api:
                api_sample = "; ".join(fr_wb_api[:5])
                add("passive", "FinalRecon/WaybackAPI", "alta", f"{len(fr_wb_api)} endpoints API Wayback", domain,
                    _evidence_text(api_sample, f"Endpoints API Wayback ({len(fr_wb_api)})"),
                    "Endpoints API descubiertos en Wayback Machine pueden exponer funcionalidades internas o datos sensibles sin autenticacion.",
                    "Revisar que estos endpoints requieran autenticacion y no expongan funcionalidades sensibles.")
            if fr_wb_params:
                param_sample = "; ".join(fr_wb_params[:5])
                add("passive", "FinalRecon/WaybackParams", "media", f"{len(fr_wb_params)} parametros sensibles Wayback", domain,
                    _evidence_text(param_sample, f"Params sensibles Wayback ({len(fr_wb_params)})"),
                    "URLs con parametros potencialmente sensibles (tokens, IDs, claves) en archivos historicos pueden exponer datos privados.",
                    "Auditar los parametros sensibles y asegurarse de que no expongan datos privados o permitan acceso no autorizado.")

    return passive, active


# ---------------------------------------------------------------------------
# CSS - TIPOGRAFIA GRANDE
# ---------------------------------------------------------------------------

CSS = r"""
:root {
  --bg-body: #0d0d0d;
  --bg-card: #111111;
  --bg-card-alt: #151515;
  --border: #303030;
  --text: #e0e0e0;
  --text-muted: #9e9e9e;
  --passive: #64b5f6;
  --passive-bg: rgba(100, 181, 246, 0.15);
  --active: #ffb74d;
  --active-bg: rgba(255, 183, 77, 0.15);
  --good: #81c784;
  --good-bg: rgba(129, 199, 132, 0.15);
  --warn: #ffb74d;
  --bad: #e57373;
  --bad-bg: rgba(229, 115, 115, 0.15);
  --info: #64b5f6;
  --accent: #4fc3f7;
  --font: 'Segoe UI',system-ui,-apple-system,sans-serif;
}
* { box-sizing:border-box; margin:0; padding:0; }
body { background:var(--bg-body); color:var(--text); font-family:var(--font); font-size:16px; line-height:1.6; padding:0; }
.wrap { max-width:1100px; margin:0 auto; padding:20px 24px 50px; }

/* Header */
.header { background:linear-gradient(135deg,#000000 0%,#1a1a1a 100%); border-radius:12px; padding:28px 32px; margin-bottom:28px; display:flex; align-items:center; gap:20px; color:#fff; }
.header .shield { font-size:42px; line-height:1; }
.header h1 { font-size:1.5rem; font-weight:700; letter-spacing:.02em; }
.header .meta { font-size:13px; opacity:.75; margin-top:4px; }
.header .badge-pa { display:inline-flex; gap:10px; margin-left:auto; }
.header .badge-pa span { padding:6px 16px; border-radius:6px; font-size:13px; font-weight:700; letter-spacing:.06em; }
.badge-passive { background:var(--passive-bg); color:var(--passive); border:1px solid var(--passive); }
.badge-active { background:var(--active-bg); color:var(--active); border:1px solid var(--active); }

/* KPI row */
.kpis { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; margin-bottom:24px; }
.kpi { background:var(--bg-card); border:1px solid var(--border); border-radius:10px; padding:18px 20px; text-align:center; box-shadow:0 1px 3px rgba(0,0,0,.04); }
.kpi .num { font-size:32px; font-weight:700; line-height:1.2; }
.kpi .lbl { font-size:12px; color:var(--text-muted); text-transform:uppercase; letter-spacing:.06em; margin-top:4px; }

/* Grade row */
.grade-row { display:flex; align-items:center; gap:18px; background:var(--bg-card); border:1px solid var(--border); border-radius:12px; padding:20px 24px; margin-bottom:24px; box-shadow:0 1px 3px rgba(0,0,0,.04); }
.grade-letter { font-size:56px; font-weight:800; line-height:1; width:70px; text-align:center; }
.grade-bar { flex:1; height:12px; background:#e2e8f0; border-radius:6px; overflow:hidden; }
.grade-fill { height:100%; border-radius:6px; }
.grade-desc { font-size:14px; color:var(--text-muted); }

/* Two-column passive/active overview */
.pa-overview { display:grid; grid-template-columns:1fr 1fr; gap:18px; margin-bottom:24px; }
.pa-col { background:var(--bg-card); border:1px solid var(--border); border-radius:12px; padding:20px 24px; box-shadow:0 1px 3px rgba(0,0,0,.04); }
.pa-col.passive { border-left:4px solid var(--passive); }
.pa-col.active { border-left:4px solid var(--active); }
.pa-col h3 { font-size:14px; text-transform:uppercase; letter-spacing:.1em; margin-bottom:10px; display:flex; align-items:center; gap:8px; }
.pa-col h3 .icon { font-size:20px; }
.pa-col.passive h3 { color:var(--passive); }
.pa-col.active h3 { color:var(--active); }
.pa-count { font-size:36px; font-weight:700; }
.pa-sub { font-size:13px; color:var(--text-muted); margin-top:4px; }
.pa-desc { font-size:13px; color:var(--text-muted); margin-top:8px; line-height:1.5; }

/* Table */
table.data { width:100%; border-collapse:collapse; font-size:14px; margin-bottom:24px; background:var(--bg-card); border-radius:8px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.04); }
table.data th { background:#1a1a1a; border:1px solid var(--border); padding:10px 12px; text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--text-muted); font-weight:600; }
table.data td { border:1px solid var(--border); padding:8px 10px; vertical-align:top; }
table.data tr:hover td { background:var(--bg-card-alt); }
table.data .num { text-align:right; white-space:nowrap; }

/* Badges */
.tag { display:inline-block; padding:3px 10px; border-radius:4px; font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:.05em; }
.tag.passive { background:var(--passive-bg); color:var(--passive); border:1px solid var(--passive); }
.tag.active { background:var(--active-bg); color:var(--active); border:1px solid var(--active); }
.sev { display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; text-transform:uppercase; }
.sev.alta { background:var(--bad-bg); color:var(--bad); }
.sev.media { background:var(--active-bg); color:#ffb74d; }
.sev.baja { background:var(--good-bg); color:var(--good); }
.sev.info { background:var(--passive-bg); color:var(--passive); }

/* Finding cards */
.findings-grid { display:grid; grid-template-columns:1fr; gap:8px; margin-bottom:24px; }
.finding { background:var(--bg-card); border:1px solid var(--border); border-radius:8px; padding:14px 16px; box-shadow:0 1px 3px rgba(0,0,0,.04); }
.finding .f-header { display:flex; align-items:center; gap:8px; margin-bottom:6px; flex-wrap:wrap; }
.finding .f-label { font-size:15px; font-weight:600; color:var(--text); }
.finding .f-domain { font-size:13px; color:var(--text-muted); margin-bottom:4px; }
.finding .f-detail { font-size:14px; color:var(--text-muted); line-height:1.5; white-space:pre-wrap; }

/* Description and recommendation */
.f-desc { font-size:14px; color:var(--text); line-height:1.6; margin:6px 0; padding:8px 10px; background:#1a1a1a; border-left:3px solid var(--info); border-radius:4px; }
.f-rec { font-size:14px; color:var(--text); line-height:1.6; margin:6px 0; padding:8px 10px; background:#1a1a1a; border-left:3px solid var(--warn); border-radius:4px; }
.f-rec strong { color:#ffb74d; }

/* Evidence visible block */
.ev-body { background:#1a1a1a; border:1px solid var(--border); border-radius:6px; padding:10px 14px; margin-top:6px; max-height:400px; overflow-y:auto; }
.ev-title { font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:.06em; color:var(--text-muted); margin-bottom:4px; }
.ev-line { display:block; padding:2px 0; font-family:'Cascadia Code','Fira Code','Consolas',monospace; font-size:13px; word-break:break-all; line-height:1.5; color:#b0b0b0; }
.ev-line strong { color:var(--accent); }

/* Provider cards */
.prov-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(340px,1fr)); gap:14px; margin-bottom:24px; }
.prov-card { background:var(--bg-card); border:1px solid var(--border); border-radius:10px; padding:16px 18px; box-shadow:0 1px 3px rgba(0,0,0,.04); }
.prov-card h4 { font-size:15px; font-weight:600; margin-bottom:6px; }
.prov-card .pdom { font-size:13px; color:var(--text-muted); }
.prov-bar { display:flex; gap:0; height:6px; border-radius:3px; overflow:hidden; margin:8px 0; }
.prov-bar .seg.passive { background:var(--passive); }
.prov-bar .seg.active { background:var(--active); }
.prov-stats { display:flex; gap:16px; font-size:13px; color:var(--text-muted); }

/* OWASP */
.owasp-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(200px,1fr)); gap:10px; margin-bottom:24px; }
.owasp-item { background:var(--bg-card); border:1px solid var(--border); border-radius:8px; padding:12px; box-shadow:0 1px 3px rgba(0,0,0,.04); }
.owasp-item .oid { font-size:11px; font-weight:700; color:var(--accent); }
.owasp-item .otitle { font-size:14px; margin:4px 0; }
.owasp-bar { height:6px; background:#e2e8f0; border-radius:3px; margin-top:8px; }
.owasp-fill { height:6px; border-radius:3px; }
.owasp-pct { font-size:13px; color:var(--text-muted); margin-top:2px; }

/* Section title */
.sec-title { font-size:18px; font-weight:700; color:var(--accent); border-bottom:2px solid var(--accent); padding-bottom:6px; margin:28px 0 16px; display:flex; align-items:center; gap:10px; }

/* Footer */
.footer { text-align:center; font-size:13px; color:var(--text-muted); border-top:1px solid var(--border); padding-top:16px; margin-top:28px; }

/* Scrollable table wrapper */
.tbl-wrap { overflow-x:auto; margin-bottom:24px; }

/* Badges */
.risk-critical { display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#5c1010; color:#fff; }
.risk-high { display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#9b1c1c; color:#fff; }
.risk-med { display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#cc8800; color:#fff; }
.risk-low { display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#2d7a4a; color:#fff; }
.epss-badge { display:inline-block; font-size:10px; padding:1px 5px; border-radius:4px; background:#e8eef5; color:#3a5478; }
.kev-badge { display:inline-block; font-size:10px; font-weight:700; padding:1px 6px; border-radius:4px; background:#fce4e4; color:#a00; }
/* Print */
@media print { body { background:#fff; color:#000; } 
   .header,.kpi,.pa-col,.finding,.prov-card,.owasp-item,.grade-row { break-inside:avoid; }
   .header { background:#000000!important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
   .tag,.sev,.badge-passive,.badge-active { -webkit-print-color-adjust:exact; print-color-adjust:exact; }
}
"""


def build_report(asm: dict[str, Any], title: str, subtitle: str, version: str) -> str:
    providers = asm.get("providers", [])
    matrix = asm.get("matrix", [])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    toc_block = render_toc(report_type="default")
    scanned_at = asm.get("generated_utc", now)
    # Resumen Ejecutivo canónico (estilo Beta1)
    resumen_block = render_resumen_ejecutivo(providers, asm, fecha_str=now, org="Incocredito", analista="@eduingt")

    
    score_legend_block = render_score_legend()
    matrix_by_domain: dict[str, dict] = {}
    for m in matrix:
        matrix_by_domain[m.get("dominio", "")] = m

    all_passive: list[dict] = []
    all_active: list[dict] = []
    prov_summaries: list[dict] = []

    for p in providers:
        domain = p.get("domain", "")
        m = matrix_by_domain.get(domain, {})
        pas, act = classify_issues(m, p)
        all_passive.extend(pas)
        all_active.extend(act)
        prov_summaries.append({
            "name": p.get("name", domain),
            "domain": domain,
            "passive_count": len(pas),
            "active_count": len(act),
            "passive_high": sum(1 for x in pas if x["severity"] in ("alta",)),
            "active_high": sum(1 for x in act if x["severity"] in ("alta",)),
            "total": len(pas) + len(act),
        })

    def severity_summary(items: list[dict]) -> dict:
        return {
            "alta": sum(1 for x in items if x["severity"] == "alta"),
            "media": sum(1 for x in items if x["severity"] == "media"),
            "baja": sum(1 for x in items if x["severity"] == "baja"),
            "info": sum(1 for x in items if x["severity"] == "info"),
        }

    pas_summary = severity_summary(all_passive)
    act_summary = severity_summary(all_active)

    total_high = pas_summary["alta"] * 3 + act_summary["alta"] * 4 + pas_summary["media"] * 1 + act_summary["media"] * 2
    score = max(0, min(100, 100 - total_high))
    grade = grade_letter(score)
    gcol = grade_color(grade)

    def render_finding_grid(items: list[dict], cat: str) -> str:
        if not items:
            return '<div style="color:var(--text-muted);font-size:15px;padding:8px 0;">Sin hallazgos</div>'
        rows = ""
        for f in items:
            sev = f["severity"]
            ev = f.get("evidence", "")
            desc = f.get("descripcion", "")
            rec = f.get("recomendacion", "")
            rec_html = ""
            if rec:
                rec_html = f'<div class="f-rec"><strong>Recomendacion:</strong> {esc(rec)}</div>'
            desc_html = ""
            if desc:
                desc_html = f'<div class="f-desc">{esc(desc)}</div>'
            rows += f"""<div class="finding">
              <div class="f-header">
                <span class="tag {cat}">{cat.upper()}</span>
                <span class="sev {sev}">{sev.upper()}</span>
                <span class="f-label">{esc(f['label'])}</span>
              </div>
              <div class="f-domain">{esc(f['domain'])}</div>
              <div class="f-detail">{esc(f['detail'])}</div>
              {desc_html}
              {rec_html}
              {ev}
            </div>"""
        return rows

    # OWASP
    owasp_html = ""
    first_m = next(iter(matrix_by_domain.values()), {})
    owasp_data = first_m.get("owasp") if matrix_by_domain else None
    if owasp_data:
        risks = owasp_data.get("risks", {})
        ocomply = owasp_data.get("overall_compliance", 0)
        ograde = owasp_data.get("overall_grade", "?")
        ocolor = grade_color(ograde)
        items = ""
        for rid in ("ASI-01", "ASI-02", "ASI-03", "ASI-04", "ASI-05", "ASI-06", "ASI-07", "ASI-08", "ASI-09", "ASI-10"):
            r = risks.get(rid, {})
            cpct = r.get("compliance_pct", 0)
            rc = grade_color(grade_letter(cpct))
            items += f"""<div class="owasp-item">
              <div class="oid">{rid}</div>
              <div class="otitle">{esc(r.get('title',''))}</div>
              <div class="owasp-bar"><div class="owasp-fill" style="width:{cpct}%;background:{rc}"></div></div>
              <div class="owasp-pct">{cpct:.0f}% compliance</div>
            </div>"""
        owasp_html = f"""<div class="sec-title">OWASP Agentic Top 10</div>
        <div class="grade-row">
          <div class="grade-letter" style="color:{ocolor}">{esc(ograde)}</div>
          <div><div class="grade-bar"><div class="grade-fill" style="width:{ocomply}%;background:{ocolor}"></div></div></div>
          <div class="grade-desc">{ocomply:.1f}% compliance general</div>
        </div>
        <div class="owasp-grid">{items}</div>"""

    # Provider cards
    prov_cards = ""
    for ps in prov_summaries:
        total = ps["total"] or 1
        pw = ps["passive_count"] / total * 100
        aw = ps["active_count"] / total * 100
        prov_cards += f"""<div class="prov-card">
          <h4>{esc(ps['name'])}</h4>
          <div class="pdom">{esc(ps['domain'])}</div>
          <div class="prov-bar">
            <div class="seg passive" style="width:{pw}%" title="{ps['passive_count']} pasivos"></div>
            <div class="seg active" style="width:{aw}%" title="{ps['active_count']} activos"></div>
          </div>
          <div class="prov-stats">
            <span style="color:var(--passive)">PASIVO: {ps['passive_count']}</span>
            <span style="color:var(--active)">ACTIVO: {ps['active_count']}</span>
            <span style="color:var(--bad)">ALTA: {ps['passive_high'] + ps['active_high']}</span>
          </div>
        </div>"""

    # Matrix table
    matrix_rows = ""
    for m in matrix:
        dom = m.get("dominio", "")
        mp = matrix_by_domain.get(dom, m)
        https_val = mp.get("https", "?")
        hsts_v = "S" if mp.get("hsts") else "N"
        csp_v = "S" if mp.get("csp") else "N"
        dnssec_v = "S" if mp.get("dnssec_ok") else "N"
        tls_v = mp.get("tls_version", "?")
        mx_c = mp.get("mx_count", 0)
        p_eol = mp.get("patching_eol", 0)
        p_end = mp.get("patching_ending", 0)
        sc_c = mp.get("supply_chain_count", 0)
        take_c = mp.get("takeover_count", 0)
        typo_c = mp.get("typosquatting_count", 0)
        csp_weak = "S" if mp.get("csp_finding_count", 0) > 0 else "N"
        cookie_ins = "S" if mp.get("cookie_insecure") else "N"
        caa_v = "S" if mp.get("caa") else "N"
        mta_v = "S" if mp.get("mta_sts") else "N"
        starttls_v = "S" if mp.get("starttls_ok") else ("N" if mp.get("starttls_count", 0) > 0 else "-")
        cve_c = mp.get("vulnerability_count", 0)
        dnsbl_c = mp.get("ip_reputation_count", 0)
        port_c = mp.get("open_port_count", 0)
        banner_c = mp.get("banner_count", 0)
        vulnscan_c = mp.get("cve_finding_count", 0)
        brute_c = mp.get("brute_sub_count", 0)
        pivot_c = mp.get("pivot_count", 0)
        matrix_rows += f"""<tr>
          <td><strong>{esc(mp.get('proveedor',''))}</strong></td>
          <td>{esc(mp.get('dominio',''))}</td>
          <td>{https_val}</td>
          <td>{hsts_v}</td>
          <td>{csp_v}</td>
          <td>{csp_weak}</td>
          <td>{cookie_ins}</td>
          <td>{dnssec_v}</td>
          <td>{tls_v}</td>
          <td class="num">{mx_c}</td>
          <td>{caa_v}</td>
          <td>{mta_v}</td>
          <td>{starttls_v}</td>
          <td class="num">{cve_c}</td>
          <td class="num">{dnsbl_c}</td>
          <td class="num">{sc_c}</td>
          <td class="num">{take_c}</td>
          <td class="num">{typo_c}</td>
          <td class="num">{p_eol}/{p_end}</td>
          <td class="num">{port_c}</td>
          <td class="num">{banner_c}</td>
          <td class="num">{vulnscan_c}</td>
          <td class="num">{brute_c}</td>
          <td class="num">{pivot_c}</td>
        </tr>"""

    matrix_table = f"""<div class="tbl-wrap">
    <table class="data">
      <thead><tr>
        <th>Proveedor</th><th>Dominio</th><th>HTTPS</th><th>HSTS</th><th>CSP</th>
        <th>CSP-W</th><th>COOK</th><th>DNSSEC</th><th>TLS</th><th>MX</th>
        <th>CAA</th><th>MTA-STS</th><th>STARTTLS</th><th>CVE</th><th>DNSBL</th>
        <th>SC</th><th>TKO</th><th>TYPO</th><th>EOL/END</th>
        <th>PORTS</th><th>BANNER</th><th>VULN-SCN</th><th>BSUB</th><th>PIVOT</th>
      </tr></thead>
      <tbody>{matrix_rows}</tbody>
    </table></div>"""

    html_out = f"""<!DOCTYPE html>
<html lang="es">
<head><meta charset="utf-8"><title>{esc(title)}</title>
<style>{CSS}</style></head>
<body>
<div class="wrap">

  <div class="header">
    <div class="shield">&#x1f6e1;</div>
    <div>
      <h1>{esc(title)}</h1>
      <div class="meta">{esc(subtitle)} | {esc(version)} | {esc(scanned_at)}</div>
    </div>
    <div class="badge-pa">
      <span class="badge-passive">PASIVO: {len(all_passive)}</span>
      <span class="badge-active">ACTIVO: {len(all_active)}</span>
    </div>
  </div>

  <div class="grade-row">
    <div class="grade-letter" style="color:{gcol}">{esc(grade)}</div>
    <div><div class="grade-bar"><div class="grade-fill" style="width:{score}%;background:{gcol}"></div></div></div>
    <div class="grade-desc">Score: {score:.1f}/100 | {len(providers)} proveedor(es) | {len(all_passive) + len(all_active)} hallazgos totales</div>
  </div>

  <div class="kpis">
    <div class="kpi"><div class="num" style="color:var(--info)">{len(providers)}</div><div class="lbl">Proveedores</div></div>
    <div class="kpi"><div class="num" style="color:var(--passive)">{len(all_passive)}</div><div class="lbl">Hallazgos Pasivos</div></div>
    <div class="kpi"><div class="num" style="color:var(--active)">{len(all_active)}</div><div class="lbl">Hallazgos Activos</div></div>
    <div class="kpi"><div class="num" style="color:var(--bad)">{pas_summary['alta'] + act_summary['alta']}</div><div class="lbl">Alta Severidad</div></div>
    <div class="kpi"><div class="num" style="color:var(--warn)">{pas_summary['media'] + act_summary['media']}</div><div class="lbl">Media Severidad</div></div>
  </div>

  <div class="pa-overview">
    <div class="pa-col passive">
      <h3><span class="icon">&#x1f50d;</span> Analisis Pasivo</h3>
      <div class="pa-count" style="color:var(--passive)">{len(all_passive)}</div>
      <div class="pa-sub">{pas_summary['alta']} alta · {pas_summary['media']} media · {pas_summary['baja']} baja · {pas_summary['info']} info</div>
      <div class="pa-desc">DNS records, SPF/DMARC/DKIM, DNSSEC, DANE, CAA, CT Logs, Typosquatting, CVE OSV, CVE Banner Grab, Credential Leaks, Social OSINT, DNSBL, URLhaus, Banner Grab, Subdomain Brute, IP Pivot</div>
    </div>
    <div class="pa-col active">
      <h3><span class="icon">&#x26a1;</span> Analisis Activo</h3>
      <div class="pa-count" style="color:var(--active)">{len(all_active)}</div>
      <div class="pa-sub">{act_summary['alta']} alta · {act_summary['media']} media · {act_summary['baja']} baja · {act_summary['info']} info</div>
      <div class="pa-desc">Puertos, TLS, HTTP Headers, CSP, Cookies, STARTTLS, Takeover, Patching, Supply Chain, Server Fingerprint, Port Scan</div>
    </div>
  </div>

  {resumen_block}

  {score_legend_block}

  <div class="sec-title">Resumen por Proveedor</div>
  <div class="prov-grid">{prov_cards}</div>

  <div class="sec-title">Matriz de Hallazgos</div>
  {matrix_table}

  <div class="sec-title" style="border-color:var(--passive);color:var(--passive);">&#x1f50d; Hallazgos Pasivos</div>
  {render_finding_grid(all_passive, "passive")}

  <div class="sec-title" style="border-color:var(--active);color:var(--active);">&#x26a1; Hallazgos Activos</div>
  {render_finding_grid(all_active, "active")}

  {owasp_html}

  <div class="footer">
    Generado: {now} | {esc(title)} v{esc(version)}
  </div>

</div>
</body>
</html>"""
    return html_out


def main() -> int:
    ap = argparse.ArgumentParser(description="Reporte ASM Pasivo/Activo")
    ap.add_argument("--asm", type=Path, default=ROOT / "asm_report.json", help="JSON de asm_scan.py")
    ap.add_argument("--out", type=Path, default=ROOT / "informe_pasivo_activo.html", help="HTML de salida")
    ap.add_argument("--title", default="INFORME ASM - PASIVO vs ACTIVO")
    ap.add_argument("--subtitle", default="Clasificacion de analisis de superficie de ataque")
    ap.add_argument("--version", default="1.0")
    args = ap.parse_args()
    asm = json.loads(args.asm.read_text(encoding="utf-8"))
    html_out = build_report(asm, args.title, args.subtitle, args.version)
    args.out.write_text(html_out, encoding="utf-8")
    print(f"[OK] {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
