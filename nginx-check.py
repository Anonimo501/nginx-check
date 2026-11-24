
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re
import socket
import ssl
import sys
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


class Colors:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


NGINX_VER_REGEX = re.compile(
    r"nginx/(\d+\.\d+\.\d+)",
    re.IGNORECASE
)

SERVER_HEADER_REGEX = re.compile(
    r"^server:\s*(.+)$",
    re.IGNORECASE | re.MULTILINE
)


# ============================================================
# FIRMAS DE CDN, WAF Y BALANCEADORES
# ============================================================

INTERMEDIARY_SIGNATURES = {
    "Cloudflare": {
        "headers": (
            "cf-ray",
            "cf-cache-status",
            "cf-mitigated",
            "cf-apo-via",
        ),
        "server": ("cloudflare",),
    },

    "AWS Application Load Balancer (ALB/ELB)": {
        "headers": (
            "x-amzn-trace-id",
            "x-amzn-requestid",
            "x-amzn-errortype",
        ),
        "server": ("awselb",),
    },

    "AWS CloudFront": {
        "headers": (
            "x-amz-cf-id",
            "x-amz-cf-pop",
        ),
        "server": ("cloudfront",),
    },

    "Akamai": {
        "headers": (
            "akamai-",
            "x-akamai-",
            "x-check-cacheable",
        ),
        "server": (
            "akamaighost",
            "akamai",
        ),
    },

    "Fastly": {
        "headers": (
            "x-served-by",
            "x-cache-hits",
            "fastly-debug-",
        ),
        "server": (
            "varnish",
            "fastly",
        ),
    },

    "Imperva / Incapsula": {
        "headers": (
            "x-iinfo",
            "x-cdn",
            "incap_ses",
            "visid_incap",
        ),
        "server": (
            "imperva",
            "incapsula",
        ),
    },

    "F5 BIG-IP": {
        "headers": (
            "x-wa-info",
            "x-cnection",
            "x-f5-",
        ),
        "server": ("big-ip",),
    },

    "Sucuri": {
        "headers": (
            "x-sucuri-id",
            "x-sucuri-cache",
        ),
        "server": ("sucuri",),
    },

    "Azure Front Door": {
        "headers": (
            "x-azure-ref",
            "x-fd-int-roxy-purgeid",
        ),
        "server": ("azurefrontdoor",),
    },

    "Google Cloud Load Balancing": {
        "headers": (
            "x-cloud-trace-context",
            "x-goog-",
        ),
        "server": (),
    },

    "Vercel": {
        "headers": (
            "x-vercel-id",
            "x-vercel-cache",
        ),
        "server": ("vercel",),
    },

    "Netlify": {
        "headers": (
            "x-nf-request-id",
        ),
        "server": ("netlify",),
    },

    "Bunny CDN": {
        "headers": (
            "cdn-pullzone",
            "cdn-requestcountrycode",
            "cdn-cachedat",
        ),
        "server": ("bunnycdn",),
    },
}


# ============================================================
# PARSEO DE RESPUESTAS HTTP
# ============================================================

def parse_response_headers(raw_response: str) -> Dict[str, str]:
    """
    Extrae las cabeceras HTTP de la primera respuesta.
    """

    result: Dict[str, str] = {}

    header_block = raw_response.split("\r\n\r\n", 1)[0]
    lines = header_block.splitlines()

    for line in lines[1:]:

        if ":" not in line:
            continue

        key, value = line.split(":", 1)

        key = key.strip().lower()
        value = value.strip()

        if not key:
            continue

        if key in result:
            result[key] += ", " + value
        else:
            result[key] = value

    return result


# ============================================================
# IDENTIFICACIÓN DE CDN / WAF / BALANCEADORES
# ============================================================

def identify_intermediaries(
    headers_seen: Dict[str, str]
) -> List[Tuple[str, List[str]]]:

    findings: List[Tuple[str, List[str]]] = []

    server_value = headers_seen.get(
        "server", ""
    ).lower()

    for provider, signature in INTERMEDIARY_SIGNATURES.items():

        evidence: List[str] = []

        for header_name, header_value in headers_seen.items():

            if any(
                header_name.startswith(prefix)
                for prefix in signature["headers"]
            ):

                evidence.append(
                    f"{header_name}: {header_value}"
                )

        if any(
            marker in server_value
            for marker in signature["server"]
        ):

            evidence.append(
                f"server: {headers_seen.get('server', '')}"
            )

        if evidence:

            findings.append(
                (provider, sorted(set(evidence)))
            )

    # Firmas genéricas de intermediarios.

    generic_headers = (
        "via",
        "x-cache",
        "x-cache-hits",
        "x-served-by",
        "x-proxy-cache",
        "x-upstream",
        "x-backend-server",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
    )

    generic = []

    for name in generic_headers:

        if name in headers_seen:

            generic.append(
                f"{name}: {headers_seen[name]}"
            )

    if generic:

        findings.append(
            (
                "Proxy / caché / balanceador intermedio",
                generic
            )
        )

    return findings


# ============================================================
# PARSEO DEL OBJETIVO
# ============================================================

def parse_target(
    target_input: str
) -> Tuple[str, int, str, str]:

    """
    Acepta dominios, IP, URLs HTTP/HTTPS y puertos personalizados.
    """

    if "://" not in target_input:

        target_input = "https://" + target_input

    parsed = urlparse(target_input)

    scheme = parsed.scheme.lower()

    if scheme not in ("http", "https"):

        raise ValueError(
            "El protocolo debe ser HTTP o HTTPS."
        )

    host = parsed.hostname

    if not host:

        raise ValueError(
            "No se pudo identificar el dominio o IP."
        )

    if parsed.port:

        port = parsed.port

    elif scheme == "https":

        port = 443

    else:

        port = 80

    base_path = parsed.path or "/"

    if parsed.query:

        base_path += "?" + parsed.query

    return host, port, base_path, scheme


# ============================================================
# CONSTRUCCIÓN DE PETICIONES
# ============================================================

def build_probes(
    base_path: str
) -> List[Tuple[str, str]]:

    """
    Genera peticiones pasivas para identificar NGINX.
    """

    clean_base = base_path.split("?")[0].rstrip("/") or "/"

    probes: List[Tuple[str, str]] = []

    if clean_base != "/":

        probes.extend([
            ("OPTIONS", clean_base),
            ("HEAD", clean_base),
            ("GET", clean_base),
            (
                "GET",
                f"{clean_base}/nonexistent_api_probe_9988"
            ),
        ])

    probes.extend([
        ("GET", "/"),
        ("GET", "/nginx_status"),
        ("GET", "/stub_status"),
        ("GET", "/nonexistent_root_probe_9988"),
        ("TRACE", "/"),
    ])

    seen = set()

    unique_probes = []

    for item in probes:

        if item not in seen:

            seen.add(item)
            unique_probes.append(item)

    return unique_probes


# ============================================================
# ENVÍO DE PETICIONES HTTP / HTTPS
# ============================================================

def send_http1_request(
    host: str,
    port: int,
    method: str,
    path: str,
    custom_headers: Dict[str, str],
    insecure: bool = False,
    scheme: str = "https",
    timeout: int = 5,
) -> str:

    """
    Envía una petición HTTP/1.1.
    Admite conexiones HTTP y HTTPS.
    """

    headers = {
        "Host": host if port in (80, 443) else f"{host}:{port}",
        "User-Agent": "Mozilla/5.0 (Security-Audit-Check)",
        "Accept": "application/json, text/html, */*",
        "Connection": "close",
    }

    for key, value in custom_headers.items():

        if "\r" in key or "\n" in key:
            raise ValueError("Nombre de cabecera inválido.")

        if "\r" in value or "\n" in value:
            raise ValueError("Valor de cabecera inválido.")

        headers[key] = value

    header_lines = "".join(
        f"{key}: {value}\r\n"
        for key, value in headers.items()
    )

    request = (
        f"{method} {path} HTTP/1.1\r\n"
        f"{header_lines}\r\n"
    ).encode("utf-8")

    with socket.create_connection(
        (host, port),
        timeout=timeout
    ) as sock:

        connection = sock

        if scheme == "https":

            ctx = ssl.create_default_context()

            if insecure:

                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            connection = ctx.wrap_socket(
                sock,
                server_hostname=host
            )

        with connection:

            connection.settimeout(timeout)
            connection.sendall(request)

            chunks = []
            total_size = 0

            while True:

                try:

                    data = connection.recv(4096)

                except socket.timeout:

                    break

                if not data:
                    break

                chunks.append(data)

                total_size += len(data)

                if total_size >= 32768:
                    break

            return b"".join(chunks).decode(
                "utf-8",
                errors="ignore"
            )


# ============================================================
# NEGOCIACIÓN HTTP/2 ALPN
# ============================================================

def check_http2(
    host: str,
    port: int,
    insecure: bool = False,
    timeout: int = 5,
) -> bool:

    """
    Comprueba si el servidor negocia HTTP/2 mediante ALPN.
    """

    ctx = ssl.create_default_context()

    if insecure:

        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    ctx.set_alpn_protocols([
        "h2",
        "http/1.1"
    ])

    try:

        with socket.create_connection(
            (host, port),
            timeout=timeout
        ) as sock:

            with ctx.wrap_socket(
                sock,
                server_hostname=host
            ) as ssock:

                alpn = ssock.selected_alpn_protocol()

                color = (
                    Colors.YELLOW
                    if alpn == "h2"
                    else Colors.GREEN
                )

                print(
                    f"{Colors.CYAN}[*]{Colors.RESET} "
                    f"Protocolo ALPN negociado: "
                    f"{color}{alpn or 'No negociado'}"
                    f"{Colors.RESET}"
                )

                return alpn == "h2"

    except Exception as error:

        print(
            f"{Colors.RED}[ERROR] Error negociando ALPN: "
            f"{error}{Colors.RESET}"
        )

        return False


# ============================================================
# EVALUACIÓN DE VERSIÓN
# ============================================================

def evaluate_version_status(
    version_str: str,
    h2_enabled: bool
) -> str:

    """
    Evaluación heurística del rango de versiones configurado
    para CVE-2026-123007 en el script original.

    La versión anunciada no demuestra por sí sola que el sistema
    sea vulnerable: pueden existir backports del fabricante.
    """

    ver_tuple = tuple(
        int(x)
        for x in version_str.split(".")
    )

    if not h2_enabled:

        return (
            f"{Colors.GREEN}[SEGURO] "
            f"Versión nginx/{version_str} detectada, "
            f"pero HTTP/2 (h2) no está activo en TLS."
            f"{Colors.RESET}"
        )

    if (
        ver_tuple == (1, 30, 7)
        or ver_tuple >= (1, 31, 9)
    ):

        return (
            f"{Colors.GREEN}[SEGURO] "
            f"Versión nginx/{version_str} "
            f"fuera del rango vulnerable configurado."
            f"{Colors.RESET}"
        )

    if (1, 9, 5) <= ver_tuple <= (1, 31, 8):

        return (
            f"{Colors.RED}{Colors.BOLD}"
            f"[POTENCIALMENTE VULNERABLE]"
            f"{Colors.RESET}{Colors.RED} "
            f"Versión nginx/{version_str} en el rango "
            f"afectado configurado con HTTP/2 activo. "
            f"Verifica posibles backports."
            f"{Colors.RESET}"
        )

    return (
        f"{Colors.GREEN}[INFO] "
        f"Versión nginx/{version_str} fuera del rango "
        f"configurado."
        f"{Colors.RESET}"
    )


# ============================================================
# ANÁLISIS PRINCIPAL
# ============================================================

def check_target(
    target: str,
    custom_headers: Dict[str, str],
    insecure: bool = False,
    timeout: int = 5,
):

    try:

        host, port, base_path, scheme = parse_target(target)

    except ValueError as error:

        print(
            f"{Colors.RED}[ERROR] {error}{Colors.RESET}"
        )

        return

    print(
        f"\n{Colors.CYAN}{Colors.BOLD}"
        f"=== Analizando {host}:{port} ==="
        f"{Colors.RESET}"
    )

    print(
        f"{Colors.DIM}"
        f"Protocolo: {scheme.upper()} | "
        f"Endpoint base: {base_path}"
        f"{Colors.RESET}"
    )

    # --------------------------------------------------------
    # 1. HTTP/2
    # --------------------------------------------------------

    h2_enabled = False

    if scheme == "https":

        h2_enabled = check_http2(
            host,
            port,
            insecure,
            timeout
        )

    else:

        print(
            f"{Colors.YELLOW}"
            f"[INFO] HTTP/2 mediante ALPN requiere TLS."
            f"{Colors.RESET}"
        )

    # --------------------------------------------------------
    # 2. IDENTIFICACIÓN DEL SERVIDOR
    # --------------------------------------------------------

    detected_version: Optional[str] = None

    found_in = ""

    is_nginx = False

    other_servers: List[str] = []

    observed_headers: Dict[str, str] = {}

    successful_requests = 0

    failed_requests = 0

    for method, path in build_probes(base_path):

        try:

            raw_resp = send_http1_request(
                host,
                port,
                method,
                path,
                custom_headers,
                insecure,
                scheme,
                timeout,
            )

            if not raw_resp:

                failed_requests += 1
                continue

            successful_requests += 1

            lower_resp = raw_resp.lower()

            # Cabeceras observadas.

            response_headers = parse_response_headers(
                raw_resp
            )

            for header_name, header_value in response_headers.items():

                if header_name in observed_headers:

                    existing = observed_headers[header_name]

                    if header_value not in existing:

                        observed_headers[header_name] += (
                            ", " + header_value
                        )

                else:

                    observed_headers[header_name] = header_value

            # Identificación por cabecera Server.

            srv_match = SERVER_HEADER_REGEX.search(
                raw_resp
            )

            if srv_match:

                srv_val = srv_match.group(1).strip()

                if "nginx" in srv_val.lower():

                    is_nginx = True

                elif srv_val not in other_servers:

                    other_servers.append(srv_val)

            # Huellas habituales de NGINX.

            if (
                "<center>nginx" in lower_resp
                or "openresty" in lower_resp
            ):

                is_nginx = True

            # Identificación de versión.

            ver_match = NGINX_VER_REGEX.search(
                raw_resp
            )

            if ver_match:

                is_nginx = True

                detected_version = ver_match.group(1)

                found_in = f"{method} {path}"

                # No se interrumpe el análisis:
                # se siguen recopilando cabeceras de intermediarios.

        except (
            socket.timeout,
            socket.gaierror,
            ConnectionError,
            ssl.SSLError,
            OSError,
            ValueError,
        ) as error:

            failed_requests += 1

            print(
                f"{Colors.DIM}"
                f"[!] {method} {path}: {error}"
                f"{Colors.RESET}"
            )

            continue

    # --------------------------------------------------------
    # 3. RESULTADO NGINX
    # --------------------------------------------------------

    print(
        f"\n{Colors.CYAN}{Colors.BOLD}"
        f"=== Identificación del servidor ==="
        f"{Colors.RESET}"
    )

    if detected_version:

        print(
            f"{Colors.GREEN}[+] Tecnología identificada: "
            f"{Colors.RESET}"
            f"{Colors.BOLD}NGINX "
            f"(versión {detected_version})"
            f"{Colors.RESET}"
        )

        print(
            f"{Colors.DIM}"
            f"[Encontrada en {found_in}]"
            f"{Colors.RESET}"
        )

        print(
            evaluate_version_status(
                detected_version,
                h2_enabled
            )
        )

    elif is_nginx:

        print(
            f"{Colors.YELLOW}[!] Tecnología identificada: "
            f"{Colors.RESET}"
            f"{Colors.BOLD}NGINX"
            f"{Colors.RESET}"
        )

        print(
            f"{Colors.YELLOW}"
            f"No fue posible determinar la versión. "
            f"Puede estar ocultada mediante server_tokens off."
            f"{Colors.RESET}"
        )

        if h2_enabled:

            print(
                f"{Colors.YELLOW}"
                f"[REVISAR] HTTP/2 está activo. "
                f"Verifica la versión internamente."
                f"{Colors.RESET}"
            )

        else:

            print(
                f"{Colors.GREEN}"
                f"[INFO] HTTP/2 no está negociado vía TLS."
                f"{Colors.RESET}"
            )

    else:

        detected_banner = (
            f" (Cabecera Server: {', '.join(other_servers)})"
            if other_servers
            else ""
        )

        print(
            f"{Colors.CYAN}[-] Tecnología identificada: "
            f"{Colors.RESET}"
            f"El servidor no presenta huellas concluyentes "
            f"de NGINX{detected_banner}."
        )

    # --------------------------------------------------------
    # 4. CDN / WAF / BALANCEADORES
    # --------------------------------------------------------

    print(
        f"\n{Colors.CYAN}{Colors.BOLD}"
        f"=== CDN / WAF / Balanceadores detectados ==="
        f"{Colors.RESET}"
    )

    intermediary_findings = identify_intermediaries(
        observed_headers
    )

    if intermediary_findings:

        for provider, evidence in intermediary_findings:

            print(
                f"\n{Colors.YELLOW}[!] Posible intermediario: "
                f"{Colors.BOLD}{provider}"
                f"{Colors.RESET}"
            )

            for item in evidence:

                print(
                    f"    {Colors.DIM}- {item}"
                    f"{Colors.RESET}"
                )

        if not is_nginx:

            print(
                f"\n{Colors.YELLOW}"
                f"[?] POSIBLE ORIGEN OCULTO:"
                f"{Colors.RESET} "
                f"Se detectaron intermediarios, pero no se "
                f"pudo confirmar NGINX en las respuestas públicas."
            )

            print(
                f"{Colors.DIM}"
                f"El servidor de origen podría utilizar NGINX "
                f"u otra tecnología."
                f"{Colors.RESET}"
            )

        else:

            print(
                f"\n{Colors.GREEN}"
                f"[+] NGINX también dejó huellas en las respuestas."
                f"{Colors.RESET}"
            )

            print(
                f"{Colors.DIM}"
                f"El intermediario y NGINX pueden formar parte "
                f"de la misma cadena de infraestructura."
                f"{Colors.RESET}"
            )

        print(
            f"\n{Colors.DIM}"
            f"[INFO] La detección es pasiva y se basa en "
            f"cabeceras HTTP. Un intermediario puede eliminar, "
            f"modificar o imitar estas cabeceras."
            f"{Colors.RESET}"
        )

    else:

        print(
            f"{Colors.GREEN}"
            f"[-] No se identificaron firmas conocidas de "
            f"CDN/WAF o balanceadores."
            f"{Colors.RESET}"
        )

        print(
            f"{Colors.DIM}"
            f"[INFO] Esto no descarta la presencia de un "
            f"intermediario que oculte sus cabeceras."
            f"{Colors.RESET}"
        )

    # --------------------------------------------------------
    # 5. RESUMEN
    # --------------------------------------------------------

    print(
        f"\n{Colors.CYAN}{Colors.BOLD}"
        f"=== Resumen del análisis ==="
        f"{Colors.RESET}"
    )

    print(
        f"Solicitudes completadas: "
        f"{Colors.GREEN}{successful_requests}"
        f"{Colors.RESET}"
    )

    print(
        f"Solicitudes fallidas: "
        f"{Colors.YELLOW}{failed_requests}"
        f"{Colors.RESET}"
    )

    print(
        f"NGINX identificado: "
        f"{Colors.GREEN if is_nginx else Colors.YELLOW}"
        f"{'Sí' if is_nginx else 'No confirmado'}"
        f"{Colors.RESET}"
    )

    print(
        f"HTTP/2 activo: "
        f"{Colors.GREEN if h2_enabled else Colors.YELLOW}"
        f"{'Sí' if h2_enabled else 'No'}"
        f"{Colors.RESET}"
    )

    print(
        f"Intermediarios identificados: "
        f"{Colors.GREEN if intermediary_findings else Colors.YELLOW}"
        f"{len(intermediary_findings)}"
        f"{Colors.RESET}"
    )


# ============================================================
# CABECERAS PERSONALIZADAS
# ============================================================

def parse_headers(
    header_list: Optional[List[str]]
) -> Dict[str, str]:

    headers: Dict[str, str] = {}

    if not header_list:

        return headers

    for item in header_list:

        if ":" not in item:

            print(
                f"{Colors.YELLOW}"
                f"[!] Cabecera ignorada por formato inválido: "
                f"{item}"
                f"{Colors.RESET}"
            )

            continue

        key, value = item.split(":", 1)

        key = key.strip()
        value = value.strip()

        if not key or "\r" in key or "\n" in key:

            print(
                f"{Colors.YELLOW}"
                f"[!] Nombre de cabecera inválido."
                f"{Colors.RESET}"
            )

            continue

        if "\r" in value or "\n" in value:

            print(
                f"{Colors.YELLOW}"
                f"[!] Valor de cabecera inválido."
                f"{Colors.RESET}"
            )

            continue

        headers[key] = value

    return headers


# ============================================================
# ARGUMENTOS CLI
# ============================================================

def main():

    examples_text = f"""
{Colors.BOLD}Ejemplos de ejecución:{Colors.RESET}

  Dominio:
    python3 script.py tudominio.com

  URL completa:
    python3 script.py https://tudominio.com/api

  HTTP:
    python3 script.py http://tudominio.com

  Puerto personalizado:
    python3 script.py https://tudominio.com:8443

  Cabecera de autenticación:
    python3 script.py https://tudominio.com \\
      -H "Authorization: Bearer tu_token"

  Varias cabeceras:
    python3 script.py https://tudominio.com \\
      -H "Authorization: Bearer token" \\
      -H "X-API-Key: clave"

  Ignorar certificado TLS:
    python3 script.py https://10.0.0.1 -k

  Timeout personalizado:
    python3 script.py https://tudominio.com --timeout 10
"""

    parser = argparse.ArgumentParser(
        description=(
            f"{Colors.BOLD}"
            "Checker pasivo remoto de NGINX, HTTP/2, "
            "CDN, WAF y balanceadores."
            f"{Colors.RESET}"
        ),
        epilog=examples_text,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "target",
        nargs="?",
        help=(
            "Dominio, IP o URL completa "
            "(ej. https://tudominio.com)"
        ),
    )

    parser.add_argument(
        "-H",
        "--header",
        action="append",
        help=(
            'Cabecera HTTP personalizada '
            '(ej. -H "Authorization: Bearer token")'
        ),
    )

    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help=(
            "Ignorar errores de validación del certificado TLS."
        ),
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Timeout de conexión en segundos (por defecto: 5).",
    )

    args = parser.parse_args()

    if not args.target:

        parser.print_help()

        return 0

    if args.timeout < 1:

        parser.error(
            "--timeout debe ser un número mayor que cero."
        )

    extra_headers = parse_headers(args.header)

    try:

        check_target(
            args.target,
            extra_headers,
            args.insecure,
            args.timeout,
        )

    except KeyboardInterrupt:

        print(
            f"\n{Colors.YELLOW}"
            f"[!] Análisis interrumpido por el usuario."
            f"{Colors.RESET}"
        )

        return 130

    except Exception as error:

        print(
            f"\n{Colors.RED}"
            f"[ERROR] Error inesperado: {error}"
            f"{Colors.RESET}"
        )

        return 1

    return 0


if __name__ == "__main__":

    sys.exit(main())
