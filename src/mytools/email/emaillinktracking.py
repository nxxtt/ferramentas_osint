#!/usr/bin/env python3
"""Modulo de testes de Email Link Tracking Bypass.

Testa se o servidor SMTP injeta mecanismos de tracking em emails de saida:
  - Tracking pixels (1x1, CSS background-image)
  - Reescrita de links via servidor de tracking
  - Injecao de parametros utm_* em URLs
  - Redirecionamentos antes do destino final
  - Headers de read receipt injetados
  - Message-ID com identificador rastreavel
  - Elementos hidden para tracking
  - URL shortener detection
  - Web beacon / CSS tracking / font fingerprinting

Fluxo:
  1. Conecta ao SMTP (porta 25/587/465) com STARTTLS
  2. Envia email HTML com payloads de tracking embutidos
  3. Analisa a resposta SMTP (se servidor adicionou headers, reescreveu links)
  4. Classifica cada tecnica: detected, not_detected, blocked, error
  5. Retorna resultado consolidado com severidade
"""
import argparse
import contextlib
import logging
import re
import smtplib
from collections.abc import Callable
from dataclasses import asdict, dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from mytools.core.utils import (
    Cyber,
    add_base_args,
    color,
    create_banner,
    init_scanner,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.emaillinktracking")

DEFAULT_PORTS = [25, 587, 465]

_CATEGORY_MAP: dict[str, list[str]] = {
    "pixel": ["pixel_1x1", "pixel_css", "web_beacon"],
    "link": ["link_rewrite", "utm_params", "redirect_chain", "url_shortener"],
    "header": ["read_receipt", "message_id_tracking"],
    "css": ["hidden_element", "css_tracking", "font_fingerprint"],
}

_TRACKING_PIXEL_1X1 = (
    '<img src="https://tracking.example.com/pixel.gif?uid=test123&ts=1234567890" '
    'width="1" height="1" style="display:none" alt="">'
)

_TRACKING_PIXEL_CSS = (
    '<div style="background-image:url(\'https://track.example.com/bg.gif?rid=abc\')'
    ';width:1px;height:1px;position:absolute;top:-9999px"></div>'
)

_LINK_REWRITE = '<a href="https://legitimate.com/page">Click here</a>'

_UTM_PARAMS = (
    '<a href="https://example.com/product?utm_source=email&utm_medium=campaign'
    '&utm_content=test&utm_term=keyword">Product link</a>'
)

_REDIRECT_CHAIN = (
    '<a href="https://redirect.example.com/r?url=https://final.com">Redirect link</a>'
)

_URL_SHORTENER = '<a href="https://bit.ly/abc123">Short link</a>'

_HIDDEN_ELEMENT = (
    '<div style="display:none;font-size:0;line-height:0" '
    'data-track-id="open-test-456">invisible content</div>'
)

_CSS_TRACKING = (
    '<style>.tracker{background:url("https://css.example.com/t.gif?cid=xyz") '
    'no-repeat;width:1px;height:1px}</style>'
    '<div class="tracker"></div>'
)

_FONT_FINGERPRINT = (
    '<style>@font-face{font-family:"Tracker";'
    'src:url("https://font.example.com/f.woff?id=789")}</style>'
)

_WEB_BEACON = (
    '<img src="https://webbeacon.example.com/beacon?email=test@test.com&opened=1" '
    'border="0" width="0" height="0" alt="">'
)

_READ_RECEIPT_HEADER = "Disposition-Notification-To"

_MESSAGE_ID_PATTERN = re.compile(r"<[^>]*tracking[^>]*@")


def _build_test_html() -> str:
    """Constrói o HTML de teste com todos os payloads de tracking."""
    return f"""<html>
<body>
<h1>Link Tracking Test</h1>
<p>This is a test email for tracking detection.</p>

{_TRACKING_PIXEL_1X1}
{_TRACKING_PIXEL_CSS}
{_WEB_BEACON}

<p>Regular link: {_LINK_REWRITE}</p>
<p>UTM link: {_UTM_PARAMS}</p>
<p>Redirect link: {_REDIRECT_CHAIN}</p>
<p>Short link: {_URL_SHORTENER}</p>

{_HIDDEN_ELEMENT}
{_CSS_TRACKING}
{_FONT_FINGERPRINT}

<p>End of test.</p>
</body>
</html>"""


def _build_test_email(
    from_addr: str,
    to_addr: str,
) -> MIMEMultipart:
    """Constrói email HTML de teste com payloads de tracking."""
    msg = MIMEMultipart("alternative")
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = "Link Tracking Bypass Test"
    msg["X-Tracking-Test"] = "mytools-emaillinktracking"

    html = _build_test_html()
    part = MIMEText(html, "html", "utf-8")
    msg.attach(part)

    return msg


@dataclass(frozen=True, slots=True)
class TrackingAttempt:
    """Resultado de uma tentativa individual de deteccao de tracking."""
    technique: str
    status: str  # detected, not_detected, blocked, error
    details: str
    error: str


@dataclass(frozen=True, slots=True)
class TrackingResult:
    """Resultado completo da verificacao de link tracking."""
    target: str
    port: int
    tls: bool
    banner: str
    attempts: list[TrackingAttempt]
    detected_techniques: list[str]
    clean_techniques: list[str]
    issues: list[str]
    overall_status: str  # tracking_detected, clean, warning


def _connect_smtp(target: str, port: int, timeout: float) -> tuple[smtplib.SMTP, bool]:
    """Conecta ao servidor SMTP e retorna (conexao, tls_ativo)."""
    try:
        if port == 465:
            server = smtplib.SMTP_SSL(target, port, timeout=timeout)
            return server, True
        server = smtplib.SMTP(target, port, timeout=timeout)
    except smtplib.SMTPConnectError as exc:
        raise ConnectionError(f"Falha ao conectar: {exc}") from exc
    except OSError as exc:
        raise ConnectionError(f"Erro de conexao: {exc}") from exc
    tls_active = False
    try:
        banner_text = server.ehlo()
        if b"STARTTLS" in (banner_text[1] if isinstance(banner_text, tuple) else b""):
            server.starttls()
            server.ehlo()
            tls_active = True
    except (smtplib.SMTPException, OSError):
        pass
    return server, tls_active


def _get_banner(server: smtplib.SMTP) -> str:
    """Retorna o banner EHLO do servidor."""
    try:
        _code, banner = server.ehlo()
        return banner.decode("utf-8", errors="replace") if isinstance(banner, bytes) else str(banner)
    except smtplib.SMTPException:
        return ""


def _detect_pixel_1x1(server_response: str, email_body: str) -> tuple[str, str]:
    """Detecta se pixel 1x1 foi injetado pelo servidor."""
    combined = server_response + email_body
    if "1x1" in combined or "1X1" in combined:
        return "detected", "Pixel 1x1 detectado na resposta"
    if 'width="1" height="1"' in combined or "width='1' height='1'" in combined:
        return "detected", "Pixel 1x1 com dimensoes 1x1 detectado"
    if "pixel.gif" in combined or "pixel.png" in combined:
        return "detected", "Pixel tracking URL detectada"
    return "not_detected", "Nenhum pixel 1x1 injetado"


def _detect_pixel_css(server_response: str, email_body: str) -> tuple[str, str]:
    """Detecta tracking via CSS background-image."""
    combined = server_response + email_body
    if ("background-image:url" in combined or "background:url" in combined) and ("track" in combined or "pixel" in combined or "beacon" in combined):
        return "detected", "CSS background-image tracking detectado"
    return "not_detected", "Nenhum CSS tracking injetado"


def _detect_web_beacon(server_response: str, email_body: str) -> tuple[str, str]:
    """Detecta web beacon."""
    combined = server_response + email_body
    if "webbeacon" in combined or "web-beacon" in combined:
        return "detected", "Web beacon detectado"
    if "beacon" in combined and ("width=\"0\"" in combined or "height=\"0\"" in combined):
        return "detected", "Beacon invisivel detectado"
    return "not_detected", "Nenhum web beacon injetado"


def _detect_link_rewrite(original: str, server_response: str, email_body: str) -> tuple[str, str]:
    """Detecta se links foram reescritos pelo servidor."""
    combined = server_response + email_body
    if original in combined:
        return "not_detected", "Link original preservado"
    if "redirect" in combined or "tracking" in combined or "click" in combined:
        return "detected", "Link possivelmente reescrito pelo servidor"
    return "not_detected", "Nenhuma reescrita de link detectada"


def _detect_utm_params(email_body: str) -> tuple[str, str]:
    """Detecta se parametros utm_* foram injetados."""
    utm_count = email_body.count("utm_")
    if utm_count > 0:
        return "detected", f"{utm_count} parametros utm_* encontrados"
    return "not_detected", "Nenhum parametro utm_* injetado"


def _detect_redirect_chain(email_body: str) -> tuple[str, str]:
    """Detecta cadeia de redirecionamentos."""
    if "redirect" in email_body.lower():
        return "detected", "URL de redirect detectada no body"
    return "not_detected", "Nenhum redirect chain detectado"


def _detect_url_shortener(email_body: str) -> tuple[str, str]:
    """Detecta uso de URL shortener."""
    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "buff.ly", "ow.ly"]
    for shortener in shorteners:
        if shortener in email_body:
            return "detected", f"URL shortener detectado: {shortener}"
    return "not_detected", "Nenhum URL shortener detectado"


def _detect_read_receipt(server_response: str) -> tuple[str, str]:
    """Detecta injecao de read receipt header."""
    if _READ_RECEIPT_HEADER.lower() in server_response.lower():
        return "detected", "Header Disposition-Notification-To injetado"
    return "not_detected", "Nenhum read receipt header injetado"


def _detect_message_id_tracking(server_response: str) -> tuple[str, str]:
    """Detecta Message-ID com identificador rastreavel."""
    match = _MESSAGE_ID_PATTERN.search(server_response)
    if match:
        return "detected", f"Message-ID com tracking detectado: {match.group()}"
    return "not_detected", "Message-ID sem tracking identificavel"


def _detect_hidden_element(email_body: str) -> tuple[str, str]:
    """Detecta elementos hidden para tracking."""
    if ("display:none" in email_body or "display: none" in email_body) and "track" in email_body.lower():
        return "detected", "Elemento hidden com tracking detectado"
    if "font-size:0" in email_body or "line-height:0" in email_body:
        return "detected", "Elemento hidden via font-size/line-height zero"
    return "not_detected", "Nenhum elemento hidden de tracking detectado"


def _detect_css_tracking(email_body: str) -> tuple[str, str]:
    """Detecta CSS tracking."""
    if ("background:url" in email_body or "background-image:url" in email_body) and ("track" in email_body or "pixel" in email_body):
        return "detected", "CSS tracking via background-url detectado"
    return "not_detected", "Nenhum CSS tracking detectado"


def _detect_font_fingerprint(email_body: str) -> tuple[str, str]:
    """Detecta font fingerprinting."""
    if "@font-face" in email_body and ("track" in email_body or "fingerprint" in email_body):
        return "detected", "Font fingerprinting detectado"
    return "not_detected", "Nenhum font fingerprinting detectado"


_DETECTOR_MAP: dict[str, tuple[str, str, Callable[..., tuple[str, str]]]] = {
    "pixel_1x1": ("pixel_1x1", "Pixel 1x1 tracking", _detect_pixel_1x1),
    "pixel_css": ("pixel_css", "CSS background-image tracking", _detect_pixel_css),
    "web_beacon": ("web_beacon", "Web beacon tracking", _detect_web_beacon),
    "link_rewrite": ("link_rewrite", "Link rewrite tracking", _detect_link_rewrite),
    "utm_params": ("utm_params", "UTM parameter injection", _detect_utm_params),
    "redirect_chain": ("redirect_chain", "Redirect chain tracking", _detect_redirect_chain),
    "url_shortener": ("url_shortener", "URL shortener detection", _detect_url_shortener),
    "read_receipt": ("read_receipt", "Read receipt header injection", _detect_read_receipt),
    "message_id_tracking": ("message_id_tracking", "Message-ID tracking", _detect_message_id_tracking),
    "hidden_element": ("hidden_element", "Hidden element tracking", _detect_hidden_element),
    "css_tracking": ("css_tracking", "CSS tracking", _detect_css_tracking),
    "font_fingerprint": ("font_fingerprint", "Font fingerprinting", _detect_font_fingerprint),
}


def scan_link_tracking(
    target: str,
    port: int = 587,
    from_addr: str = "test@example.com",
    to_addr: str = "test@example.com",
    timeout: float = 10.0,
    category: str | None = None,
) -> TrackingResult:
    """Executa a verificacao de Email Link Tracking."""
    attempts: list[TrackingAttempt] = []
    issues: list[str] = []
    banner = ""
    tls_active = False

    try:
        server, tls_active = _connect_smtp(target, port, timeout)
    except ConnectionError as exc:
        issues.append(f"Falha de conexao: {exc}")
        return TrackingResult(
            target=target, port=port, tls=False, banner="",
            attempts=[], detected_techniques=[], clean_techniques=[],
            issues=issues, overall_status="error",
        )

    try:
        banner = _get_banner(server)
        msg = _build_test_email(from_addr, to_addr)
        email_body = msg.as_string()

        server_response = ""
        try:
            server.ehlo()
            server.mail(from_addr)
            server.rcpt(to_addr)
            _code, response = server.data(email_body)
            server_response = response.decode("utf-8", errors="replace") if isinstance(response, bytes) else str(response)
            server.rset()
        except smtplib.SMTPResponseException as exc:
            server_response = f"{exc.smtp_code} {exc.smtp_error}"
        except smtplib.SMTPException as exc:
            server_response = str(exc)

        if category:
            selected = _CATEGORY_MAP.get(category, [])
            if not selected:
                issues.append(f"Categoria desconhecida: {category}")
                selected = list(_DETECTOR_MAP.keys())
        else:
            selected = list(_DETECTOR_MAP.keys())

        for name in selected:
            if name not in _DETECTOR_MAP:
                continue

            _, label, detector = _DETECTOR_MAP[name]

            try:
                if name in ("pixel_1x1", "pixel_css", "web_beacon"):
                    status, details = detector(server_response, email_body)
                elif name == "link_rewrite":
                    status, details = detector(_LINK_REWRITE, server_response, email_body)
                elif name in ("utm_params", "redirect_chain", "url_shortener",
                              "hidden_element", "css_tracking", "font_fingerprint"):
                    status, details = detector(email_body)
                elif name in ("read_receipt", "message_id_tracking"):
                    status, details = detector(server_response)
                else:
                    status, details = "not_detected", "Detector nao implementado"

                if status == "detected":
                    issues.append(f"Tracking detectado: {label}")

                attempts.append(TrackingAttempt(
                    technique=name,
                    status=status,
                    details=details[:200],
                    error="",
                ))
            except Exception as exc:
                attempts.append(TrackingAttempt(
                    technique=name,
                    status="error",
                    details="",
                    error=str(exc)[:200],
                ))

    finally:
        with contextlib.suppress(smtplib.SMTPException):
            server.quit()

    detected = [a.technique for a in attempts if a.status == "detected"]
    clean = [a.technique for a in attempts if a.status == "not_detected"]

    if detected:
        overall = "tracking_detected"
    elif clean:
        overall = "clean"
    else:
        overall = "warning"

    if overall == "tracking_detected":
        issues.append(f"{len(detected)}/{len(attempts)} tecnicas de tracking detectadas")
    elif overall == "clean":
        issues.append("Nenhum mecanismo de tracking injetado pelo servidor")
    else:
        issues.append("Resultado inconclusivo")

    return TrackingResult(
        target=target,
        port=port,
        tls=tls_active,
        banner=banner[:200],
        attempts=attempts,
        detected_techniques=detected,
        clean_techniques=clean,
        issues=issues,
        overall_status=overall,
    )


def print_results(result: TrackingResult) -> None:
    """Exibe o relatorio de Email Link Tracking."""
    print(color("\n[+] Email Link Tracking — Relatorio:", Cyber.GREEN, Cyber.BOLD))
    print(f"  Target: {color(result.target, Cyber.WHITE, Cyber.BOLD)}:{result.port}")
    print(f"  TLS: {color('Sim' if result.tls else 'Nao', Cyber.CYAN)}")
    print()

    status_colors = {
        "tracking_detected": (Cyber.RED, Cyber.BOLD),
        "clean": (Cyber.GREEN, Cyber.BOLD),
        "warning": (Cyber.YELLOW, ""),
        "error": (Cyber.YELLOW, ""),
    }
    sc = status_colors.get(result.overall_status, (Cyber.WHITE, ""))
    print(f"  Status: {color(result.overall_status.upper(), *sc)}")
    print()

    status_icons = {
        "detected": color("[!]", Cyber.RED, Cyber.BOLD),
        "not_detected": color("[+]", Cyber.GREEN),
        "blocked": color("[+]", Cyber.GREEN),
        "error": color("[-]", Cyber.YELLOW),
    }

    print(color("  Tecnicas analisadas:", Cyber.CYAN, Cyber.BOLD))
    for a in result.attempts:
        icon = status_icons.get(a.status, color("[?]", Cyber.WHITE))
        print(f"    {icon} {a.technique}")
        if a.status == "detected":
            print(f"      Detalhes: {a.details[:80]}")
        elif a.status == "error":
            print(f"      Erro: {a.error[:80]}")
        print()

    if result.issues:
        print(color("  Observacoes:", Cyber.YELLOW, Cyber.BOLD))
        for issue in result.issues:
            print(f"    {color('[!]', Cyber.YELLOW)} {issue}")
        print()

    if result.overall_status == "tracking_detected":
        print(color(f"  [-] Servidor INJETA TRACKING — {len(result.detected_techniques)}/{len(result.attempts)} tecnicas detectadas", Cyber.RED, Cyber.BOLD))
        print(color("  [-] Risco: privacidade comprometida, leituras rastreadas, links reescritos", Cyber.CYAN))
        print(color("  [-] Remedio: desabilitar injection de tracking, usar proxys de privacidade", Cyber.CYAN))
    elif result.overall_status == "clean":
        print(color("  [+] Servidor limpo — nenhum mecanismo de tracking injetado", Cyber.GREEN, Cyber.BOLD))
    else:
        print(color("  [!] Resultado inconclusivo — revisar manualmente", Cyber.YELLOW))


def banner_art() -> None:
    """Exibe o banner do Email Link Tracking."""
    art = r"""
    __  __    _    _     ______   __  __           _      _
   |  \/  |  / \  | |   / ___\ \ / / / __| |_ __ (_)_  _| |
   | |\/| | / _ \ | |___\___ \\ V / | (__| | '_ \| \ \/ / |
   | |  | |/ ___ \| |____|__) || |   \__ \ | | | | |>  <| |___
   |_|  |_/_/   \_\_|   |____/ |_|   |___/_|_| |_|_/_/\_\_____|
"""
    create_banner(art, "   link tracking: detecta tracking pixels, link rewrites, UTM params, redirects em emails")()


def build_parser() -> argparse.ArgumentParser:
    """Construi o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Email Link Tracking — detecta tracking pixels e link rewrites em emails.",
        epilog="Analisa se o servidor injeta mecanismos de tracking em emails de saida.",
    )
    add_base_args(parser)
    parser.add_argument("target", nargs="?", help="Host SMTP alvo (ex: mail.example.com).")
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=587,
        help="Porta SMTP. Padrao: 587",
    )
    parser.add_argument(
        "--from-addr",
        default="test@example.com",
        help="Endereco FROM para os testes. Padrao: test@example.com",
    )
    parser.add_argument(
        "--to-addr",
        default="test@example.com",
        help="Endereco TO para os testes. Padrao: test@example.com",
    )
    parser.add_argument(
        "--category", "-c",
        choices=list(_CATEGORY_MAP.keys()),
        help="Testa apenas uma categoria de tracking.",
    )
    return parser


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan (async)."""
    quiet = init_scanner(args)

    target = getattr(args, "target", None)
    if not target:
        print(color("[!] Informe um host SMTP.", Cyber.RED))
        return 1

    if getattr(args, "dry_run", False):
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhuma conexao SMTP sera feita.")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Target: {color(target, Cyber.WHITE, Cyber.BOLD)}:{args.port}")
        return 0

    result = scan_link_tracking(
        target=target,
        port=args.port,
        from_addr=args.from_addr,
        to_addr=args.to_addr,
        timeout=args.timeout,
        category=getattr(args, "category", None),
    )

    if not quiet:
        print_results(result)

    if args.output:
        write_output(
            args.output,
            [asdict(result)],
            ["target", "port", "overall_status", "detected_techniques", "issues"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do Email Link Tracking."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(a.target),
        prompt="linktrack> ",
        description="Email Link Tracking — detecta tracking pixels e link rewrites em emails.",
        example="mail.example.com --port 587",
        contextual_help=(
            "Uso: <host> [opcoes]\n"
            "Exemplos:\n"
            "  mail.example.com\n"
            "  mail.example.com --port 25\n"
            "  mail.example.com --from-addr admin@test.com\n"
            "  mail.example.com --category pixel\n"
            "  mail.example.com --category link"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
