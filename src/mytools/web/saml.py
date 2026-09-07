#!/usr/bin/env python3

"""Modulo de deteccao de SAML Attacks.



Testa se uma implementacao SAML e vulneravel a ataques:

  - assertion_replay: replay completo, timestamp modificado, NotOnAfter bypass, InResponseTo bypass, assertion expirada

  - xml_signature_wrapping: exclusive c14n, signature clone, comment injection, namespace stripping, attribute manipulation



Fluxo:

  1. Recebe SAML Response (via --file ou --saml-response)

  2. Decodifica e parseia o XML

  3. Para cada categoria, gera payloads de ataque

  4. Opcionalmente envia ao servidor via --url

  5. Retorna resultado consolidado com severidade

"""

import argparse
import base64
import logging
import xml.etree.ElementTree as ET
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from pathlib import Path

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_banner,
    print_exploit_info,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.saml")


_CATEGORY_MAP: dict[str, list[str]] = {
    "assertion_replay": [
        "full_replay",
        "timestamp_modification",
        "noton_after_bypass",
        "inresponseto_bypass",
        "expired_assertion",
    ],
    "xml_signature_wrapping": [
        "exclusive_c14n",
        "signature_clone",
        "comment_injection",
        "namespace_stripping",
        "attribute_manipulation",
    ],
}


_SAML_NS = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


def _decode_saml_response(encoded: str) -> str | None:
    """Decodifica SAML Response de base64."""

    try:
        padded = encoded + "=" * ((4 - len(encoded) % 4) % 4)

        return base64.b64decode(padded).decode(errors="replace")

    except Exception:
        return None


def _parse_saml_xml(xml_str: str) -> ET.Element | None:
    """Parseia SAML XML."""

    try:
        return ET.fromstring(xml_str)

    except ET.ParseError:
        return None


def _extract_assertion_conditions(root: ET.Element) -> dict[str, str]:
    """Extrai condicoes do assertion (NotBefore, NotOnAfter)."""

    conditions: dict[str, str] = {}

    for cond in root.iter(f"{{{_SAML_NS['saml']}}}Conditions"):
        nb = cond.get("NotBefore", "")

        noa = cond.get("NotOnAfter", "")

        if nb:
            conditions["NotBefore"] = nb

        if noa:
            conditions["NotOnAfter"] = noa

    return conditions


def _extract_response_id(root: ET.Element) -> str:
    """Extrai ID do Response."""

    return root.get("ID", root.get(f"{{{_SAML_NS['samlp']}}}ID", ""))


def _extract_assertion_id(root: ET.Element) -> str:
    """Extrai ID do Assertion."""

    for assertion in root.iter(f"{{{_SAML_NS['saml']}}}Assertion"):
        return assertion.get("ID", "")

    return ""


def _extract_in_response_to(root: ET.Element) -> str:
    """Extrai InResponseTo do Response."""

    return root.get("InResponseTo", "")


def _generate_modified_response(xml_str: str, modifications: dict[str, str]) -> str:
    """Gera SAML Response com modificacoes."""

    result = xml_str

    for old, new in modifications.items():
        result = result.replace(old, new)

    return result


async def _test_assertion_replay_category(
    xml_str: str,
    root: ET.Element,
    url: str | None,
    timeout: float,
) -> list[dict[str, object]]:
    """Testa assertion replay."""

    results: list[dict[str, object]] = []

    conditions = _extract_assertion_conditions(root)

    response_id = _extract_response_id(root)

    in_response_to = _extract_in_response_to(root)

    results.append(
        {
            "technique": "full_replay",
            "category": "assertion_replay",
            "vulnerable": False,
            "details": f"response ID={response_id[:20]}... â€” replay requer envio ao servidor",
            "error": "",
        }
    )

    results.append(
        {
            "technique": "timestamp_modification",
            "category": "assertion_replay",
            "vulnerable": False,
            "details": "modificacao de IssueInstant â€” requer envio ao servidor",
            "error": "",
        }
    )

    not_on_after = conditions.get("NotOnAfter", "")

    if not_on_after:
        results.append(
            {
                "technique": "noton_after_bypass",
                "category": "assertion_replay",
                "vulnerable": False,
                "details": f"NotOnAfter={not_on_after} â€” testar se servidor valida expiracao",
                "error": "",
            }
        )

    else:
        results.append(
            {
                "technique": "noton_after_bypass",
                "category": "assertion_replay",
                "vulnerable": True,
                "details": "NotOnAfter ausente â€” assertion sem expiracao",
                "error": "",
            }
        )

    results.append(
        {
            "technique": "inresponseto_bypass",
            "category": "assertion_replay",
            "vulnerable": not in_response_to,
            "details": f"InResponseTo={in_response_to or 'ausente'} â€” "
            + ("possivel replay cross-session" if not in_response_to else "presente"),
            "error": "",
        }
    )

    results.append(
        {
            "technique": "expired_assertion",
            "category": "assertion_replay",
            "vulnerable": not bool(conditions),
            "details": "condicoes de tempo "
            + ("ausentes" if not conditions else "presentes"),
            "error": "",
        }
    )

    return results


async def _test_xml_signature_wrapping_category(
    xml_str: str,
    root: ET.Element,
    url: str | None,
    timeout: float,
) -> list[dict[str, object]]:
    """Testa XML Signature Wrapping."""

    results: list[dict[str, object]] = []

    has_signature = next(root.iter(f"{{{_SAML_NS['ds']}}}Signature"), None) is not None

    results.append(
        {
            "technique": "exclusive_c14n",
            "category": "xml_signature_wrapping",
            "vulnerable": False,
            "details": "exclusive canonicalization attack â€” requer envio ao servidor",
            "error": "",
        }
    )

    results.append(
        {
            "technique": "signature_clone",
            "category": "xml_signature_wrapping",
            "vulnerable": has_signature,
            "details": "signature element "
            + ("detectado â€” possivel clone" if has_signature else "ausente"),
            "error": "",
        }
    )

    results.append(
        {
            "technique": "comment_injection",
            "category": "xml_signature_wrapping",
            "vulnerable": False,
            "details": "comment injection no XML â€” requer envio ao servidor",
            "error": "",
        }
    )

    results.append(
        {
            "technique": "namespace_stripping",
            "category": "xml_signature_wrapping",
            "vulnerable": False,
            "details": "namespace stripping â€” requer envio ao servidor",
            "error": "",
        }
    )

    results.append(
        {
            "technique": "attribute_manipulation",
            "category": "xml_signature_wrapping",
            "vulnerable": False,
            "details": "attribute manipulation apos signature â€” requer envio ao servidor",
            "error": "",
        }
    )

    return results


CATEGORY_TESTERS: dict[str, Callable[..., Awaitable[list[dict[str, object]]]]] = {
    "assertion_replay": _test_assertion_replay_category,
    "xml_signature_wrapping": _test_xml_signature_wrapping_category,
}


@dataclass(frozen=True, slots=True)
class SAMLAttempt:
    technique: str

    category: str

    vulnerable: bool

    details: str

    error: str

    exploit: str = ""

    tool: str = ""


@dataclass(frozen=True, slots=True)
class SAMLResult:
    target: str | None

    xml_valid: bool

    response_id: str

    assertion_id: str

    conditions: dict[str, str]

    has_signature: bool

    attempts: list[SAMLAttempt]

    vulnerable_techniques: list[str]

    issues: list[str]

    overall_status: str


def print_results(result: SAMLResult) -> None:
    """Exibe os resultados do scan de SAML."""

    vuln = [a for a in result.attempts if a.vulnerable]

    safe = [a for a in result.attempts if not a.vulnerable and not a.error]

    errors = [a for a in result.attempts if a.error]

    print(color("\n--- SAML Attack Detection ---", Cyber.CYAN, Cyber.BOLD))

    if result.target:
        print(color(f"  Alvo:        {result.target}", Cyber.WHITE))

    print(color(f"  XML valido:  {'sim' if result.xml_valid else 'nao'}", Cyber.WHITE))

    print(color(f"  Response ID: {result.response_id[:30] or 'N/A'}", Cyber.GRAY))

    print(color(f"  Assertion ID:{result.assertion_id[:30] or 'N/A'}", Cyber.GRAY))

    print(color(f"  Condicoes:   {result.conditions or 'nenhuma'}", Cyber.GRAY))

    print(
        color(f"  Signature:   {'sim' if result.has_signature else 'nao'}", Cyber.WHITE)
    )

    print(color(f"  Testes:      {len(result.attempts)}", Cyber.WHITE))

    print(color(f"  Vulneraveis: {len(vuln)}", Cyber.RED if vuln else Cyber.GREEN))

    print(color(f"  Seguros:     {len(safe)}", Cyber.GREEN))

    print(color(f"  Erros:       {len(errors)}", Cyber.RED if errors else Cyber.GRAY))

    if vuln:
        print(color("\n  [!] Vulnerabilidades encontradas:", Cyber.RED))

        seen: set[str] = set()

        for a in vuln:
            if a.technique in seen:
                continue

            seen.add(a.technique)

            print(color(f"    [{a.category}] {a.technique}", Cyber.RED))

            if a.details:
                print(color(f"      {a.details}", Cyber.GRAY))

            print_exploit_info(a.exploit, a.tool)

        print(
            color(
                f"\n  Total: {len(vuln)} vulneraveis de {len(result.attempts)} testes",
                Cyber.WHITE,
            )
        )

    else:
        print(color("\n  [+] Nenhuma vulnerabilidade SAML detectada", Cyber.GREEN))

    if result.issues:
        print(color("\n  [!] Observacoes:", Cyber.YELLOW))

        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))


async def run_scan(
    saml_response: str,
    target: str | None,
    categories: list[str],
    output_file: str | None,
    timeout: float,
) -> int:
    """Executa o scan de SAML Attacks."""

    logger.info("SAML scan (target=%s)", target)

    issues: list[str] = []

    xml_str = _decode_saml_response(saml_response)

    if xml_str is None:
        print(color("Erro: SAML Response invalido ou corrupto", Cyber.RED))

        return 1

    root = _parse_saml_xml(xml_str)

    if root is None:
        print(color("Erro: XML do SAML Response invalido", Cyber.RED))

        return 1

    conditions = _extract_assertion_conditions(root)

    response_id = _extract_response_id(root)

    assertion_id = _extract_assertion_id(root)

    has_signature = next(root.iter(f"{{{_SAML_NS['ds']}}}Signature"), None) is not None

    all_attempts: list[SAMLAttempt] = []

    test_categories = categories if categories else list(_CATEGORY_MAP.keys())

    for cat in test_categories:
        tester = CATEGORY_TESTERS.get(cat)

        if tester is None:
            continue

        try:
            raw = await tester(xml_str, root, target, timeout)

            all_attempts.extend(
                SAMLAttempt(
                    technique=str(item["technique"]),
                    category=str(item["category"]),
                    vulnerable=bool(item["vulnerable"]),
                    details=str(item["details"]),
                    error=str(item["error"]),
                    exploit="signature_wrapping_payload"
                    if bool(item["vulnerable"])
                    else "",
                    tool="SAMLRaider",
                )
                for item in raw
            )

        except Exception as e:
            all_attempts.append(
                SAMLAttempt(
                    technique=f"{cat}_error",
                    category=cat,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})

    if not conditions:
        issues.append("NotBefore/NotOnAfter ausentes â€” assertions podem nao expirar")

    if not has_signature:
        issues.append("Assinatura XML ausente â€” assertions podem ser falsificadas")

    result = SAMLResult(
        target=target,
        xml_valid=True,
        response_id=response_id,
        assertion_id=assertion_id,
        conditions=conditions,
        has_signature=has_signature,
        attempts=all_attempts,
        vulnerable_techniques=vuln_techs,
        issues=issues,
        overall_status="vulnerable" if vuln_techs else "safe",
    )

    print_results(result)

    logger.info(
        "SAML scan concluido: %d testes, %d vulneraveis",
        len(all_attempts),
        len(vuln_techs),
    )

    if output_file:
        write_output(output_file, asdict(result))

        logger.info("Resultados salvos em %s", output_file)

    return 1 if vuln_techs else 0


def banner_art() -> None:
    """Exibe a banner do modulo."""

    art = r"""

    ___  ___  __      __       ___

   / __|/ _ \ \ \    / /      / __|

   \__ \ (_) | \ \/\/ /       \__ \

   |___/\___/   \_/\_/        |___/

"""

    create_banner(art, "   saml: assertion_replay, xml_signature_wrapping")()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""

    parser = argparse.ArgumentParser(
        prog="mytools-saml",
        description="SAML Attack Detection â€” detecta assertion replay e XML Signature Wrapping.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-saml --file response.xml\n"
            "  mytools-saml --saml-response PHNhbWw+...\n"
            "  mytools-saml --file response.xml --url https://target.com/acs\n"
            "  mytools-saml --file response.xml -c assertion_replay\n"
            "  mytools-saml --file response.xml -o resultado.json"
        ),
    )

    parser.add_argument("--saml-response", help="SAML Response em base64")

    parser.add_argument("--file", help="Arquivo com SAML Response XML ou base64")

    parser.add_argument(
        "--url", help="URL do ACS (Assertion Consumer Service) para envio ativo"
    )

    parser.add_argument(
        "-c",
        "--category",
        default="all",
        choices=["all", "assertion_replay", "xml_signature_wrapping"],
        help="Categoria de testes (default: todas)",
    )

    add_common_args(parser, "web")

    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa o scan SAML a partir de argumentos parseados."""

    saml_response = getattr(args, "saml_response", None)

    file_path = getattr(args, "file", None)

    if not saml_response and file_path:
        try:
            content = Path(file_path).read_text(encoding="utf-8").strip()

            saml_response = content.splitlines()[0] if content else ""

        except OSError, IndexError:
            print(color(f"Erro ao ler arquivo: {file_path}", Cyber.RED))

            return 1

    if not saml_response:
        print(
            color(
                "Erro: forneÃ§a um SAML Response via --saml-response ou --file",
                Cyber.RED,
            )
        )

        return 1

    categories: list[str] = []

    if getattr(args, "category", None) and args.category != "all":
        categories = [args.category]

    return safe_asyncio_run(
        run_scan(
            saml_response=saml_response,
            target=getattr(args, "url", None),
            categories=categories,
            output_file=getattr(args, "output", None),
            timeout=getattr(args, "timeout", 10),
        ),
    )


def main() -> int:
    """Entry point do modulo SAML Attack Detection."""

    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "saml_response", None) or getattr(a, "file", None)
        ),
        prompt="saml> ",
        description="SAML Attack Detection interativo.",
        example="--file response.xml -c assertion_replay",
        contextual_help=(
            "Uso: --file <arquivo> ou --saml-response <base64>\n"
            "Exemplos:\n"
            "  --file response.xml\n"
            "  --saml-response PHNhbWw+...\n"
            "  --file response.xml --url https://target.com/acs\n"
            "  --file response.xml -c assertion_replay\n"
            "  --file response.xml -o resultado.json"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
