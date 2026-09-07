#!/usr/bin/env python3
"""Phone Lookup — consulta informacoes de um numero de telefone.

Fontes:
  - Local (offline): validacao/formato via phonenumbers, DDD/UF/cidades e
    operadora por prefixo (dados publicos ANATEL) para numeros brasileiros.
  - NumLookup (API opcional, requer chave): operadora, localizacao, tipo.
  - IPQualityScore (API opcional, requer chave): fraud score, status, etc.

Exemplo:
  mytools-phone +5561981280041
  mytools-phone +5561981280041 --numlookup-key KEY --ipqs-key KEY
"""

import argparse
import contextlib
import json
import logging
import os
from dataclasses import asdict, dataclass, field, replace
from typing import TYPE_CHECKING
from urllib.parse import quote

import phonenumbers
import phonenumbers.carrier
import phonenumbers.geocoder
import phonenumbers.timezone

if TYPE_CHECKING:
    import httpx

from mytools.core.utils import (
    Cyber,
    FetchError,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    ensure_output_dir,
    fetch,
    init_scanner,
    print_json,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)
from mytools.data import load_payloads

logger = logging.getLogger("mytools.phonelookup")

NUMLOOKUP_URL = "https://api.numlookupapi.com/v1/validate/{number}"
IPQS_URL = "https://www.ipqualityscore.com/api/json/phone/{key}/{number}"

_DDD_FALLBACK: dict[str, dict] = {"61": {"uf": "DF", "cities": ["Brasilia"]}}
_CARRIER_FALLBACK: dict[str, str] = {"96": "Vivo"}

_COUNTRY_NAMES = {
    "BR": "Brasil",
    "US": "Estados Unidos",
    "GB": "Reino Unido",
    "PT": "Portugal",
    "AR": "Argentina",
    "MX": "Mexico",
    "ES": "Espanha",
    "FR": "Franca",
    "DE": "Alemanha",
    "IT": "Italia",
    "CA": "Canada",
}

_NUMBER_TYPE_NAMES = {
    phonenumbers.PhoneNumberType.FIXED_LINE: "linha fixa",
    phonenumbers.PhoneNumberType.MOBILE: "movel",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixa/movel",
    phonenumbers.PhoneNumberType.TOLL_FREE: "0800",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "tarifa premium",
    phonenumbers.PhoneNumberType.SHARED_COST: "custo compartilhado",
    phonenumbers.PhoneNumberType.VOIP: "voip",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "numero pessoal",
    phonenumbers.PhoneNumberType.PAGER: "pager",
    phonenumbers.PhoneNumberType.UAN: "UAN",
    phonenumbers.PhoneNumberType.VOICEMAIL: "correio de voz",
}

banner = create_banner(
    r"""
     ____  _                      __
    / __ \| |__   ___  _ __   ___ / _| ___  _ __ _ __ _____      _
   / / _` | '_ \ / _ \| '_ \ / _ \ |_ / _ \| '__| '_ ` _ \ \ /\ / /
  | | (_| | |_) | (_) | | | |  __/  _| (_) | |  | | | | | \ V  V /
   \ \__,_|_.__/ \___/|_| |_|\___|_|  \___/|_|  |_| |_| |_|\_/\_/
    \____/
""",
    "Phone Lookup | use apenas em alvos autorizados",
)


@dataclass(frozen=True, slots=True)
class PhoneResult:
    """Resultado consolidado de uma consulta de telefone."""

    raw_number: str
    e164: str
    local_format: str
    international_format: str
    country_code: str
    country_name: str
    region: str = ""
    timezone: str = ""
    is_valid: bool = False
    line_type: str = ""
    ddd: str = ""
    uf: str = ""
    cities: list[str] = field(default_factory=list)
    carrier_local: str = ""
    numlookup: dict[str, object] = field(default_factory=dict)
    ipqs: dict[str, object] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)


def _load_phone_data() -> tuple[dict, dict]:
    """Carrega mapa de DDD e operadoras do YAML (com fallback)."""
    data = load_payloads("osint", "phone_lookup", default={})
    ddd = data.get("ddd") if isinstance(data, dict) else None
    carriers = data.get("carrier_prefixes") if isinstance(data, dict) else None
    return ddd or _DDD_FALLBACK, carriers or _CARRIER_FALLBACK


_DDD_MAP, _CARRIER_MAP = _load_phone_data()


def parse_number(raw: str, region: str = "BR") -> PhoneResult:
    """Interpreta e valida um numero de telefone via phonenumbers."""
    raw = (raw or "").strip()
    num = None
    with contextlib.suppress(phonenumbers.NumberParseException):
        num = phonenumbers.parse(raw, region)
    if num is None:
        with contextlib.suppress(phonenumbers.NumberParseException):
            num = phonenumbers.parse(raw, None)

    if num is None:
        return PhoneResult(
            raw_number=raw,
            e164="",
            local_format="",
            international_format="",
            country_code="",
            country_name="",
            is_valid=False,
            issues=["Numero invalido ou formato nao reconhecido"],
        )

    valid = phonenumbers.is_valid_number(num)
    cc = phonenumbers.region_code_for_number(num) or ""
    result = PhoneResult(
        raw_number=raw,
        e164=phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164),
        local_format=phonenumbers.format_number(
            num, phonenumbers.PhoneNumberFormat.NATIONAL
        ),
        international_format=phonenumbers.format_number(
            num, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        ),
        country_code=cc,
        country_name=_COUNTRY_NAMES.get(cc, "")
        or (phonenumbers.geocoder.country_name_for_number(num, "pt") or ""),
        region=phonenumbers.geocoder.description_for_number(num, "pt") or "",
        timezone=", ".join(phonenumbers.timezone.time_zones_for_number(num)),
        is_valid=valid,
        line_type=_NUMBER_TYPE_NAMES.get(phonenumbers.number_type(num), "desconhecido"),
        sources=["local"],
    )

    if cc == "BR" and valid:
        result = _lookup_br(result, num)
    return result


def _lookup_br(result: PhoneResult, num: phonenumbers.PhoneNumber) -> PhoneResult:
    """Enriquece numeros brasileiros com DDD/UF/cidades/operadora."""
    ns = phonenumbers.national_significant_number(num)
    if len(ns) not in (10, 11):
        return result
    ddd = ns[:2]
    mobile = len(ns) == 11 and ns[2] == "9"
    info = _DDD_MAP.get(ddd, {})
    cities = list(info.get("cities", [])) if isinstance(info, dict) else []
    uf = info.get("uf", "") if isinstance(info, dict) else ""
    carrier = ""
    if mobile and len(ns) >= 5:
        carrier = _CARRIER_MAP.get(ns[3:5], "")
    new_type = "movel" if mobile else "linha fixa"
    if result.line_type not in ("fixa/movel", "desconhecido"):
        new_type = result.line_type
    return replace(
        result,
        ddd=ddd,
        uf=uf,
        cities=cities,
        carrier_local=carrier,
        line_type=new_type,
    )


async def _numlookup(
    client: httpx.AsyncClient,
    number: str,
    api_key: str,
    country_code: str,
    timeout: float,
) -> dict | None:
    """Consulta a API NumLookup (opcional)."""
    if not api_key:
        return None
    url = NUMLOOKUP_URL.format(number=quote(number, safe="+"))
    query = f"?country_code={quote(country_code, safe='')}" if country_code else ""
    try:
        status, _headers, body, _ = await fetch(
            client,
            url + query,
            timeout=timeout,
            max_retries=1,
            headers={"apikey": api_key},
        )
    except FetchError:
        return {"error": "falha de rede"}
    if status == 401:
        return {"error": "chave invalida"}
    if status == 429:
        return {"error": "rate limit"}
    if status != 200:
        return {"error": f"HTTP {status}"}
    try:
        data = json.loads(body)
    except json.JSONDecodeError, ValueError:
        return {"error": "resposta invalida"}
    if not isinstance(data, dict):
        return {"error": "resposta invalida"}
    keys = (
        "valid",
        "number",
        "country_prefix",
        "country_code",
        "country_name",
        "location",
        "carrier",
        "line_type",
        "local_format",
        "international_format",
    )
    return {k: data[k] for k in keys if data.get(k) is not None}


async def _ipqs(
    client: httpx.AsyncClient,
    number: str,
    api_key: str,
    country_code: str,
    timeout: float,
) -> dict | None:
    """Consulta a API IPQualityScore (opcional)."""
    if not api_key:
        return None
    url = IPQS_URL.format(key=quote(api_key, safe=""), number=quote(number, safe=""))
    query = (
        f"?country={quote(country_code, safe='')}&strictness=0" if country_code else ""
    )
    try:
        status, _headers, body, _ = await fetch(
            client, url + query, timeout=timeout, max_retries=1
        )
    except FetchError:
        return {"error": "falha de rede"}
    if status != 200:
        return {"error": f"HTTP {status}"}
    try:
        data = json.loads(body)
    except json.JSONDecodeError, ValueError:
        return {"error": "resposta invalida"}
    if not isinstance(data, dict):
        return {"error": "resposta invalida"}
    keys = (
        "success",
        "message",
        "valid",
        "active",
        "active_status",
        "fraud_score",
        "recent_abuse",
        "prepaid",
        "voip",
        "risky",
        "leaked",
        "do_not_call",
        "spammer",
        "name",
        "carrier",
        "line_type",
        "country",
        "region",
        "city",
        "zip_code",
        "dialing_code",
    )
    return {k: data[k] for k in keys if data.get(k) is not None}


async def run_scan(
    raw: str,
    region: str = "BR",
    numlookup_key: str | None = None,
    ipqs_key: str | None = None,
    timeout: float = 10.0,
    user_agent: str | None = None,
    proxy: str | None = None,
    verify: bool = False,
) -> PhoneResult:
    """Executa a consulta completa (local + APIs opcionais)."""
    result = parse_number(raw, region)
    if not result.is_valid:
        return result

    if not (numlookup_key or ipqs_key):
        return result

    client = create_async_client(
        user_agent=user_agent, proxy=proxy, timeout=timeout, verify=verify
    )
    issues: list[str] = list(result.issues)
    sources: list[str] = list(result.sources)
    try:
        if numlookup_key:
            data = await _numlookup(
                client, result.e164, numlookup_key, result.country_code, timeout
            )
            if data is not None:
                sources.append("numlookup")
                if "error" in data:
                    issues.append(f"NumLookup: {data['error']}")
                elif data.get("valid") is False:
                    issues.append("NumLookup: numero invalido")
                result = replace(result, numlookup=data, sources=sources, issues=issues)
        if ipqs_key:
            data = await _ipqs(
                client, result.e164, ipqs_key, result.country_code, timeout
            )
            if data is not None:
                sources.append("ipqs")
                if "error" in data:
                    issues.append(f"IPQS: {data['error']}")
                elif data.get("success") is False:
                    message = data.get("message") or "numero invalido"
                    issues.append(f"IPQS: {message}")
                result = replace(result, ipqs=data, sources=sources, issues=issues)
    finally:
        await client.aclose()
    return result


def print_results(result: PhoneResult) -> None:
    """Imprime o resultado da consulta de forma colorida."""
    print()
    print(color(f"  Numero: {result.raw_number}", Cyber.CYAN, Cyber.BOLD))
    if not result.is_valid:
        print(color("  [-] Numero invalido.", Cyber.RED))
        for issue in result.issues:
            print(f"      {color('[i]', Cyber.RED)} {issue}")
        return

    print(
        f"  Validade: {color('valido', Cyber.GREEN)}  |  "
        f"Tipo: {color(result.line_type or '-', Cyber.YELLOW)}"
    )
    print(f"  E.164: {color(result.e164, Cyber.GREEN)}")
    if result.local_format:
        print(f"  Formato nacional: {result.local_format}")
    if result.international_format:
        print(f"  Formato internacional: {result.international_format}")
    print(
        f"  Pais: {color(result.country_name or result.country_code or '-', Cyber.GREEN)}"
    )
    if result.region:
        print(f"  Regiao: {result.region}")
    if result.timezone:
        print(f"  Fuso: {result.timezone}")

    if result.ddd:
        print()
        print(color("  [Brasil]", Cyber.BOLD))
        print(f"  DDD: {result.ddd}")
        if result.uf:
            print(f"  UF: {color(result.uf, Cyber.CYAN)}")
        if result.cities:
            print(f"  Cidades: {', '.join(result.cities)}")
        real_carrier = (
            result.numlookup.get("carrier") or result.ipqs.get("carrier") or ""
        )
        if result.carrier_local and not real_carrier:
            print(f"  Operadora (aprox.): {color(result.carrier_local, Cyber.CYAN)}")

    if result.numlookup:
        print()
        print(color("  [NumLookup]", Cyber.BOLD))
        if result.numlookup.get("carrier"):
            print(f"  Operadora: {result.numlookup['carrier']}")
        if result.numlookup.get("location"):
            print(f"  Localizacao: {result.numlookup['location']}")
        if result.numlookup.get("line_type"):
            print(f"  Tipo de linha: {result.numlookup['line_type']}")
        if result.numlookup.get("country_name"):
            print(f"  Pais: {result.numlookup['country_name']}")

    if result.ipqs:
        print()
        print(color("  [IPQualityScore]", Cyber.BOLD))
        fraud = result.ipqs.get("fraud_score")
        if isinstance(fraud, (int, float)):
            score_color = (
                Cyber.RED
                if fraud >= 70
                else Cyber.YELLOW
                if fraud >= 50
                else Cyber.GREEN
            )
            print(f"  Fraud score: {color(str(fraud), score_color, Cyber.BOLD)}")
        for key, label in (
            ("active", "Ativo"),
            ("active_status", "Status"),
            ("carrier", "Operadora"),
            ("city", "Cidade"),
            ("region", "Regiao"),
            ("zip_code", "CEP"),
            ("dialing_code", "DDI"),
            ("line_type", "Tipo de linha"),
        ):
            value = result.ipqs.get(key)
            if value is not None and value not in ("", "N/A"):
                print(f"  {label}: {value}")
        flags = [
            ("risky", "Risco"),
            ("recent_abuse", "Abuso recente"),
            ("prepaid", "Pre-pago"),
            ("voip", "VoIP"),
            ("leaked", "Vazado"),
            ("do_not_call", "Nao ligar"),
            ("spammer", "Spammer"),
        ]
        for key, label in flags:
            value = result.ipqs.get(key)
            if value is True or value == 1:
                print(f"  {label}: {color('Sim', Cyber.RED)}")
            elif value is False or value == 0:
                print(f"  {label}: {color('Nao', Cyber.GREEN)}")

    if result.issues:
        print()
        for issue in result.issues:
            print(f"  {color('[i]', Cyber.RED)} {issue}")
    print()


def build_parser() -> argparse.ArgumentParser:
    """Constroi o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Phone Lookup — informacoes de um numero de telefone.",
    )
    add_common_args(parser, "osint")
    parser.add_argument("number", help="Numero de telefone (ex.: +5511987654321).")
    parser.add_argument(
        "--region",
        default="BR",
        help="Regiao default (ISO alpha-2) para interpretar numero sem +. Padrao: BR",
    )
    parser.add_argument(
        "--numlookup-key",
        dest="numlookup_key",
        default=os.getenv("MYTOOLS_NUMLOOKUP_KEY"),
        help="API key do NumLookup (ou env MYTOOLS_NUMLOOKUP_KEY).",
    )
    parser.add_argument(
        "--ipqs-key",
        dest="ipqs_key",
        default=os.getenv("MYTOOLS_IPQS_KEY"),
        help="API key do IPQualityScore (ou env MYTOOLS_IPQS_KEY).",
    )
    return parser


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa uma unica consulta (async)."""
    quiet = init_scanner(args)
    raw = args.number
    if not raw:
        logger.error("Informe um numero. Ex: mytools-phone +5511987654321")
        return 1

    result = await run_scan(
        raw,
        region=getattr(args, "region", "BR"),
        numlookup_key=getattr(args, "numlookup_key", None),
        ipqs_key=getattr(args, "ipqs_key", None),
        timeout=args.timeout,
        user_agent=args.user_agent,
        proxy=args.proxy,
        verify=getattr(args, "verify", False),
    )

    if getattr(args, "json_output", False):
        print_json(asdict(result))
    elif not quiet:
        print_results(result)

    if getattr(args, "output_dir", None):
        safe = "".join(c for c in result.raw_number if c.isalnum()) or "phone"
        out_path = f"{args.output_dir}/phone_{safe}.json"
        ensure_output_dir(args.output_dir)
        write_output(out_path, asdict(result), quiet=quiet)

    if getattr(args, "output", None):
        write_output(args.output, asdict(result), quiet=quiet)

    api_error = any(i.startswith(("NumLookup:", "IPQS:")) for i in result.issues)
    return 1 if (not result.is_valid) or api_error else 0


def run_once(args: argparse.Namespace) -> int:
    """Executa uma unica consulta com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do Phone Lookup."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.number),
        prompt="phone> ",
        description="Phone Lookup interativo.",
        example="+5561981280041 --numlookup-key KEY --ipqs-key KEY",
        contextual_help=(
            "Uso: <numero> [opcoes]\n"
            "Exemplos:\n"
            "  phone> +5561981280041\n"
            "  phone> 61981280041\n"
            "  phone> +12125551234 --region US\n"
            "  phone> +5561981280041 --numlookup-key KEY\n"
            "  phone> +5561981280041 --ipqs-key KEY\n"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
