#!/usr/bin/env python3
"""Scanner de portas TCP rápido para laboratórios e hosts autorizados."""
from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from types import MappingProxyType
from typing import Iterable

from utils import Cyber, add_base_args, color, create_banner, parse_int_range, print_table, set_color, setup_logging, write_output, run_interactive_shell

import logging

logger = logging.getLogger("mytools.portscanner")


DEFAULT_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 119, 123, 135, 139, 143, 161, 194, 389,
    443, 445, 465, 587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 9200, 27017,
]

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
    49153, 49154, 49155, 49156, 49157,
]



banner = create_banner(r"""
    ____             __  _____
   / __ \____  _____/ /_/ ___/_________ _____  ____  ___  _____
  / /_/ / __ \/ ___/ __/\__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / ____/ /_/ / /  / /_ ___/ / /__/ /_/ / / / / / / /  __/ /
/_/    \____/_/   \__//____/\___/\__,_/_/ /_/_/ /_/\___/_/
""", "   TCP scanner | use apenas em alvos autorizados")


@dataclass(frozen=True)
class Finding:
    """Representa uma porta aberta encontrada durante a varredura."""
    host: str
    address: str
    port: int
    state: str
    service: str
    banner: str = ""


def parse_ports(value: str) -> list[int]:
    """Converte string de portas em lista ordenada de inteiros."""
    aliases = {
        "default": DEFAULT_PORTS,
        "top100": TOP_100_PORTS,
        "all": list(range(1, 65536)),
    }
    return parse_int_range(value, 1, 65535, "porta", aliases)


def resolve_targets(values: Iterable[str]) -> list[tuple[str, str]]:
    """Resolve nomes, IPs e CIDRs em lista de pares (host, endereço IP)."""
    targets: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for value in values:
        value = value.strip()
        if not value:
            continue

        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            try:
                address = socket.gethostbyname(value)
            except socket.gaierror as error:
                raise ValueError(f"nao consegui resolver {value!r}: {error}") from error
            item = (value, address)
            if item not in seen:
                targets.append(item)
                seen.add(item)
            continue

        for ip in network.hosts() if network.num_addresses > 2 else network:
            address = str(ip)
            item = (address, address)
            if item not in seen:
                targets.append(item)
                seen.add(item)

    if not targets:
        raise ValueError("nenhum alvo valido informado")
    return targets


def service_name(port: int) -> str:
    """Retorna o nome do serviço associado à porta TCP."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


BANNER_PROBES = MappingProxyType({
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
})


def grab_banner(sock: socket.socket, port: int, timeout: float) -> str:
    """Tenta capturar o banner de um socket conectado na porta informada."""
    sock.settimeout(timeout)

    try:
        if port in BANNER_PROBES:
            sock.sendall(BANNER_PROBES[port])
        data = sock.recv(120)
    except (OSError, socket.timeout):
        return ""
    return data.decode("utf-8", errors="replace").strip().replace("\r", " ").replace("\n", " ")


def scan_port(
    host: str,
    address: str,
    port: int,
    timeout: float,
    with_banner: bool,
) -> Finding | None:
    """Tenta conectar a uma porta e retorna um Finding se estiver aberta."""
    try:
        with socket.create_connection((address, port), timeout=timeout) as sock:
            banner_text = grab_banner(sock, port, timeout) if with_banner else ""
            return Finding(
                host=host,
                address=address,
                port=port,
                state="open",
                service=service_name(port),
                banner=banner_text,
            )
    except (ConnectionRefusedError, TimeoutError, OSError, socket.timeout):
        return None


def scan_targets(
    targets: list[tuple[str, str]],
    ports: list[int],
    timeout: float,
    workers: int,
    with_banner: bool,
) -> list[Finding]:
    """Executa a varredura multi-threaded em todos os alvos e portas."""
    findings: list[Finding] = []
    total = len(targets) * len(ports)
    started = time.monotonic()

    logger.info("scan iniciado: %d alvos, %d portas (%d tentativas)", len(targets), len(ports), total)
    logger.debug("timeout=%.2f, workers=%d, banner=%s", timeout, workers, with_banner)

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Alvos: {color(str(len(targets)), Cyber.WHITE, Cyber.BOLD)} | Portas: {color(str(len(ports)), Cyber.WHITE, Cyber.BOLD)} | Tentativas: {color(str(total), Cyber.WHITE, Cyber.BOLD)}")
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Timeout: {color(f'{timeout:.2f}s', Cyber.YELLOW)} | Threads: {color(str(workers), Cyber.YELLOW)}")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        batch_size = workers * 2
        pending = []
        targets_ports = [
            (host, address, port)
            for host, address in targets
            for port in ports
        ]

        def _process_completed(futures_list: list[Future[Finding | None]]) -> None:
            for future in as_completed(futures_list):
                try:
                    finding = future.result()
                except Exception:
                    continue
                if finding:
                    findings.append(finding)
                    banner_text = f" | {finding.banner}" if finding.banner else ""
                    port_text = str(finding.port).ljust(5)
                    print(
                        f"{color('[+]', Cyber.GREEN, Cyber.BOLD)} "
                        f"{color(finding.address, Cyber.CYAN)}:"
                        f"{color(port_text, Cyber.YELLOW)} "
                        f"{color('open', Cyber.GREEN, Cyber.BOLD)} "
                        f"{color(finding.service, Cyber.MAGENTA)}"
                        f"{color(banner_text, Cyber.GRAY)}"
                    )

        for host, address, port in targets_ports:
            pending.append(executor.submit(scan_port, host, address, port, timeout, with_banner))
            if len(pending) >= batch_size:
                _process_completed(pending)
                pending.clear()
        _process_completed(pending)

    elapsed = time.monotonic() - started
    findings.sort(key=lambda item: (ip_sort_key(item.address), item.port))
    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Finalizado em {color(f'{elapsed:.2f}s', Cyber.YELLOW)}. "
        f"Portas abertas: {color(str(len(findings)), Cyber.GREEN, Cyber.BOLD)}",
    )
    return findings


def ip_sort_key(address: str) -> tuple[int, int, str]:
    """Gera chave de ordenação numérica para endereços IP."""
    try:
        ip = ipaddress.ip_address(address)
        version = 0 if ip.version == 4 else 1
        return (version, 0, ip.packed.hex())
    except ValueError:
        return (2, 0, address)


def print_port_table(findings: list[Finding]) -> None:
    """Exibe os findings em formato de tabela colorida no terminal."""
    headers = ("HOST", "IP", "PORT", "SERVICE", "BANNER")
    rows = [
        (item.host, item.address, str(item.port), item.service, item.banner)
        for item in findings
    ]
    print_table(
        headers=headers,
        rows=rows,
        column_styles=[
            (Cyber.WHITE,),
            (Cyber.CYAN,),
            (Cyber.YELLOW,),
            (Cyber.MAGENTA,),
            (Cyber.GRAY,),
        ],
        empty_message="Nenhuma porta aberta encontrada.",
    )


def build_parser() -> argparse.ArgumentParser:
    """Constrói e retorna o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Port scanner TCP rapido para laboratorios e hosts autorizados."
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="IP, hostname ou CIDR. Ex: 192.168.0.10 scanme.nmap.org 10.0.0.0/30",
    )
    parser.add_argument("-l", "--list", dest="target_list", help="Arquivo com alvos (um por linha).")
    parser.add_argument(
        "-p",
        "--ports",
        type=parse_ports,
        default=DEFAULT_PORTS,
        help="Portas: default, top100, all, 22,80,443 ou 1-1024. Padrao: default",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=200,
        help="Numero de threads. Padrao: 200",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=None,
        help="Alias de --workers (deprecated). Use --workers.",
    )
    parser.add_argument(
        "-b",
        "--banner",
        action="store_true",
        help="Tenta coletar banner em portas abertas.",
    )
    add_base_args(parser, timeout_default=0.5)
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa uma única varredura com os argumentos fornecidos."""
    setup_logging(verbose=args.verbose, log_file=args.log_file)
    quiet = getattr(args, "quiet", False)
    if getattr(args, "color", None) is not None:
        set_color(args.color)

    if args.threads is not None:
        import warnings
        warnings.warn(
            "--threads e deprecated, use --workers",
            DeprecationWarning,
            stacklevel=2,
        )
        args.workers = args.threads

    if args.timeout <= 0:
        raise ValueError("timeout precisa ser maior que zero")
    if args.workers < 1:
        raise ValueError("workers precisa ser maior que zero")

    all_targets: list[str] = list(args.targets) if args.targets else []
    if getattr(args, "target_list", None):
        try:
            with open(args.target_list, "r", encoding="utf-8", errors="replace") as fh:
                all_targets.extend(line.strip() for line in fh if line.strip() and not line.startswith("#"))
        except FileNotFoundError:
            raise ValueError(f"arquivo nao encontrado: {args.target_list}")
    if not all_targets:
        raise ValueError("informe pelo menos um alvo ou use -l/--list")

    targets = resolve_targets(all_targets)
    findings = scan_targets(
        targets=targets,
        ports=args.ports,
        timeout=args.timeout,
        workers=args.workers,
        with_banner=args.banner,
    )
    if not quiet:
        print_port_table(findings)
    if args.output:
        write_output(
            args.output,
            [asdict(f) for f in findings],
            ["host", "address", "port", "state", "service", "banner"],
            quiet=quiet,
        )
    return 0


def main() -> int:
    """Ponto de entrada principal do scanner."""
    parser = build_parser()
    args = parser.parse_args()
    has_targets = args.targets or getattr(args, "target_list", None)
    if not has_targets:

        def _validate(args):
            if not args.targets and not getattr(args, "target_list", None):
                raise ValueError("Informe pelo menos um alvo.")

        return run_interactive_shell(
            parser, "scanner> ", run_once,
            description="PortScanner interativo.",
            example="192.168.0.10 -p 1-1024 -b",
            validate_fn=_validate,
            banner_fn=banner,
        )

    quiet = getattr(args, "quiet", False)
    if quiet and not args.output:
        print(color("Erro: modo quiet requer -o/--output", Cyber.RED), file=sys.stderr)
        return 1

    try:
        if not quiet:
            banner()
        return run_once(args)
    except Exception as error:
        print(color(f"Erro: {error}", Cyber.RED), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
