#!/usr/bin/env python3
"""Scanner de portas TCP rápido para laboratórios e hosts autorizados."""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import shlex
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Iterable

from utils import Cyber, clear_console, color, setup_logging

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



def banner() -> None:
    """Exibe o banner ASCII do scanner na tela."""
    art = r"""
    ____             __  _____
   / __ \____  _____/ /_/ ___/_________ _____  ____  ___  _____
  / /_/ / __ \/ ___/ __/\__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / ____/ /_/ / /  / /_ ___/ / /__/ /_/ / / / / / / /  __/ /
/_/    \____/_/   \__//____/\___/\__,_/_/ /_/_/ /_/\___/_/
"""
    print(color(art.rstrip(), Cyber.CYAN, Cyber.BOLD))
    print(color("   TCP scanner | use apenas em alvos autorizados\n", Cyber.MAGENTA))


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
    if value == "default":
        return DEFAULT_PORTS
    if value == "top100":
        return TOP_100_PORTS
    if value == "all":
        return list(range(1, 65536))

    ports: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                start_raw, end_raw = part.split("-", 1)
                start, end = int(start_raw), int(end_raw)
                if start > end:
                    start, end = end, start
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        except ValueError:
            raise argparse.ArgumentTypeError(f"porta invalida: {part!r}")

    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise argparse.ArgumentTypeError(
            f"portas invalidas: {', '.join(map(str, sorted(invalid)))}"
        )
    if not ports:
        raise argparse.ArgumentTypeError("informe pelo menos uma porta")
    return sorted(ports)


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


BANNER_PROBES = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
}


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
        futures = [
            executor.submit(scan_port, host, address, port, timeout, with_banner)
            for host, address in targets
            for port in ports
        ]

        for future in as_completed(futures):
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


def print_table(findings: list[Finding]) -> None:
    """Exibe os findings em formato de tabela colorida no terminal."""
    if not findings:
        print(color("Nenhuma porta aberta encontrada.", Cyber.RED))
        return

    headers = ("HOST", "IP", "PORT", "SERVICE", "BANNER")
    rows = [
        (item.host, item.address, str(item.port), item.service, item.banner)
        for item in findings
    ]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in rows))
        for index in range(len(headers))
    ]

    print()
    print(color("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)), Cyber.CYAN, Cyber.BOLD))
    print(color("  ".join("-" * width for width in widths), Cyber.BLUE))
    for row in rows:
        host, address, port, service, row_banner = row
        print(
            "  ".join(
                (
                    color(host.ljust(widths[0]), Cyber.WHITE),
                    color(address.ljust(widths[1]), Cyber.CYAN),
                    color(port.ljust(widths[2]), Cyber.YELLOW),
                    color(service.ljust(widths[3]), Cyber.MAGENTA),
                    color(row_banner.ljust(widths[4]), Cyber.GRAY),
                )
            )
        )


def write_output(path: str, findings: list[Finding]) -> None:
    """Salva os findings em arquivo JSON ou CSV."""
    extension = os.path.splitext(path)[1].lower()
    with open(path, "w", encoding="utf-8", newline="") as file_handle:
        if extension == ".json":
            json.dump([asdict(item) for item in findings], file_handle, indent=2)
            file_handle.write("\n")
        else:
            writer = csv.DictWriter(
                file_handle,
                fieldnames=["host", "address", "port", "state", "service", "banner"],
            )
            writer.writeheader()
            for item in findings:
                writer.writerow(asdict(item))
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Resultado salvo em {color(path, Cyber.GREEN)}")


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
    parser.add_argument(
        "-p",
        "--ports",
        type=parse_ports,
        default=DEFAULT_PORTS,
        help="Portas: default, top100, all, 22,80,443 ou 1-1024. Padrao: default",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=0.5,
        help="Timeout por conexao em segundos. Padrao: 0.5",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=200,
        help="Numero de threads. Padrao: 200",
    )
    parser.add_argument(
        "-b",
        "--banner",
        action="store_true",
        help="Tenta coletar banner em portas abertas.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Salva resultado em .json ou .csv.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Mostra mensagens de debug no terminal.")
    parser.add_argument("--log-file", help="Salva logs em arquivo.")
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa uma única varredura com os argumentos fornecidos."""
    setup_logging(verbose=args.verbose, log_file=args.log_file)
    if args.timeout <= 0:
        raise ValueError("timeout precisa ser maior que zero")
    if args.workers < 1:
        raise ValueError("workers precisa ser maior que zero")

    targets = resolve_targets(args.targets)
    findings = scan_targets(
        targets=targets,
        ports=args.ports,
        timeout=args.timeout,
        workers=args.workers,
        with_banner=args.banner,
    )
    print_table(findings)
    if args.output:
        write_output(args.output, findings)
    return 0


def interactive_shell(parser: argparse.ArgumentParser) -> int:
    """Inicia o modo interativo com loop de comandos."""
    banner()
    print(color("PortScanner interativo.", Cyber.WHITE, Cyber.BOLD), "Digite 'help', 'clear' ou 'exit'.")
    print(color("Ex:", Cyber.CYAN), "192.168.0.10 -p 1-1024 -b")

    while True:
        try:
            raw = input(color("scanner> ", Cyber.GREEN, Cyber.BOLD)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if not raw:
            continue
        if raw in {"exit", "quit"}:
            return 0
        if raw == "clear":
            clear_console()
            continue
        if raw == "help":
            parser.print_help()
            continue

        try:
            args = parser.parse_args(shlex.split(raw))
            if not args.targets:
                print(color("Informe pelo menos um alvo.", Cyber.RED))
                continue
            run_once(args)
        except SystemExit:
            continue
        except Exception as error:
            print(f"Erro: {error}")


def main() -> int:
    """Ponto de entrada principal do scanner."""
    parser = build_parser()
    args = parser.parse_args()
    if not args.targets:
        return interactive_shell(parser)

    try:
        banner()
        return run_once(args)
    except Exception as error:
        print(color(f"Erro: {error}", Cyber.RED), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
