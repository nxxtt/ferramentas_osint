"""BaseScanner — elimina boilerplate comum em 85+ modulos.

Fornece:
- ``ScanGroup`` enum para select do dispatch de ``run_once``
- ``BaseScanner`` ABC com template de ``build_parser``, ``main``, ``run_once``
- Hooks sobrescreviveis: ``_add_arguments``, ``_build_run_once_kwargs``,
  ``_get_return_code``, ``_example``, ``_help``

Logger fica module-level em cada arquivo (compativel com codigo existente).
"""

from __future__ import annotations

import argparse
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import asdict
from enum import Enum, auto
from pathlib import Path
from typing import Any

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_banner,
    ensure_output_dir,
    init_scanner,
    print_json,
    run_main_loop,
    safe_asyncio_run,
    workspace_path,
    write_output,
)

__all__ = ["BaseScanner", "ScanGroup"]


class ScanGroup(Enum):
    """Grupo arquitetural do modulo."""

    A = auto()  # run_scan() retorna int; output gerenciado internamente
    B = auto()  # run_scan() retorna Result dataclass; output em run_once


class BaseScanner(ABC):
    """Classe base para modulos de scan.

    Subclasses definem:
        prog, description, prompt, module_name, banner_text, group

    E implementam:
        _add_arguments, run_scan, print_results, _example, _help
    """

    # --- Subclasses definem estas strings ---
    prog: str = ""
    description: str = ""
    prompt: str = ""
    module_name: str = ""
    banner_text: str = ""
    banner_fn: Callable[[], None] | None = None
    group: ScanGroup = ScanGroup.B
    module_type: str = "core"

    # ------------------------------------------------------------------
    # Parser
    # ------------------------------------------------------------------

    def build_parser(self) -> argparse.ArgumentParser:
        """Template: cria parser base e chama hook _add_arguments."""
        parser = argparse.ArgumentParser(
            prog=self.prog,
            description=self.description,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        self._add_arguments(parser)
        add_common_args(parser, self.module_type)
        return parser

    @abstractmethod
    def _add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Subclasses adicionam args especificos (url, category, etc)."""
        ...

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    @abstractmethod
    async def run_scan(self, **kwargs: Any) -> int | object:
        """Logica de scan. Grupo A retorna int, Grupo B retorna Result."""
        ...

    @abstractmethod
    def print_results(self, result: object) -> None:
        """Formata e imprime resultados."""
        ...

    # ------------------------------------------------------------------
    # Target resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _get_target(args: argparse.Namespace) -> str | None:
        """Resolve target de args.url OU args.target."""
        return getattr(args, "url", None) or getattr(args, "target", None)

    # ------------------------------------------------------------------
    # run_once dispatch
    # ------------------------------------------------------------------

    def run_once(self, args: argparse.Namespace) -> int:
        """Dispatch para grupo A ou B."""
        if self.group == ScanGroup.A:
            return self._run_once_a(args)
        return self._run_once_b(args)

    def _run_once_a(self, args: argparse.Namespace) -> int:
        """Grupo A: run_scan retorna int, output gerenciado internamente."""
        init_scanner(args)
        target = self._get_target(args)
        output_file = getattr(args, "output", None)
        if not output_file:
            output_dir = getattr(args, "output_dir", None)
            if output_dir and target:
                output_file = str(workspace_path(output_dir, target))
                ensure_output_dir(str(Path(output_file).parent))
        return safe_asyncio_run(
            self.run_scan(
                target=target,
                categories=self._get_categories(args),
                timeout=getattr(args, "timeout", 10),
                output_file=output_file,
                json_output=getattr(args, "json_output", False),
                proxy=getattr(args, "proxy", None),
                headless=getattr(args, "headless", False),
            )
        )

    def _run_once_b(self, args: argparse.Namespace) -> int:
        """Grupo B: scan retorna Result, output gerenciado em run_once."""
        quiet = init_scanner(args)
        kwargs = self._build_run_once_kwargs(args)
        if not self._get_target(args):
            print(color("Especifique um alvo.", Cyber.RED))
            return 1
        result = safe_asyncio_run(self.run_scan(**kwargs))
        if getattr(args, "json_output", False):
            print_json(asdict(result))
        elif not quiet:
            self.print_results(result)
        payload = asdict(result)
        output_path = getattr(args, "output", None)
        if output_path:
            write_output(output_path, payload)
        output_dir = getattr(args, "output_dir", None)
        if output_dir:
            ws = workspace_path(output_dir, self._get_target(args) or "")
            ensure_output_dir(str(ws.parent))
            write_output(str(ws), payload, quiet=True)
        return self._get_return_code(result)

    # ------------------------------------------------------------------
    # Hooks sobrescreviveis
    # ------------------------------------------------------------------

    def _build_run_once_kwargs(self, args: argparse.Namespace) -> dict[str, Any]:
        """Kwargs passados ao scan no Grupo B. Sobrescrever para modulos
        que usam parametros diferentes (domain, wordlist, etc)."""
        return {
            "url": self._get_target(args),
            "timeout": getattr(args, "timeout", 10.0),
            "user_agent": getattr(args, "user_agent", None),
            "proxy": getattr(args, "proxy", None),
            "verify": getattr(args, "verify", False),
            "category": getattr(args, "category", None),
            "concurrency": getattr(args, "concurrency", 5),
        }

    def _get_categories(self, args: argparse.Namespace) -> list[str]:
        """Extrai lista de categorias de args.category."""
        cat = getattr(args, "category", None)
        return [cat] if cat and cat != "all" else []

    def _get_return_code(self, result: object) -> int:
        """Codigo de saida: 0 somente se o scan reportou 'secure'.

        Qualquer outro status (vuln, erro, unsigned, etc) retorna 1.
        Convencao do repo: modules retornam 1 quando ha falhas/vulns e
        0 quando tudo esta seguro. Sobrescrever se necessario.
        """
        status = getattr(result, "overall_status", "error")
        return 1 if status != "secure" else 0

    # ------------------------------------------------------------------
    # main()
    # ------------------------------------------------------------------

    def main(self) -> int:
        """Entry point — identico em todos os modulos."""
        return run_main_loop(
            parser=self.build_parser(),
            banner_fn=self._make_banner(),
            run_fn=self.run_once,
            has_target=lambda a: bool(self._get_target(a)),
            prompt=self.prompt,
            description=f"{self.description.strip()} interativo.",
            example=self._example(),
            contextual_help=self._help(),
        )

    def _make_banner(self) -> Callable[[], None]:
        """Cria callable do banner. Suporta banner_fn para modulos com banner pre-existente."""
        if self.banner_fn is not None:
            return self.banner_fn
        return create_banner(self.banner_text, self.description)

    @abstractmethod
    def _example(self) -> str:
        """Exemplo de uso para o shell interativo."""
        ...

    @abstractmethod
    def _help(self) -> str:
        """Help contextual para o shell interativo."""
        ...
