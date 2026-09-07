#!/usr/bin/env python3
"""Attack Analysis — Visualização de caminhos de ataque e sugestão de exploits.

Gera grafos de ataque baseados em findings de segurança:
  - Attack path: grafo direcionado mostrando vetores de ataque
  - Exploit suggest: consolida exploits de todos os findings
  - Exporta PNG/SVG via matplotlib e DOT format (graphviz)
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import matplotlib
import networkx as nx

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_banner,
    print_exploit_info,
    print_json,
    run_main_loop,
    write_output,
)

logger = logging.getLogger("mytools.attackanalysis")

_BANNER_LINES: str = (
    "     _        _       _           _   \n"
    "    / \\   ___| |_ ___| |__   __ _| |_ \n"
    "   / _ \\ / __| __/ __| '_ \\ / _` | __|\n"
    "  / ___ \\ (__| || (__| | | | (_| | |_ \n"
    " /_/   \\_\\___|\\__\\___|_| |_|\\__,_|\\__|\n"
)

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#ff4444",
    "high": "#ff8800",
    "medium": "#ffcc00",
    "low": "#4488ff",
    "info": "#888888",
}


@dataclass(frozen=True, slots=True)
class AttackNode:
    """Nó no grafo de ataque."""

    id: str
    label: str
    severity: str
    category: str
    module: str
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class AttackEdge:
    """Aresta no grafo de ataque."""

    source: str
    target: str
    relationship: str


@dataclass(frozen=True, slots=True)
class AttackGraph:
    """Grafo de ataque completo."""

    nodes: list[AttackNode]
    edges: list[AttackEdge]
    target: str
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int


def build_graph(findings: list[dict[str, Any]], target: str) -> AttackGraph:
    """Constrói grafo de ataque a partir de findings."""
    nodes: list[AttackNode] = []
    edges: list[AttackEdge] = []
    severity_counts: dict[str, int] = {s: 0 for s in _SEVERITY_COLORS}
    by_category: dict[str, list[str]] = {}

    for i, finding in enumerate(findings):
        severity = finding.get("severity", "info")
        category = finding.get("category", "unknown")
        item = finding.get("item", f"finding_{i}")
        exploit = finding.get("exploit", "")

        node_id = f"vuln_{i}"
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        by_category.setdefault(category, []).append(node_id)

        nodes.append(
            AttackNode(
                id=node_id,
                label=f"{item}\n({severity})",
                severity=severity,
                category=category,
                module=item,
                exploit=exploit,
            )
        )

    for members in by_category.values():
        edges.extend(
            AttackEdge(
                source=members[i],
                target=members[j],
                relationship="same_category",
            )
            for i in range(len(members))
            for j in range(i + 1, len(members))
        )

    return AttackGraph(
        nodes=nodes,
        edges=edges,
        target=target,
        total_vulnerabilities=len(findings),
        critical_count=severity_counts.get("critical", 0),
        high_count=severity_counts.get("high", 0),
        medium_count=severity_counts.get("medium", 0),
        low_count=severity_counts.get("low", 0),
        info_count=severity_counts.get("info", 0),
    )


def render_png(graph: AttackGraph, output_path: str) -> None:
    """Renderiza grafo como PNG."""
    G = _build_nx_graph(graph)
    _draw_graph(G, graph, output_path, "png")


def render_svg(graph: AttackGraph, output_path: str) -> None:
    """Renderiza grafo como SVG."""
    G = _build_nx_graph(graph)
    _draw_graph(G, graph, output_path, "svg")


def export_dot(graph: AttackGraph, output_path: str) -> None:
    """Exporta grafo em formato DOT (Graphviz)."""
    G = _build_nx_graph(graph)
    dot_lines = ["digraph AttackGraph {", "  rankdir=LR;", "  node [shape=box];"]
    for node_id, data in G.nodes(data=True):
        label = data.get("label", node_id).replace("\n", "\\n")
        color_val = _SEVERITY_COLORS.get(data.get("severity", "info"), "#888888")
        dot_lines.append(
            f'  "{node_id}" [label="{label}" style=filled fillcolor="{color_val}"];'
        )
    for source, target_val, data in G.edges(data=True):
        rel = data.get("relationship", "")
        dot_lines.append(f'  "{source}" -> "{target_val}" [label="{rel}"];')
    dot_lines.append("}")
    Path(output_path).write_text("\n".join(dot_lines), encoding="utf-8")


def _build_nx_graph(graph: AttackGraph) -> nx.DiGraph:
    """Constrói networkx DiGraph a partir de AttackGraph."""
    G = nx.DiGraph()
    for node in graph.nodes:
        G.add_node(
            node.id,
            label=node.label,
            severity=node.severity,
            category=node.category,
            module=node.module,
            exploit=node.exploit,
        )
    for edge in graph.edges:
        G.add_edge(edge.source, edge.target, relationship=edge.relationship)
    return G


def _draw_graph(G: nx.DiGraph, graph: AttackGraph, output_path: str, fmt: str) -> None:
    """Desenha grafo com matplotlib."""
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)
    node_colors = []
    for node_id in G.nodes():
        severity = G.nodes[node_id].get("severity", "info")
        node_colors.append(_SEVERITY_COLORS.get(severity, "#888888"))
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=2000, alpha=0.9)
    nx.draw_networkx_labels(G, pos, font_size=8, font_weight="bold")
    nx.draw_networkx_edges(G, pos, edge_color="#666666", arrows=True, arrowsize=20)
    edge_labels = nx.get_edge_attributes(G, "relationship")
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=6)
    plt.title(f"Attack Path — {graph.target}", fontsize=14, fontweight="bold")
    plt.legend(
        handles=[
            Line2D(
                [0],
                [0],
                marker="o",
                color="w",
                markerfacecolor=c,
                markersize=10,
                label=s.title(),
            )
            for s, c in _SEVERITY_COLORS.items()
        ],
        loc="upper left",
    )
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(output_path, format=fmt, dpi=150, bbox_inches="tight")
    plt.close()


_EXPLOIT_TOOLS: tuple[tuple[str, str], ...] = (
    ("sqlmap", "sqlmap"),
    ("sql", "sqlmap"),
    ("xsstrike", "XSStrike"),
    ("xss", "XSStrike"),
    ("wfuzz", "wfuzz"),
    ("ffuf", "ffuf"),
    ("gobuster", "gobuster"),
    ("nuclei", "nuclei"),
    ("ysoserial", "ysoserial"),
    ("metasploit", "msfconsole"),
    ("nmap", "nmap"),
    ("hydra", "hydra"),
    ("jwt", "jwt_tool"),
    ("ssti", "tplmap"),
    ("ssrf", "ssrfmap"),
    ("xxe", "xxe-injector"),
    ("graphql", "graphql-playground"),
    ("curl", "curl"),
)

_DEFAULT_EXPLOIT_TOOL = "curl"


def _suggest_tool(finding: dict[str, Any], exploit: str) -> str:
    """Sugere ferramenta para o exploit: preferencia ao 'tool' do finding."""
    tool = finding.get("tool", "")
    if tool:
        return tool
    exploit_lower = exploit.lower()
    for keyword, tool_name in _EXPLOIT_TOOLS:
        if keyword in exploit_lower:
            return tool_name
    return _DEFAULT_EXPLOIT_TOOL


def suggest_exploits(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Consolida exploits de todos os findings."""
    exploits = []
    for finding in findings:
        exploit = finding.get("exploit", "")
        if exploit:
            exploits.append(
                {
                    "module": finding.get("item", "unknown"),
                    "severity": finding.get("severity", "info"),
                    "exploit": exploit,
                    "tool": _suggest_tool(finding, exploit),
                }
            )
    return exploits


def print_results(graph: AttackGraph, exploits: list[dict[str, str]]) -> None:
    """Imprime resultados da análise."""
    print()
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Attack Analysis")
    print(color("[*]", Cyber.CYAN), f"Target: {graph.target}")
    print()
    print(
        color("[*]", Cyber.CYAN),
        f"Total vulnerabilities: {graph.total_vulnerabilities}",
    )
    if graph.critical_count:
        print(color("    [-]", Cyber.RED), f"Critical: {graph.critical_count}")
    if graph.high_count:
        print(color("    [-]", Cyber.RED), f"High: {graph.high_count}")
    if graph.medium_count:
        print(color("    [-]", Cyber.YELLOW), f"Medium: {graph.medium_count}")
    if graph.low_count:
        print(color("    [-]", Cyber.CYAN), f"Low: {graph.low_count}")
    if graph.info_count:
        print(color("    [-]", Cyber.GREEN), f"Info: {graph.info_count}")
    print()
    if exploits:
        print(
            color("[!]", Cyber.RED, Cyber.BOLD),
            f"Suggested exploits ({len(exploits)}):",
        )
        for exp in exploits:
            print(color("    [-]", Cyber.RED), f"[{exp['severity']}] {exp['module']}")
            print(color("        ->", Cyber.YELLOW), exp["exploit"])
            print_exploit_info(exp["exploit"], exp["tool"])
    else:
        print(color("[+]", Cyber.GREEN), "No exploits suggested")
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mytools-analysis",
        description="Attack Analysis — Visualização de caminhos de ataque",
    )
    parser.add_argument(
        "findings_file", help="Arquivo JSON com findings (output de attackaudit)"
    )
    parser.add_argument(
        "--target", default="unknown", help="Target label (default: unknown)"
    )
    parser.add_argument("--png", help="Caminho para salvar PNG")
    parser.add_argument("--svg", help="Caminho para salvar SVG")
    parser.add_argument("--dot", help="Caminha para salvar DOT")
    parser.add_argument(
        "--exploits-only", action="store_true", help="Mostrar apenas exploits"
    )
    add_common_args(parser, "web")
    return parser


def run_once(args: argparse.Namespace) -> int:
    findings_file = Path(args.findings_file)
    if not findings_file.exists():
        logger.error("arquivo não encontrado: %s", findings_file)
        return 1
    try:
        findings = json.loads(findings_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        logger.error("JSON inválido: %s", e)
        return 1
    if not isinstance(findings, list):
        findings = [findings]
    target = str(getattr(args, "target", "unknown"))
    graph = build_graph(findings, target)
    exploits = suggest_exploits(findings)
    if getattr(args, "json_output", False):
        print_json({"graph": asdict(graph), "exploits": exploits})
    else:
        print_results(graph, exploits)
    output = getattr(args, "output", None)
    if output:
        data = {
            "target": graph.target,
            "total_vulnerabilities": graph.total_vulnerabilities,
            "critical": graph.critical_count,
            "high": graph.high_count,
            "medium": graph.medium_count,
            "low": graph.low_count,
            "info": graph.info_count,
            "exploits": exploits,
        }
        write_output(output, data)
    png_path = getattr(args, "png", None)
    if png_path:
        render_png(graph, png_path)
        logger.info("PNG salvo: %s", png_path)
    svg_path = getattr(args, "svg", None)
    if svg_path:
        render_svg(graph, svg_path)
        logger.info("SVG salvo: %s", svg_path)
    dot_path = getattr(args, "dot", None)
    if dot_path:
        export_dot(graph, dot_path)
        logger.info("DOT salvo: %s", dot_path)
    return 1 if graph.critical_count or graph.high_count else 0


def main() -> int:
    return run_main_loop(
        parser=build_parser(),
        banner_fn=create_banner(_BANNER_LINES, "Attack Analysis"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "findings_file", None)),
        prompt="analysis> ",
        description="Attack Analysis — Visualização de caminhos de ataque",
        example="mytools-analysis findings.json --png attack_path.png",
        contextual_help="analysis: attack_path, exploit_suggest, DOT/PNG/SVG export",
    )


if __name__ == "__main__":
    raise SystemExit(main())
