#!/usr/bin/env python3
"""Gerenciador de credenciais no keyring do SO.

Permite armazenar, recuperar e gerenciar API keys e tokens de autenticacao
de forma segura usando o keyring do sistema operacional (Windows Credential
Manager, macOS Keychain, Linux SecretService).

Uso:
    mytools-cred set <nome>        — armazena uma credencial
    mytools-cred get <nome>        — recupera uma credencial
    mytools-cred delete <nome>     — remove uma credencial
    mytools-cred list              — lista credenciais salvas

Em scanners, use o prefixo @ para referenciar credenciais salvas:
    mytools attackaudit https://target.com --bearer-token @meu_token
"""
import argparse
import getpass
import sys

_SERVICE_NAME = "mytools"


def _get_keyring():  # type: ignore[no-untyped-def]
    """Retorna o modulo keyring ou None se nao disponivel."""
    try:
        import keyring

        return keyring
    except ImportError:
        return None


def _list_credentials() -> list[str]:  # type: ignore[no-untyped-def]
    """Lista todas as credenciais salvas com prefixo mytools/.

    keyring nao fornece listagem nativa, entao usamos um registro
    auxiliar para rastrear nomes de credenciais.
    """
    kr = _get_keyring()
    if kr is None:
        return []
    registry = kr.get_password(_SERVICE_NAME, "__registry__")
    if not registry:
        return []
    return sorted(registry.splitlines())


def _update_registry(name: str, add: bool = True) -> None:
    """Adiciona ou remove um nome do registro de credenciais."""
    kr = _get_keyring()
    if kr is None:
        return
    registry = kr.get_password(_SERVICE_NAME, "__registry__")
    names = set(registry.splitlines()) if registry else set()
    if add:
        names.add(name)
    else:
        names.discard(name)
    kr.set_password(_SERVICE_NAME, "__registry__", "\n".join(sorted(names)))


def set_credential(name: str, value: str | None = None) -> bool:
    """Armazena uma credencial no keyring.

    Se value nao for fornecido, solicita interativamente (sem echo).
    Retorna True em caso de sucesso.
    """
    kr = _get_keyring()
    if kr is None:
        print("Erro: keyring nao disponivel. Instale com: pip install keyring", file=sys.stderr)
        return False
    if value is None:
        value = getpass.getpass(f"Valor para '{name}': ")
    if not value:
        print("Erro: valor vazio nao pode ser armazenado.", file=sys.stderr)
        return False
    kr.set_password(_SERVICE_NAME, name, value)
    _update_registry(name, add=True)
    print(f"Credencial '{name}' armazenada com sucesso.")
    return True


def get_credential(name: str) -> str | None:
    """Recupera uma credencial do keyring. Retorna None se nao encontrada."""
    kr = _get_keyring()
    if kr is None:
        return None
    return kr.get_password(_SERVICE_NAME, name)


def delete_credential(name: str) -> bool:
    """Remove uma credencial do keyring. Retorna True em caso de sucesso."""
    kr = _get_keyring()
    if kr is None:
        print("Erro: keyring nao disponivel.", file=sys.stderr)
        return False
    existing = kr.get_password(_SERVICE_NAME, name)
    if existing is None:
        print(f"Credencial '{name}' nao encontrada.")
        return False
    kr.delete_password(_SERVICE_NAME, name)
    _update_registry(name, add=False)
    print(f"Credencial '{name}' removida com sucesso.")
    return True


def list_credentials() -> list[str]:
    """Lista nomes das credenciais salvas (sem exibir valores)."""
    names = _list_credentials()
    if not names:
        print("Nenhuma credencial salva.")
    else:
        print("Credenciais salvas:")
        for name in names:
            print(f"  - {name}")
    return names


def build_parser() -> argparse.ArgumentParser:
    """Cria o parser CLI para mytools-cred."""
    parser = argparse.ArgumentParser(
        prog="mytools-cred",
        description="Gerencia credenciais no keyring do SO.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_set = sub.add_parser("set", help="Armazena uma credencial.")
    p_set.add_argument("name", help="Nome da credencial (ex: bearer_token)")

    p_get = sub.add_parser("get", help="Recupera uma credencial.")
    p_get.add_argument("name", help="Nome da credencial")

    p_del = sub.add_parser("delete", help="Remove uma credencial.")
    p_del.add_argument("name", help="Nome da credencial")

    sub.add_parser("list", help="Lista credenciais salvas.")

    return parser


def main() -> int:
    """Ponto de entrada CLI para mytools-cred."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "set":
        return 0 if set_credential(args.name) else 1
    if args.command == "get":
        value = get_credential(args.name)
        if value is None:
            print(f"Credencial '{args.name}' nao encontrada.", file=sys.stderr)
            return 1
        print(value)
        return 0
    if args.command == "delete":
        return 0 if delete_credential(args.name) else 1
    if args.command == "list":
        list_credentials()
        return 0
    parser.print_help()
    return 1
