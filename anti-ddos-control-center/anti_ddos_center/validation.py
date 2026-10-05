"""Validação de entradas: único ponto de confiança para dados externos."""
from __future__ import annotations

import ipaddress


class ValidationError(ValueError):
    """Erro de entrada do usuário, seguro para exibir na interface."""


def _preview(text: str) -> str:
    # repr() escapa caracteres de controle, evitando injeção de ANSI no terminal.
    return repr(text[:40])


def normalize_ip(value: object) -> str:
    """Devolve a forma canônica de um IPv4/IPv6 ou levanta ValidationError."""
    if not isinstance(value, str):
        raise ValidationError("O IP deve ser um texto")
    text = value.strip()
    if not text or len(text) > 45 or "%" in text:
        raise ValidationError(f"Endereço IP inválido: {_preview(text)}")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        raise ValidationError(f"Endereço IP inválido: {_preview(text)}") from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


def parse_int(value: str, name: str, minimum: int, maximum: int) -> int:
    """Converte texto em inteiro ASCII dentro de [minimum, maximum]."""
    text = value.strip()
    if not (text.isascii() and text.isdigit()):
        raise ValidationError(f"{name} deve ser um número inteiro positivo")
    if len(text) > 12 or not minimum <= int(text) <= maximum:
        raise ValidationError(f"{name} deve estar entre {minimum} e {maximum}")
    return int(text)
