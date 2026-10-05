"""Interface de linha de comando (camada de apresentação).

Só conversa com o motor `AntiDDoS`; nenhuma regra de proteção vive aqui.
"""
from __future__ import annotations

import argparse
import difflib
import os
import re
import shlex
import shutil
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, TextIO

from . import __version__
from .config import (
    BLOCK_MAX,
    BLOCK_MIN,
    RATE_LIMIT_MAX,
    RATE_LIMIT_MIN,
    WINDOW_MAX,
    WINDOW_MIN,
)
from .core import AntiDDoS
from .validation import ValidationError, normalize_ip, parse_int

TITLE = "ANTI-DDoS CONTROL CENTER"
CREDIT = "Created by my TikTok profile"
MAX_INPUT_LENGTH = 512
DEFAULT_LOG_LINES = 20
MAX_LOG_LINES = 500

SHIELD = [
    r".--------------.",
    r"|   _______    |",
    r"|  /  | |  \   |",
    r"| |   | |   |  |",
    r"|  \__\_/__/   |",
    r" \            /",
    r"  \          /",
    r"   '--.  .--'",
    r"       \/",
]

HELP_ROWS = [
    ("help", "Mostra todos os comandos"),
    ("status", "Estado, limites e estatísticas"),
    ("protect on|off", "Ativa ou desativa a proteção"),
    ("limit <req> <seg>", "Define o rate limit"),
    ("blocktime <seg>", "Duração do bloqueio automático"),
    ("block <IP>", "Bloqueia um IP"),
    ("unblock <IP>", "Remove um IP do bloqueio"),
    ("whitelist add <IP>", "Adiciona IP à whitelist"),
    ("whitelist remove <IP>", "Remove IP da whitelist"),
    ("list blocked", "Lista IPs bloqueados"),
    ("list whitelist", "Lista IPs permitidos"),
    ("logs [n]", "Eventos recentes (padrão 20)"),
    ("clear", "Limpa o terminal"),
    ("banner", "Mostra o banner"),
    ("exit", "Fecha o programa"),
]

UNICODE_BOX = {"tl": "╔", "tr": "╗", "bl": "╚", "br": "╝", "h": "═", "v": "║", "rule": "─"}
ASCII_BOX = {"tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "=", "v": "|", "rule": "-"}

Handler = Callable[[List[str]], Optional[bool]]


def format_duration(seconds: float) -> str:
    total = int(max(0, seconds))
    days, rest = divmod(total, 86_400)
    hours, rest = divmod(rest, 3_600)
    minutes, secs = divmod(rest, 60)
    if days:
        return f"{days}d {hours:02d}h {minutes:02d}m"
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def _enable_windows_vt() -> bool:
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:  # noqa: BLE001 - qualquer falha significa "sem cor"
        return False


def _detect_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR") is not None or os.environ.get("TERM") == "dumb":
        return False
    isatty = getattr(stream, "isatty", None)
    if isatty is None or not isatty():
        return False
    if os.name == "nt":
        return _enable_windows_vt()
    return True


def _detect_unicode(stream: TextIO) -> bool:
    encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "").replace("_", "")
    return encoding.startswith("utf")


class Terminal:
    """Saída com cores ANSI opcionais e fallback ASCII."""

    CODES = {
        "bold": "1", "dim": "2", "red": "31", "green": "32",
        "yellow": "33", "blue": "34", "magenta": "35", "cyan": "36",
    }

    def __init__(
        self,
        stream: TextIO,
        color: Optional[bool] = None,
        unicode: Optional[bool] = None,
    ) -> None:
        self.stream = stream
        self.color = _detect_color(stream) if color is None else color
        self.unicode = _detect_unicode(stream) if unicode is None else unicode

    @property
    def box(self) -> Dict[str, str]:
        return UNICODE_BOX if self.unicode else ASCII_BOX

    @property
    def width(self) -> int:
        return shutil.get_terminal_size((80, 24)).columns

    def paint(self, text: str, *styles: str) -> str:
        if not self.color or not styles:
            return text
        codes = ";".join(self.CODES[style] for style in styles)
        return f"\033[{codes}m{text}\033[0m"

    def write(self, text: str = "") -> None:
        data = text + "\n"
        try:
            self.stream.write(data)
        except UnicodeEncodeError:
            encoding = getattr(self.stream, "encoding", None) or "ascii"
            self.stream.write(data.encode(encoding, "replace").decode(encoding))
        self.stream.flush()


class ControlCenter:
    """Loop interativo e despacho de comandos."""

    def __init__(
        self,
        engine: AntiDDoS,
        stream: Optional[TextIO] = None,
        color: Optional[bool] = None,
        unicode: Optional[bool] = None,
        use_readline: bool = False,
    ) -> None:
        self.engine = engine
        self.term = Terminal(stream or sys.stdout, color, unicode)
        self._use_readline = use_readline and self.term.color
        self._aliases = {"?": "help", "quit": "exit", "cls": "clear"}
        self._handlers: Dict[str, Handler] = {
            "help": self._cmd_help,
            "status": self._cmd_status,
            "protect": self._cmd_protect,
            "limit": self._cmd_limit,
            "blocktime": self._cmd_blocktime,
            "block": self._cmd_block,
            "unblock": self._cmd_unblock,
            "whitelist": self._cmd_whitelist,
            "list": self._cmd_list,
            "logs": self._cmd_logs,
            "clear": self._cmd_clear,
            "banner": self._cmd_banner,
            "exit": self._cmd_exit,
        }

    # --- ciclo principal -------------------------------------------------
    def run(self) -> int:
        self.show_banner()
        while True:
            try:
                line = input(self._prompt())
            except EOFError:
                self.term.write()
                break
            except KeyboardInterrupt:
                self.term.write()
                self._info("Use 'exit' para sair.")
                continue
            if not self.execute(line):
                break
        self.engine.shutdown()
        self._info("Até logo.")
        return 0

    def execute(self, line: str) -> bool:
        """Executa uma linha de comando. Retorna False quando deve encerrar."""
        if len(line) > MAX_INPUT_LENGTH:
            self._err(f"Comando longo demais (máximo {MAX_INPUT_LENGTH} caracteres)")
            return True
        try:
            tokens = shlex.split(line)
        except ValueError:
            self._err("Aspas não fechadas no comando")
            return True
        if not tokens:
            return True

        name = tokens[0].lower()
        name = self._aliases.get(name, name)
        handler = self._handlers.get(name)
        if handler is None:
            self._unknown(tokens[0])
            return True
        try:
            return handler(tokens[1:]) is not False
        except ValidationError as exc:
            self._err(str(exc))
        except OSError as exc:
            self._err(f"Erro de armazenamento: {exc.strerror or exc}")
        return True

    # --- saída -----------------------------------------------------------
    def _prompt(self) -> str:
        color = "green" if self.engine.protection_enabled else "red"
        text = f"{self.term.paint('anti-ddos', 'bold', color)} {self.term.paint('>', 'bold')} "
        if self._use_readline:
            text = re.sub(r"(\033\[[0-9;]*m)", "\001\\1\002", text)
        return text

    def _ok(self, message: str) -> None:
        self.term.write(f"{self.term.paint('[+]', 'bold', 'green')} {message}")

    def _err(self, message: str) -> None:
        self.term.write(f"{self.term.paint('[x]', 'bold', 'red')} {message}")

    def _warn(self, message: str) -> None:
        self.term.write(f"{self.term.paint('[!]', 'bold', 'yellow')} {message}")

    def _info(self, message: str) -> None:
        self.term.write(f"{self.term.paint('[*]', 'bold', 'cyan')} {message}")

    def _section(self, title: str) -> None:
        rule = self.term.box["rule"]
        width = max(24, min(self.term.width - 1, 56))
        fill = rule * max(2, width - len(title) - 4)
        self.term.write(self.term.paint(f"{rule * 2} {title} {fill}", "bold", "blue"))

    def _unknown(self, raw: str) -> None:
        shown = repr(raw[:30])
        guess = difflib.get_close_matches(raw.lower(), list(self._handlers), n=1)
        hint = f" Você quis dizer '{guess[0]}'?" if guess else " Digite 'help'."
        self._err(f"Comando desconhecido: {shown}.{hint}")

    @staticmethod
    def _expect(args: List[str], count: int, usage: str) -> None:
        if len(args) != count:
            raise ValidationError(f"Uso: {usage}")

    def show_banner(self) -> None:
        term = self.term
        box = term.box
        inner = max(32, min(46, term.width - 2))
        for line in SHIELD:
            term.write(term.paint(line.center(inner + 2).rstrip(), "cyan"))
        term.write(term.paint(box["tl"] + box["h"] * inner + box["tr"], "cyan"))
        for text in (TITLE, "", CREDIT):
            left = (inner - len(text)) // 2
            right = inner - len(text) - left
            styled = term.paint(text, "bold", "cyan") if text == TITLE else term.paint(text, "dim")
            edge = term.paint(box["v"], "cyan")
            term.write(f"{edge}{' ' * left}{styled}{' ' * right}{edge}")
        term.write(term.paint(box["bl"] + box["h"] * inner + box["br"], "cyan"))
        term.write()
        if self.engine.protection_enabled:
            state = term.paint("PROTECTED", "bold", "green")
        else:
            state = term.paint("UNPROTECTED", "bold", "red")
        term.write(f"STATUS: {state}")
        term.write()
        term.write(term.paint("Digite 'help' para ver os comandos.", "dim"))

    # --- comandos --------------------------------------------------------
    def _cmd_help(self, args: List[str]) -> None:
        self._expect(args, 0, "help")
        self._section("Comandos")
        wide = self.term.width >= 56
        for usage, description in HELP_ROWS:
            if wide:
                self.term.write(f"  {self.term.paint(usage.ljust(24), 'cyan')} {description}")
            else:
                self.term.write(f"  {self.term.paint(usage, 'cyan')}")
                self.term.write(f"      {self.term.paint(description, 'dim')}")

    def _cmd_status(self, args: List[str]) -> None:
        self._expect(args, 0, "status")
        settings = self.engine.config.settings
        stats = self.engine.stats()
        protection = (
            self.term.paint("ON", "bold", "green")
            if settings.protection
            else self.term.paint("OFF", "bold", "red")
        )
        auto_block = f"{settings.block_seconds} s" if settings.block_seconds else "desativado"
        rows = [
            ("Proteção", protection),
            ("Limite atual", f"{settings.rate_limit} requisições"),
            ("Janela de tempo", f"{settings.window_seconds} s"),
            ("Bloqueio automático", auto_block),
            (
                "IPs bloqueados",
                f"{stats.blocked_total} (perm.: {stats.blocked_permanent}, "
                f"temp.: {stats.blocked_temporary})",
            ),
            ("IPs na whitelist", str(len(settings.whitelist))),
            ("Requisições observadas", str(stats.requests_observed)),
            ("Eventos detectados", str(stats.events_detected)),
            ("Uptime", format_duration(stats.uptime_seconds)),
        ]
        self._section("Status")
        pad = max(len(label) for label, _ in rows)
        for label, value in rows:
            self.term.write(f"  {self.term.paint(label.ljust(pad), 'dim')} : {value}")
        self._section("Arquivos")
        self.term.write(f"  {self.term.paint('Configuração', 'dim')}:")
        self.term.write(f"    {self.engine.config.config_path}")
        self.term.write(f"  {self.term.paint('Log de eventos', 'dim')}:")
        self.term.write(f"    {self.engine.logger.path}")
        if self.engine.logger.last_error:
            self._warn(f"Falha ao gravar o log: {self.engine.logger.last_error}")

    def _cmd_protect(self, args: List[str]) -> None:
        self._expect(args, 1, "protect on|off")
        choice = args[0].lower()
        if choice not in ("on", "off"):
            raise ValidationError("Uso: protect on|off")
        enabled = choice == "on"
        if self.engine.set_protection(enabled):
            self._ok("Proteção ativada" if enabled else "Proteção desativada")
        else:
            self._info(f"A proteção já estava {'ativada' if enabled else 'desativada'}")

    def _cmd_limit(self, args: List[str]) -> None:
        self._expect(args, 2, "limit <requisições> <segundos>")
        requests = parse_int(args[0], "Requisições", RATE_LIMIT_MIN, RATE_LIMIT_MAX)
        seconds = parse_int(args[1], "Segundos", WINDOW_MIN, WINDOW_MAX)
        self.engine.set_limit(requests, seconds)
        self._ok(f"Rate limit definido: {requests} requisições por janela de {seconds}s")

    def _cmd_blocktime(self, args: List[str]) -> None:
        self._expect(args, 1, "blocktime <segundos>  (0 desativa o bloqueio automático)")
        seconds = parse_int(args[0], "Segundos", BLOCK_MIN, BLOCK_MAX)
        self.engine.set_block_seconds(seconds)
        if seconds:
            self._ok(f"Bloqueio automático: {seconds}s")
        else:
            self._ok("Bloqueio automático desativado (excessos continuam sendo recusados)")

    def _cmd_block(self, args: List[str]) -> None:
        self._expect(args, 1, "block <IP>")
        ip = normalize_ip(args[0])
        if self.engine.ips.block(ip):
            self._ok(f"IP bloqueado: {ip}")
        else:
            self._warn(f"{ip} já estava bloqueado")

    def _cmd_unblock(self, args: List[str]) -> None:
        self._expect(args, 1, "unblock <IP>")
        ip = normalize_ip(args[0])
        if self.engine.ips.unblock(ip):
            self._ok(f"IP desbloqueado: {ip}")
        else:
            self._warn(f"{ip} não está bloqueado")

    def _cmd_whitelist(self, args: List[str]) -> None:
        if len(args) != 2 or args[0].lower() not in ("add", "remove"):
            raise ValidationError("Uso: whitelist add|remove <IP>")
        ip = normalize_ip(args[1])
        if args[0].lower() == "add":
            if self.engine.ips.whitelist_add(ip):
                self._ok(f"IP adicionado à whitelist: {ip}")
            else:
                self._warn(f"{ip} já está na whitelist")
        elif self.engine.ips.whitelist_remove(ip):
            self._ok(f"IP removido da whitelist: {ip}")
        else:
            self._warn(f"{ip} não está na whitelist")

    def _cmd_list(self, args: List[str]) -> None:
        if len(args) != 1 or args[0].lower() not in ("blocked", "whitelist"):
            raise ValidationError("Uso: list blocked|whitelist")
        if args[0].lower() == "blocked":
            self._list_blocked()
        else:
            self._list_whitelist()

    def _list_blocked(self) -> None:
        permanent = self.engine.ips.blocked()
        temporary = sorted(self.engine.ips.temp_blocks().items())
        if not permanent and not temporary:
            self._info("Nenhum IP bloqueado.")
            return
        self._section("IPs bloqueados")
        index = 0
        for ip in permanent:
            index += 1
            self.term.write(f"  {index:>3}. {ip}  {self.term.paint('permanente', 'red')}")
        for ip, remaining in temporary:
            index += 1
            note = f"temporário (restam {format_duration(remaining)})"
            self.term.write(f"  {index:>3}. {ip}  {self.term.paint(note, 'yellow')}")

    def _list_whitelist(self) -> None:
        addresses = self.engine.ips.whitelisted()
        if not addresses:
            self._info("A whitelist está vazia.")
            return
        self._section("Whitelist")
        for index, ip in enumerate(addresses, 1):
            self.term.write(f"  {index:>3}. {self.term.paint(ip, 'green')}")

    def _cmd_logs(self, args: List[str]) -> None:
        if len(args) > 1:
            raise ValidationError("Uso: logs [quantidade]")
        count = DEFAULT_LOG_LINES
        if args:
            count = parse_int(args[0], "Quantidade", 1, MAX_LOG_LINES)
        lines = self.engine.logger.tail(count)
        if not lines:
            self._info("Nenhum evento registrado.")
            return
        self._section(f"Últimos {len(lines)} eventos")
        for line in lines:
            self.term.write("  " + self._style_log_line(line))

    def _style_log_line(self, line: str) -> str:
        stamp, sep, message = line.partition("] ")
        if not (sep and stamp.startswith("[")):
            return line
        style = ()
        lowered = message.lower()
        if "excesso" in lowered:
            style = ("red",)
        elif "bloqueado" in lowered or "desativada" in lowered:
            style = ("yellow",)
        elif "ativada" in lowered or "whitelist" in lowered or "desbloqueado" in lowered:
            style = ("green",)
        return f"{self.term.paint(stamp + ']', 'dim')} {self.term.paint(message, *style)}"

    def _cmd_clear(self, args: List[str]) -> None:
        self._expect(args, 0, "clear")
        if self.term.color:
            self.term.stream.write("\033[H\033[2J\033[3J")
            self.term.stream.flush()
        else:
            self.term.write("\n" * 40)

    def _cmd_banner(self, args: List[str]) -> None:
        self._expect(args, 0, "banner")
        self.show_banner()

    def _cmd_exit(self, args: List[str]) -> bool:
        self._expect(args, 0, "exit")
        return False


def _setup_readline() -> bool:
    try:
        import readline  # noqa: F401  (histórico e edição de linha)
    except ImportError:
        return False
    return True


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="anti_ddos.py",
        description="Anti-DDoS Control Center: central de proteção defensiva.",
    )
    parser.add_argument("--data-dir", type=Path, default=None,
                        help="pasta de dados (padrão: ~/.anti_ddos_center)")
    parser.add_argument("--no-color", action="store_true", help="desativa cores ANSI")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    try:
        engine = AntiDDoS(data_dir=args.data_dir)
    except OSError as exc:
        print(f"Erro: não foi possível preparar a pasta de dados: {exc}", file=sys.stderr)
        return 1

    center = ControlCenter(
        engine,
        color=False if args.no_color else None,
        use_readline=_setup_readline(),
    )
    return center.run()
