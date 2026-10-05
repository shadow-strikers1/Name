"""Configuração persistente com validação e recuperação de arquivos corrompidos."""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .validation import ValidationError, normalize_ip

APP_DIR_NAME = ".anti_ddos_center"
ENV_DATA_DIR = "ANTI_DDOS_HOME"
CONFIG_FILE = "config.json"
LOG_FILE = "events.log"

RATE_LIMIT_MIN, RATE_LIMIT_MAX = 1, 1_000_000
WINDOW_MIN, WINDOW_MAX = 1, 86_400
BLOCK_MIN, BLOCK_MAX = 0, 604_800  # 0 desativa o bloqueio temporário automático
DEFAULT_WHITELIST: Tuple[str, ...] = ("127.0.0.1", "::1")

_INT_FIELDS = (
    ("rate_limit", RATE_LIMIT_MIN, RATE_LIMIT_MAX),
    ("window_seconds", WINDOW_MIN, WINDOW_MAX),
    ("block_seconds", BLOCK_MIN, BLOCK_MAX),
)


def default_data_dir() -> Path:
    override = os.environ.get(ENV_DATA_DIR)
    if override:
        return Path(override).expanduser()
    return Path.home() / APP_DIR_NAME


def _valid_int(value: Any, low: int, high: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def _clean_ip_list(raw: Any, name: str, warnings: List[str]) -> Optional[List[str]]:
    if not isinstance(raw, list):
        warnings.append(f"campo '{name}' ausente ou inválido; valor padrão restaurado")
        return None
    cleaned: List[str] = []
    for item in raw:
        try:
            ip = normalize_ip(item)
        except ValidationError:
            warnings.append(f"entrada inválida removida de '{name}'")
            continue
        if ip not in cleaned:
            cleaned.append(ip)
    return cleaned


@dataclass
class Settings:
    protection: bool = True
    rate_limit: int = 60
    window_seconds: int = 60
    block_seconds: int = 600
    blocked_ips: List[str] = field(default_factory=list)
    whitelist: List[str] = field(default_factory=lambda: list(DEFAULT_WHITELIST))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protection": self.protection,
            "rate_limit": self.rate_limit,
            "window_seconds": self.window_seconds,
            "block_seconds": self.block_seconds,
            "blocked_ips": list(self.blocked_ips),
            "whitelist": list(self.whitelist),
        }

    @classmethod
    def from_raw(cls, raw: Any) -> Tuple["Settings", List[str]]:
        """Valida dados lidos do disco; campos inválidos voltam ao padrão."""
        if not isinstance(raw, dict):
            raise ValidationError("a configuração deve ser um objeto JSON")
        settings = cls()
        defaults = cls()
        warnings: List[str] = []

        if isinstance(raw.get("protection"), bool):
            settings.protection = raw["protection"]
        else:
            warnings.append("campo 'protection' ausente ou inválido; padrão restaurado")

        for name, low, high in _INT_FIELDS:
            value = raw.get(name)
            if _valid_int(value, low, high):
                setattr(settings, name, value)
            else:
                default = getattr(defaults, name)
                warnings.append(f"campo '{name}' ausente ou inválido; padrão {default} restaurado")

        blocked = _clean_ip_list(raw.get("blocked_ips"), "blocked_ips", warnings)
        whitelist = _clean_ip_list(raw.get("whitelist"), "whitelist", warnings)
        if blocked is not None:
            settings.blocked_ips = blocked
        if whitelist is not None:
            settings.whitelist = whitelist

        conflicts = [ip for ip in settings.blocked_ips if ip in settings.whitelist]
        if conflicts:
            settings.blocked_ips = [ip for ip in settings.blocked_ips if ip not in conflicts]
            warnings.append("IPs da whitelist removidos da lista de bloqueio (whitelist tem prioridade)")
        return settings, warnings


class ConfigManager:
    """Carrega, valida e grava config.json de forma atômica."""

    def __init__(self, data_dir: Optional[Path] = None) -> None:
        self.data_dir = Path(data_dir).expanduser() if data_dir else default_data_dir()
        self.config_path = self.data_dir / CONFIG_FILE
        self.log_path = self.data_dir / LOG_FILE
        self.settings = Settings()
        self.warnings: List[str] = []
        self._lock = threading.RLock()

    def load(self) -> Settings:
        with self._lock:
            self.warnings = []
            self._ensure_dir()
            if not self.config_path.exists():
                self.settings = Settings()
                self._try_save()
                return self.settings
            try:
                raw = json.loads(self.config_path.read_text(encoding="utf-8"))
                settings, problems = Settings.from_raw(raw)
            except (OSError, ValueError, RecursionError) as exc:
                self._quarantine()
                self.warnings.append(
                    f"configuração ilegível ({type(exc).__name__}); nova configuração criada"
                )
                self.settings = Settings()
                self._try_save()
                return self.settings
            self.settings = settings
            if problems:
                self.warnings.extend(problems)
                self._try_save()
            return self.settings

    def save(self) -> None:
        with self._lock:
            self._ensure_dir()
            payload = json.dumps(self.settings.to_dict(), indent=4, ensure_ascii=False) + "\n"
            tmp = self.config_path.with_name(CONFIG_FILE + ".tmp")
            try:
                with tmp.open("w", encoding="utf-8") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, self.config_path)
            except OSError:
                try:
                    tmp.unlink()
                except OSError:
                    pass
                raise
            try:
                os.chmod(self.config_path, 0o600)
            except OSError:
                pass

    def update(self, **changes: Any) -> None:
        """Altera campos e grava; em caso de falha de disco, desfaz a alteração."""
        with self._lock:
            previous: Dict[str, Any] = {}
            for name in changes:
                if not hasattr(self.settings, name):
                    raise AttributeError(f"campo de configuração desconhecido: {name}")
                previous[name] = getattr(self.settings, name)
            for name, value in changes.items():
                setattr(self.settings, name, list(value) if isinstance(value, list) else value)
            try:
                self.save()
            except OSError:
                for name, value in previous.items():
                    setattr(self.settings, name, value)
                raise

    def _ensure_dir(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.data_dir, 0o700)
        except OSError:
            pass

    def _try_save(self) -> None:
        try:
            self.save()
        except OSError as exc:
            self.warnings.append(f"não foi possível gravar a configuração: {exc.strerror or exc}")

    def _quarantine(self) -> None:
        backup = self.config_path.with_name(f"{CONFIG_FILE}.corrupt-{int(time.time())}")
        try:
            os.replace(self.config_path, backup)
        except OSError:
            pass
