"""Gerência de IPs bloqueados (permanentes e temporários) e whitelist."""
from __future__ import annotations

import threading
import time
from typing import Callable, Dict, FrozenSet, List, Optional

from .config import ConfigManager
from .logger import EventLogger
from .validation import ValidationError, normalize_ip

_MAX_TEMP_BEFORE_PRUNE = 10_000


class IPManager:
    """Bloqueios permanentes e whitelist persistem em config.json.

    Bloqueios temporários (automáticos) vivem só em memória e expiram sozinhos.
    A whitelist sempre tem prioridade sobre qualquer bloqueio.
    """

    def __init__(
        self,
        config: ConfigManager,
        logger: EventLogger,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config
        self._logger = logger
        self._clock = clock
        self._temp: Dict[str, float] = {}
        self._lock = threading.RLock()
        self._blocked_set: FrozenSet[str] = frozenset()
        self._white_set: FrozenSet[str] = frozenset()
        self._refresh()

    # --- consultas -------------------------------------------------------
    def blocked(self) -> List[str]:
        with self._lock:
            return list(self._config.settings.blocked_ips)

    def whitelisted(self) -> List[str]:
        with self._lock:
            return list(self._config.settings.whitelist)

    def is_whitelisted(self, ip: str) -> bool:
        return normalize_ip(ip) in self._white_set

    def is_permanently_blocked(self, ip: str) -> bool:
        return normalize_ip(ip) in self._blocked_set

    def temp_remaining(self, ip: str, now: Optional[float] = None) -> float:
        """Segundos restantes do bloqueio temporário (0.0 se não houver)."""
        canonical = normalize_ip(ip)
        with self._lock:
            moment = self._clock() if now is None else now
            expiry = self._temp.get(canonical)
            if expiry is None:
                return 0.0
            if expiry <= moment:
                del self._temp[canonical]
                return 0.0
            return expiry - moment

    def temp_blocks(self, now: Optional[float] = None) -> Dict[str, float]:
        with self._lock:
            moment = self._clock() if now is None else now
            self._prune(moment)
            return {ip: expiry - moment for ip, expiry in self._temp.items()}

    # --- bloqueio --------------------------------------------------------
    def block(self, ip: str) -> bool:
        """Bloqueia permanentemente. False se já estava bloqueado."""
        canonical = normalize_ip(ip)
        with self._lock:
            if canonical in self._white_set:
                raise ValidationError(
                    f"{canonical} está na whitelist; remova-o da whitelist antes de bloquear"
                )
            if canonical in self._blocked_set:
                return False
            self._config.update(blocked_ips=self._config.settings.blocked_ips + [canonical])
            self._temp.pop(canonical, None)
            self._refresh()
            self._logger.log(f"IP bloqueado: {canonical}")
            return True

    def unblock(self, ip: str) -> bool:
        """Remove bloqueio permanente e/ou temporário. False se não havia."""
        canonical = normalize_ip(ip)
        with self._lock:
            was_permanent = canonical in self._blocked_set
            if was_permanent:
                remaining = [x for x in self._config.settings.blocked_ips if x != canonical]
                self._config.update(blocked_ips=remaining)
                self._refresh()
            was_temporary = self._temp.pop(canonical, None) is not None
            if not (was_permanent or was_temporary):
                return False
            self._logger.log(f"IP desbloqueado: {canonical}")
            return True

    def temp_block(self, ip: str, seconds: int, now: Optional[float] = None) -> bool:
        """Bloqueio automático. Nunca atinge IPs da whitelist."""
        canonical = normalize_ip(ip)
        with self._lock:
            if seconds <= 0 or canonical in self._white_set or canonical in self._blocked_set:
                return False
            moment = self._clock() if now is None else now
            if len(self._temp) >= _MAX_TEMP_BEFORE_PRUNE:
                self._prune(moment)
            self._temp[canonical] = moment + seconds
            return True

    # --- whitelist -------------------------------------------------------
    def whitelist_add(self, ip: str) -> bool:
        canonical = normalize_ip(ip)
        with self._lock:
            if canonical in self._white_set:
                return False
            settings = self._config.settings
            was_blocked = canonical in self._blocked_set
            self._config.update(
                whitelist=settings.whitelist + [canonical],
                blocked_ips=[x for x in settings.blocked_ips if x != canonical],
            )
            was_blocked = self._temp.pop(canonical, None) is not None or was_blocked
            self._refresh()
            self._logger.log(f"IP adicionado à whitelist: {canonical}")
            if was_blocked:
                self._logger.log(f"Bloqueio removido ao entrar na whitelist: {canonical}")
            return True

    def whitelist_remove(self, ip: str) -> bool:
        canonical = normalize_ip(ip)
        with self._lock:
            if canonical not in self._white_set:
                return False
            remaining = [x for x in self._config.settings.whitelist if x != canonical]
            self._config.update(whitelist=remaining)
            self._refresh()
            self._logger.log(f"IP removido da whitelist: {canonical}")
            return True

    # --- internos --------------------------------------------------------
    def _refresh(self) -> None:
        settings = self._config.settings
        self._blocked_set = frozenset(settings.blocked_ips)
        self._white_set = frozenset(settings.whitelist)

    def _prune(self, moment: float) -> None:
        for ip in [ip for ip, expiry in self._temp.items() if expiry <= moment]:
            del self._temp[ip]
