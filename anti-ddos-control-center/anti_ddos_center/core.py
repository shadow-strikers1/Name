"""Motor de proteção: une configuração, IPs, rate limiting e logs.

Integração futura (servidor/site/API): chame `AntiDDoS.check_request(ip)` a cada
requisição recebida e responda 429/403 quando `verdict.allowed` for False.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, Optional

from .config import (
    BLOCK_MAX,
    BLOCK_MIN,
    RATE_LIMIT_MAX,
    RATE_LIMIT_MIN,
    WINDOW_MAX,
    WINDOW_MIN,
    ConfigManager,
)
from .ip_manager import IPManager
from .logger import EventLogger
from .rate_limiter import RateLimiter, RateResult
from .validation import ValidationError, normalize_ip

_MAX_SUSPECTS = 10_000
_MAX_LOG_THROTTLE_ENTRIES = 10_000


class Reason(str, Enum):
    ALLOWED = "allowed"
    WHITELISTED = "whitelisted"
    PROTECTION_OFF = "protection_off"
    BLOCKED = "blocked"
    TEMP_BLOCKED = "temp_blocked"
    RATE_LIMITED = "rate_limited"
    INVALID_IP = "invalid_ip"


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: Reason
    ip: str
    retry_after: float = 0.0


@dataclass(frozen=True)
class Stats:
    requests_observed: int
    events_detected: int
    blocked_permanent: int
    blocked_temporary: int
    uptime_seconds: float

    @property
    def blocked_total(self) -> int:
        return self.blocked_permanent + self.blocked_temporary


class AntiDDoS:
    """Fachada do motor defensivo. Thread-safe."""

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._clock = clock
        self._lock = threading.RLock()
        self.config = ConfigManager(data_dir)
        self.config.load()
        self.logger = EventLogger(self.config.log_path)
        self.ips = IPManager(self.config, self.logger, clock)
        settings = self.config.settings
        self.limiter = RateLimiter(settings.rate_limit, settings.window_seconds, clock)
        self._started = clock()
        self._requests = 0
        self._events = 0
        self._suspects: Dict[str, int] = {}
        self._last_excess_log: Dict[str, float] = {}

        for warning in self.config.warnings:
            self.logger.log(f"Aviso de configuração: {warning}")
        self.logger.log("Central iniciada")

    # --- controles -------------------------------------------------------
    @property
    def protection_enabled(self) -> bool:
        return self.config.settings.protection

    def set_protection(self, enabled: bool) -> bool:
        """Liga/desliga a proteção. False se já estava no estado pedido."""
        with self._lock:
            if self.config.settings.protection == enabled:
                return False
            self.config.update(protection=enabled)
            self.logger.log("Proteção ativada" if enabled else "Proteção desativada")
            return True

    def set_limit(self, requests: int, seconds: int) -> None:
        if not (RATE_LIMIT_MIN <= requests <= RATE_LIMIT_MAX):
            raise ValidationError(f"Requisições deve estar entre {RATE_LIMIT_MIN} e {RATE_LIMIT_MAX}")
        if not (WINDOW_MIN <= seconds <= WINDOW_MAX):
            raise ValidationError(f"Segundos deve estar entre {WINDOW_MIN} e {WINDOW_MAX}")
        with self._lock:
            self.config.update(rate_limit=requests, window_seconds=seconds)
            self.limiter.configure(requests, seconds)
            self.logger.log(f"Rate limit alterado: {requests} requisições por {seconds}s")

    def set_block_seconds(self, seconds: int) -> None:
        if not (BLOCK_MIN <= seconds <= BLOCK_MAX):
            raise ValidationError(f"Segundos deve estar entre {BLOCK_MIN} e {BLOCK_MAX}")
        with self._lock:
            self.config.update(block_seconds=seconds)
            self.logger.log(f"Duração do bloqueio automático alterada: {seconds}s")

    # --- decisão por requisição -----------------------------------------
    def check_request(self, ip: str) -> Verdict:
        """Avalia uma requisição vinda de `ip`. Ordem de prioridade:

        whitelist > proteção desligada > bloqueio permanente > bloqueio
        temporário > rate limit.
        """
        try:
            canonical = normalize_ip(ip)
        except ValidationError:
            return Verdict(False, Reason.INVALID_IP, "")

        with self._lock:
            now = self._clock()
            self._requests += 1
            if self.ips.is_whitelisted(canonical):
                return Verdict(True, Reason.WHITELISTED, canonical)
            if not self.config.settings.protection:
                return Verdict(True, Reason.PROTECTION_OFF, canonical)
            if self.ips.is_permanently_blocked(canonical):
                return Verdict(False, Reason.BLOCKED, canonical)
            remaining = self.ips.temp_remaining(canonical, now)
            if remaining > 0:
                return Verdict(False, Reason.TEMP_BLOCKED, canonical, remaining)

            result = self.limiter.hit(canonical, now)
            if result.allowed:
                return Verdict(True, Reason.ALLOWED, canonical)
            return self._handle_excess(canonical, result, now)

    def _handle_excess(self, ip: str, result: RateResult, now: float) -> Verdict:
        self._events += 1
        self._mark_suspect(ip)
        block_seconds = self.config.settings.block_seconds
        blocked = self.ips.temp_block(ip, block_seconds, now)
        if blocked:
            self.limiter.reset(ip)

        if self._should_log_excess(ip, now):
            message = (
                f"Excesso de requisições detectado: {ip} "
                f"({result.count}/{result.limit} em {int(self.limiter.window_seconds)}s)"
            )
            if blocked:
                message += f" - bloqueio temporário de {block_seconds}s"
            self.logger.log(message)

        retry = float(block_seconds) if blocked else result.retry_after
        return Verdict(False, Reason.RATE_LIMITED, ip, retry)

    def _should_log_excess(self, ip: str, now: float) -> bool:
        """Evita encher o log: no máximo uma linha por IP a cada janela."""
        last = self._last_excess_log.get(ip)
        if last is not None and now - last < self.limiter.window_seconds:
            return False
        if len(self._last_excess_log) >= _MAX_LOG_THROTTLE_ENTRIES:
            self._last_excess_log.clear()
        self._last_excess_log[ip] = now
        return True

    def _mark_suspect(self, ip: str) -> None:
        if ip not in self._suspects and len(self._suspects) >= _MAX_SUSPECTS:
            self._suspects.pop(next(iter(self._suspects)))
        self._suspects[ip] = self._suspects.get(ip, 0) + 1

    # --- observabilidade -------------------------------------------------
    def suspects(self) -> Dict[str, int]:
        """IPs que excederam o limite nesta sessão -> nº de violações."""
        with self._lock:
            return dict(self._suspects)

    def stats(self) -> Stats:
        with self._lock:
            now = self._clock()
            return Stats(
                requests_observed=self._requests,
                events_detected=self._events,
                blocked_permanent=len(self.ips.blocked()),
                blocked_temporary=len(self.ips.temp_blocks(now)),
                uptime_seconds=max(0.0, now - self._started),
            )

    def shutdown(self) -> None:
        self.logger.log("Central encerrada")
