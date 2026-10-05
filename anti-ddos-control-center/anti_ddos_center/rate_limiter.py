"""Rate limiting por IP com janela deslizante, 100% em memória."""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Dict, Optional


@dataclass(frozen=True)
class RateResult:
    allowed: bool
    count: int          # requisições na janela, contando a atual
    limit: int
    retry_after: float  # segundos até liberar uma vaga (0 se permitido)


class RateLimiter:
    """IP -> timestamps das requisições dentro da janela.

    Requisições acima do limite NÃO são registradas, então a memória por IP
    fica limitada a `limit` timestamps mesmo sob flood.
    """

    def __init__(
        self,
        limit: int,
        window_seconds: int,
        clock: Callable[[], float] = time.monotonic,
        max_tracked: int = 100_000,
    ) -> None:
        self._check(limit, window_seconds)
        self._limit = limit
        self._window = float(window_seconds)
        self._clock = clock
        self._max_tracked = max_tracked
        self._hits: Dict[str, Deque[float]] = {}
        self._last_sweep = clock()
        self._lock = threading.Lock()

    @staticmethod
    def _check(limit: int, window_seconds: int) -> None:
        if limit < 1 or window_seconds < 1:
            raise ValueError("limit e window_seconds devem ser >= 1")

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def window_seconds(self) -> float:
        return self._window

    def configure(self, limit: int, window_seconds: int) -> None:
        self._check(limit, window_seconds)
        with self._lock:
            self._limit = limit
            self._window = float(window_seconds)

    def hit(self, ip: str, now: Optional[float] = None) -> RateResult:
        with self._lock:
            moment = self._clock() if now is None else now
            self._sweep_if_due(moment)
            queue = self._hits.get(ip)
            if queue is None:
                queue = self._hits[ip] = deque()
            self._expire(queue, moment)
            if len(queue) >= self._limit:
                retry = max(0.0, queue[0] + self._window - moment)
                return RateResult(False, len(queue) + 1, self._limit, retry)
            queue.append(moment)
            return RateResult(True, len(queue), self._limit, 0.0)

    def reset(self, ip: Optional[str] = None) -> None:
        with self._lock:
            if ip is None:
                self._hits.clear()
            else:
                self._hits.pop(ip, None)

    def tracked(self) -> int:
        with self._lock:
            return len(self._hits)

    def _expire(self, queue: Deque[float], moment: float) -> None:
        cutoff = moment - self._window
        while queue and queue[0] <= cutoff:
            queue.popleft()

    def _sweep_if_due(self, moment: float) -> None:
        if moment - self._last_sweep < self._window and len(self._hits) <= self._max_tracked:
            return
        for ip in list(self._hits):
            queue = self._hits[ip]
            self._expire(queue, moment)
            if not queue:
                del self._hits[ip]
        self._last_sweep = moment
        if len(self._hits) > self._max_tracked:
            # Teto de memória: descarta os 10% com atividade mais antiga.
            victims = sorted(self._hits, key=lambda key: self._hits[key][-1])
            for ip in victims[: max(1, len(victims) // 10)]:
                del self._hits[ip]
