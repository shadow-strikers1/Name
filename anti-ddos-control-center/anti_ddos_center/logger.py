"""Registro de eventos de segurança em arquivo de texto."""
from __future__ import annotations

import os
import threading
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Callable, Deque, List, Optional

MAX_LOG_BYTES = 1_048_576  # ao atingir, events.log vira events.log.1


def _sanitize(message: object) -> str:
    """Remove quebras de linha e caracteres de controle (evita log/ANSI injection)."""
    collapsed = " ".join(str(message).split())
    return "".join(ch for ch in collapsed if ch.isprintable())


class EventLogger:
    """Grava linhas no formato: [AAAA-MM-DD HH:MM:SS] mensagem."""

    def __init__(
        self,
        path: Path,
        max_bytes: int = MAX_LOG_BYTES,
        now: Callable[[], datetime] = datetime.now,
    ) -> None:
        self._path = Path(path)
        self._max_bytes = max_bytes
        self._now = now
        self._memory: Deque[str] = deque(maxlen=500)
        self._lock = threading.Lock()
        self.last_error: Optional[str] = None

    @property
    def path(self) -> Path:
        return self._path

    def log(self, message: str) -> str:
        line = f"[{self._now():%Y-%m-%d %H:%M:%S}] {_sanitize(message)}"
        with self._lock:
            self._memory.append(line)
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                self._rotate_if_needed()
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
                self.last_error = None
            except OSError as exc:
                # Falha de log nunca deve derrubar a proteção.
                self.last_error = exc.strerror or str(exc)
        return line

    def tail(self, count: int = 20) -> List[str]:
        if count <= 0:
            return []
        with self._lock:
            try:
                with self._path.open("r", encoding="utf-8", errors="replace") as handle:
                    lines = [_sanitize(raw) for raw in deque(handle, maxlen=count)]
                return lines
            except FileNotFoundError:
                return []
            except OSError:
                return list(self._memory)[-count:]

    def _rotate_if_needed(self) -> None:
        try:
            size = self._path.stat().st_size
        except FileNotFoundError:
            return
        if size >= self._max_bytes:
            os.replace(self._path, self._path.with_name(self._path.name + ".1"))
