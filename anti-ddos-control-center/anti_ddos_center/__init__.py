"""Anti-DDoS Control Center: motor defensivo de rate limiting e bloqueio de IPs."""

__version__ = "1.0.0"

from .config import ConfigManager, Settings  # noqa: E402
from .core import AntiDDoS, Reason, Stats, Verdict  # noqa: E402
from .ip_manager import IPManager  # noqa: E402
from .logger import EventLogger  # noqa: E402
from .rate_limiter import RateLimiter, RateResult  # noqa: E402
from .validation import ValidationError  # noqa: E402

__all__ = [
    "AntiDDoS",
    "ConfigManager",
    "EventLogger",
    "IPManager",
    "RateLimiter",
    "RateResult",
    "Reason",
    "Settings",
    "Stats",
    "ValidationError",
    "Verdict",
    "__version__",
]
