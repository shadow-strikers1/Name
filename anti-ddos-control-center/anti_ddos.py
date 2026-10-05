#!/usr/bin/env python3
"""Anti-DDoS Control Center: ponto de entrada.

Uso:  python3 anti_ddos.py [--data-dir PASTA] [--no-color] [--version]
"""
import sys

if sys.version_info < (3, 8):
    sys.exit("Anti-DDoS Control Center requer Python 3.8 ou superior.")

from anti_ddos_center.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
