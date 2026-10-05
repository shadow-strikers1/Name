"""Testes do Anti-DDoS Control Center (somente biblioteca padrão)."""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from typing import Optional

from anti_ddos_center import AntiDDoS, EventLogger, RateLimiter, Reason, ValidationError
from anti_ddos_center.cli import ControlCenter, format_duration

ROOT = Path(__file__).resolve().parent.parent
DEFAULTS = {
    "protection": True,
    "rate_limit": 60,
    "window_seconds": 60,
    "block_seconds": 600,
    "blocked_ips": [],
    "whitelist": ["127.0.0.1", "::1"],
}


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TempDirCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.data_dir = Path(self._tmp.name) / "data"
        self.clock = FakeClock()

    def engine(self) -> AntiDDoS:
        return AntiDDoS(data_dir=self.data_dir, clock=self.clock)

    def log_text(self) -> str:
        return (self.data_dir / "events.log").read_text(encoding="utf-8")


class ConfigTests(TempDirCase):
    def test_initial_config_is_created_with_defaults(self) -> None:
        self.assertFalse(self.data_dir.exists())
        eng = self.engine()
        config_path = self.data_dir / "config.json"
        self.assertTrue(config_path.is_file())
        self.assertEqual(json.loads(config_path.read_text(encoding="utf-8")), DEFAULTS)
        self.assertTrue(eng.protection_enabled)

    def test_config_persists_across_restarts(self) -> None:
        eng = self.engine()
        eng.set_limit(10, 5)
        eng.set_protection(False)
        eng.ips.block("192.168.1.100")
        eng.ips.whitelist_add("10.0.0.7")

        again = self.engine()
        settings = again.config.settings
        self.assertFalse(settings.protection)
        self.assertEqual((settings.rate_limit, settings.window_seconds), (10, 5))
        self.assertEqual(settings.blocked_ips, ["192.168.1.100"])
        self.assertIn("10.0.0.7", settings.whitelist)

    def test_corrupted_config_is_recovered(self) -> None:
        self.data_dir.mkdir(parents=True)
        (self.data_dir / "config.json").write_text("{not json", encoding="utf-8")
        eng = self.engine()
        self.assertEqual(eng.config.settings.to_dict(), DEFAULTS)
        self.assertEqual(
            json.loads((self.data_dir / "config.json").read_text(encoding="utf-8")), DEFAULTS
        )
        self.assertTrue(list(self.data_dir.glob("config.json.corrupt-*")))
        self.assertIn("Aviso de configuração", self.log_text())

    def test_non_object_json_is_recovered(self) -> None:
        self.data_dir.mkdir(parents=True)
        (self.data_dir / "config.json").write_text("[1, 2, 3]", encoding="utf-8")
        self.assertEqual(self.engine().config.settings.to_dict(), DEFAULTS)

    def test_invalid_fields_fall_back_individually(self) -> None:
        self.data_dir.mkdir(parents=True)
        bad = {
            "protection": "yes",
            "rate_limit": -5,
            "window_seconds": 30,
            "block_seconds": 10,
            "blocked_ips": ["1.2.3.4", "lixo", "127.0.0.1"],
            "whitelist": "nope",
        }
        (self.data_dir / "config.json").write_text(json.dumps(bad), encoding="utf-8")
        settings = self.engine().config.settings
        self.assertTrue(settings.protection)
        self.assertEqual(settings.rate_limit, 60)
        self.assertEqual(settings.window_seconds, 30)
        self.assertEqual(settings.block_seconds, 10)
        self.assertEqual(settings.whitelist, ["127.0.0.1", "::1"])
        # 127.0.0.1 está na whitelist, que tem prioridade sobre o bloqueio.
        self.assertEqual(settings.blocked_ips, ["1.2.3.4"])


class ProtectionTests(TempDirCase):
    def test_toggle_protection_and_log(self) -> None:
        eng = self.engine()
        self.assertTrue(eng.set_protection(False))
        self.assertFalse(eng.protection_enabled)
        self.assertFalse(eng.set_protection(False))  # já estava desligada
        self.assertTrue(eng.set_protection(True))
        text = self.log_text()
        self.assertIn("Proteção desativada", text)
        self.assertIn("Proteção ativada", text)
        self.assertEqual(text.count("Proteção desativada"), 1)

    def test_set_limit_validates_range(self) -> None:
        eng = self.engine()
        with self.assertRaises(ValidationError):
            eng.set_limit(0, 60)
        with self.assertRaises(ValidationError):
            eng.set_limit(10, 0)
        eng.set_limit(100, 30)
        self.assertIn("Rate limit alterado: 100 requisições por 30s", self.log_text())


class IPManagerTests(TempDirCase):
    def test_block_and_unblock(self) -> None:
        eng = self.engine()
        self.assertTrue(eng.ips.block("192.168.1.100"))
        self.assertFalse(eng.ips.block("192.168.1.100"))
        self.assertEqual(eng.ips.blocked(), ["192.168.1.100"])
        self.assertTrue(eng.ips.unblock("192.168.1.100"))
        self.assertFalse(eng.ips.unblock("192.168.1.100"))
        text = self.log_text()
        self.assertIn("IP bloqueado: 192.168.1.100", text)
        self.assertIn("IP desbloqueado: 192.168.1.100", text)

    def test_invalid_ips_are_rejected(self) -> None:
        eng = self.engine()
        for bad in ("", "abc", "999.1.1.1", "1.2.3", "10.0.0.0/8", "1.2.3.4; rm -rf /", "fe80::1%eth0"):
            with self.assertRaises(ValidationError, msg=bad):
                eng.ips.block(bad)
        self.assertEqual(eng.ips.blocked(), [])

    def test_ip_normalization(self) -> None:
        eng = self.engine()
        eng.ips.block("::ffff:10.1.1.1")
        eng.ips.block("2001:DB8:0:0:0:0:0:1")
        self.assertEqual(eng.ips.blocked(), ["10.1.1.1", "2001:db8::1"])

    def test_whitelist_add_remove(self) -> None:
        eng = self.engine()
        self.assertTrue(eng.ips.whitelist_add("10.0.0.5"))
        self.assertFalse(eng.ips.whitelist_add("10.0.0.5"))
        self.assertTrue(eng.ips.is_whitelisted("10.0.0.5"))
        self.assertTrue(eng.ips.whitelist_remove("10.0.0.5"))
        self.assertFalse(eng.ips.whitelist_remove("10.0.0.5"))
        text = self.log_text()
        self.assertIn("IP adicionado à whitelist: 10.0.0.5", text)
        self.assertIn("IP removido da whitelist: 10.0.0.5", text)

    def test_whitelist_has_priority_over_blocks(self) -> None:
        eng = self.engine()
        eng.ips.block("10.0.0.9")
        eng.ips.whitelist_add("10.0.0.9")
        self.assertEqual(eng.ips.blocked(), [])
        with self.assertRaises(ValidationError):
            eng.ips.block("10.0.0.9")
        self.assertEqual(eng.check_request("10.0.0.9").reason, Reason.WHITELISTED)


class RateLimiterTests(unittest.TestCase):
    def test_limit_and_sliding_window(self) -> None:
        clock = FakeClock()
        limiter = RateLimiter(3, 10, clock)
        results = [limiter.hit("1.1.1.1") for _ in range(3)]
        self.assertTrue(all(r.allowed for r in results))
        blocked = limiter.hit("1.1.1.1")
        self.assertFalse(blocked.allowed)
        self.assertEqual(blocked.count, 4)
        self.assertAlmostEqual(blocked.retry_after, 10.0)
        clock.advance(10.1)
        self.assertTrue(limiter.hit("1.1.1.1").allowed)

    def test_ips_are_independent(self) -> None:
        limiter = RateLimiter(1, 60, FakeClock())
        self.assertTrue(limiter.hit("1.1.1.1").allowed)
        self.assertFalse(limiter.hit("1.1.1.1").allowed)
        self.assertTrue(limiter.hit("2.2.2.2").allowed)

    def test_configure_and_memory_cleanup(self) -> None:
        clock = FakeClock()
        limiter = RateLimiter(5, 10, clock)
        for i in range(50):
            limiter.hit(f"10.0.0.{i}")
        self.assertEqual(limiter.tracked(), 50)
        clock.advance(11)
        limiter.hit("9.9.9.9")  # dispara a varredura de IPs inativos
        self.assertEqual(limiter.tracked(), 1)
        limiter.configure(1, 5)
        self.assertEqual((limiter.limit, limiter.window_seconds), (1, 5.0))
        with self.assertRaises(ValueError):
            limiter.configure(0, 5)

    def test_tracked_ips_have_a_hard_cap(self) -> None:
        limiter = RateLimiter(5, 3600, FakeClock(), max_tracked=100)
        for i in range(500):
            limiter.hit(f"10.1.{i // 250}.{i % 250}")
        self.assertLessEqual(limiter.tracked(), 100)


class EngineTests(TempDirCase):
    IP = "203.0.113.9"

    def test_stats_start_at_zero(self) -> None:
        stats = self.engine().stats()
        self.assertEqual(
            (stats.requests_observed, stats.events_detected, stats.blocked_total), (0, 0, 0)
        )

    def test_excess_triggers_event_and_temporary_block(self) -> None:
        eng = self.engine()
        eng.set_limit(3, 10)
        for _ in range(3):
            self.assertTrue(eng.check_request(self.IP).allowed)
        trigger = eng.check_request(self.IP)
        self.assertFalse(trigger.allowed)
        self.assertEqual(trigger.reason, Reason.RATE_LIMITED)
        self.assertEqual(trigger.retry_after, 600.0)
        follow = eng.check_request(self.IP)
        self.assertEqual(follow.reason, Reason.TEMP_BLOCKED)

        stats = eng.stats()
        self.assertEqual(stats.requests_observed, 5)
        self.assertEqual(stats.events_detected, 1)
        self.assertEqual(stats.blocked_temporary, 1)
        self.assertEqual(eng.suspects(), {self.IP: 1})
        self.assertIn(f"Excesso de requisições detectado: {self.IP}", self.log_text())

        self.clock.advance(601)  # bloqueio expira
        self.assertTrue(eng.check_request(self.IP).allowed)
        self.assertEqual(eng.stats().blocked_temporary, 0)

    def test_whitelisted_ip_is_never_blocked(self) -> None:
        eng = self.engine()
        eng.set_limit(2, 60)
        eng.ips.whitelist_add(self.IP)
        verdicts = [eng.check_request(self.IP) for _ in range(100)]
        self.assertTrue(all(v.allowed and v.reason == Reason.WHITELISTED for v in verdicts))
        self.assertEqual(eng.stats().events_detected, 0)
        self.assertEqual(eng.suspects(), {})

    def test_default_whitelist_covers_loopback(self) -> None:
        eng = self.engine()
        eng.set_limit(1, 60)
        for ip in ("127.0.0.1", "::1"):
            self.assertTrue(all(eng.check_request(ip).allowed for _ in range(5)))

    def test_protection_off_allows_everything_but_whitelist_logic_holds(self) -> None:
        eng = self.engine()
        eng.set_limit(1, 60)
        eng.ips.block(self.IP)
        eng.set_protection(False)
        self.assertEqual(eng.check_request(self.IP).reason, Reason.PROTECTION_OFF)
        eng.set_protection(True)
        self.assertEqual(eng.check_request(self.IP).reason, Reason.BLOCKED)

    def test_invalid_ip_is_denied_and_not_counted(self) -> None:
        eng = self.engine()
        verdict = eng.check_request("não-é-ip")
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.reason, Reason.INVALID_IP)
        self.assertEqual(eng.stats().requests_observed, 0)

    def test_without_block_seconds_excess_is_still_refused_and_log_is_throttled(self) -> None:
        eng = self.engine()
        eng.set_limit(1, 60)
        eng.set_block_seconds(0)
        eng.check_request(self.IP)
        for _ in range(20):
            self.assertEqual(eng.check_request(self.IP).reason, Reason.RATE_LIMITED)
        self.assertEqual(eng.stats().events_detected, 20)
        self.assertEqual(self.log_text().count("Excesso de requisições detectado"), 1)

    def test_manual_unblock_clears_temporary_block(self) -> None:
        eng = self.engine()
        eng.set_limit(1, 60)
        eng.check_request(self.IP)
        eng.check_request(self.IP)
        self.assertEqual(eng.stats().blocked_temporary, 1)
        self.assertTrue(eng.ips.unblock(self.IP))
        self.assertEqual(eng.stats().blocked_temporary, 0)


class LoggerTests(TempDirCase):
    def test_line_format(self) -> None:
        logger = EventLogger(
            self.data_dir / "events.log", now=lambda: datetime(2026, 10, 5, 19, 30, 0)
        )
        line = logger.log("IP bloqueado: 192.168.1.100")
        self.assertEqual(line, "[2026-10-05 19:30:00] IP bloqueado: 192.168.1.100")
        self.assertEqual(logger.tail(5), [line])

    def test_real_timestamp_format(self) -> None:
        eng = self.engine()
        eng.ips.block("192.168.1.100")
        pattern = r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] IP bloqueado: 192\.168\.1\.100$"
        self.assertTrue(any(re.match(pattern, l) for l in self.log_text().splitlines()))

    def test_control_characters_cannot_forge_entries(self) -> None:
        logger = EventLogger(self.data_dir / "events.log")
        logger.log("linha1\n[2026-01-01 00:00:00] falsa\x1b[31m")
        raw = (self.data_dir / "events.log").read_text(encoding="utf-8")
        self.assertEqual(len(raw.splitlines()), 1)
        self.assertNotIn("\x1b", raw)

    def test_rotation_and_tail(self) -> None:
        logger = EventLogger(self.data_dir / "events.log", max_bytes=200)
        for i in range(30):
            logger.log(f"evento {i}")
        self.assertTrue((self.data_dir / "events.log.1").exists())
        self.assertTrue(logger.tail(3)[-1].endswith("evento 29"))
        self.assertEqual(logger.tail(0), [])

    def test_unwritable_log_does_not_raise(self) -> None:
        blocker = self.data_dir
        blocker.parent.mkdir(parents=True, exist_ok=True)
        blocker.write_text("arquivo no lugar da pasta", encoding="utf-8")
        logger = EventLogger(blocker / "events.log")
        logger.log("não deve levantar exceção")
        self.assertIsNotNone(logger.last_error)
        self.assertEqual(len(logger.tail(5)), 1)


class CliTests(TempDirCase):
    def setUp(self) -> None:
        super().setUp()
        self.out = io.StringIO()
        self.center = ControlCenter(self.engine(), stream=self.out, color=False, unicode=True)

    def run_cmd(self, line: str) -> tuple:
        self.out.seek(0)
        self.out.truncate()
        keep_going = self.center.execute(line)
        return keep_going, self.out.getvalue()

    def test_help_lists_commands(self) -> None:
        _, out = self.run_cmd("help")
        for word in ("protect on|off", "limit", "block <IP>", "whitelist add", "list blocked", "logs", "exit"):
            self.assertIn(word, out)

    def test_status_shows_zeroes_and_paths(self) -> None:
        _, out = self.run_cmd("status")
        self.assertIn("ON", out)
        self.assertRegex(out, r"Requisições observadas\s*: 0")
        self.assertRegex(out, r"Eventos detectados\s*: 0")
        self.assertIn("60 requisições", out)
        self.assertIn(str(self.data_dir / "config.json"), out)
        self.assertIn(str(self.data_dir / "events.log"), out)

    def test_protect_commands(self) -> None:
        _, out = self.run_cmd("protect off")
        self.assertIn("Proteção desativada", out)
        self.assertFalse(self.center.engine.protection_enabled)
        _, out = self.run_cmd("protect off")
        self.assertIn("já estava", out)
        _, out = self.run_cmd("PROTECT ON")
        self.assertIn("Proteção ativada", out)

    def test_limit_command(self) -> None:
        _, out = self.run_cmd("limit 60 60")
        self.assertIn("60 requisições por janela de 60s", out)
        self.run_cmd("limit 5 20")
        settings = self.center.engine.config.settings
        self.assertEqual((settings.rate_limit, settings.window_seconds), (5, 20))

    def test_block_unblock_whitelist_and_lists(self) -> None:
        _, out = self.run_cmd("block 192.168.1.100")
        self.assertIn("IP bloqueado: 192.168.1.100", out)
        _, out = self.run_cmd("list blocked")
        self.assertIn("192.168.1.100", out)
        _, out = self.run_cmd("unblock 192.168.1.100")
        self.assertIn("IP desbloqueado", out)
        _, out = self.run_cmd("list blocked")
        self.assertIn("Nenhum IP bloqueado", out)
        _, out = self.run_cmd("whitelist add 10.0.0.5")
        self.assertIn("adicionado à whitelist", out)
        _, out = self.run_cmd("list whitelist")
        self.assertIn("10.0.0.5", out)
        _, out = self.run_cmd("whitelist remove 10.0.0.5")
        self.assertIn("removido da whitelist", out)

    def test_blocking_a_whitelisted_ip_is_refused(self) -> None:
        _, out = self.run_cmd("block 127.0.0.1")
        self.assertIn("whitelist", out)
        self.assertEqual(self.center.engine.ips.blocked(), [])

    def test_invalid_commands_never_crash(self) -> None:
        cases = [
            "foo", "blokc 1.2.3.4", "limit", "limit 10", "limit abc 5", "limit 0 10",
            "limit 10 0", "limit -1 5", "limit 99999999999999999999 5", "block", "block 1.2.3.4 5.6.7.8",
            "block 999.1.1.1", "block $(reboot)", "whitelist", "whitelist add", "whitelist nuke 1.2.3.4",
            "protect", "protect maybe", "list", "list nothing", "logs 0", "logs abc", "logs 1 2",
            "help me", "status now", "'aspas abertas", "x" * 1000,
        ]
        for line in cases:
            keep_going, out = self.run_cmd(line)
            self.assertTrue(keep_going, line[:40])
            self.assertIn("[x]", out, line[:40])
        self.assertEqual(self.center.engine.config.settings.rate_limit, 60)
        self.assertEqual(self.center.engine.ips.blocked(), [])

    def test_unknown_command_suggests_closest(self) -> None:
        _, out = self.run_cmd("blokc 1.2.3.4")
        self.assertIn("block", out)

    def test_blank_line_clear_banner_and_exit(self) -> None:
        self.assertEqual(self.run_cmd("   ")[0], True)
        self.assertEqual(self.run_cmd("clear")[0], True)
        _, out = self.run_cmd("banner")
        self.assertIn("ANTI-DDoS CONTROL CENTER", out)
        self.assertIn("Created by my TikTok profile", out)
        self.assertIn("STATUS: PROTECTED", out)
        self.assertEqual(self.run_cmd("exit")[0], False)
        self.assertEqual(self.run_cmd("quit")[0], False)

    def test_logs_command(self) -> None:
        _, out = self.run_cmd("logs")
        self.assertIn("Central iniciada", out)
        self.run_cmd("block 8.8.8.8")
        _, out = self.run_cmd("logs 5")
        self.assertIn("IP bloqueado: 8.8.8.8", out)

    def test_works_without_color_or_unicode(self) -> None:
        out = io.StringIO()
        plain = ControlCenter(self.center.engine, stream=out, color=False, unicode=False)
        plain.execute("banner")
        plain.execute("status")
        text = out.getvalue()
        self.assertNotIn("\033", text)
        self.assertTrue(text.isascii() or "ç" in text or "ã" in text)  # só ASCII na moldura
        self.assertIn("+", text)

    def test_ansi_colors_when_enabled(self) -> None:
        out = io.StringIO()
        ControlCenter(self.center.engine, stream=out, color=True, unicode=True).execute("status")
        self.assertIn("\033[", out.getvalue())

    def test_format_duration(self) -> None:
        self.assertEqual(format_duration(0), "0s")
        self.assertEqual(format_duration(65), "1m 05s")
        self.assertEqual(format_duration(3725), "1h 02m 05s")
        self.assertEqual(format_duration(90_000), "1d 01h 00m")


class EntryPointTests(TempDirCase):
    def run_script(self, stdin: str, *extra: str) -> subprocess.CompletedProcess:
        env = dict(os.environ, NO_COLOR="1", PYTHONIOENCODING="utf-8")
        return subprocess.run(
            [sys.executable, str(ROOT / "anti_ddos.py"), "--data-dir", str(self.data_dir), *extra],
            input=stdin, capture_output=True, text=True, timeout=60, env=env, cwd=self._tmp.name,
        )

    def test_script_runs_directly(self) -> None:
        proc = self.run_script("status\nblock 1.2.3.4\nlist blocked\nfoo\nexit\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("ANTI-DDoS CONTROL CENTER", proc.stdout)
        self.assertIn("Created by my TikTok profile", proc.stdout)
        self.assertIn("1.2.3.4", proc.stdout)
        self.assertIn("Comando desconhecido", proc.stdout)
        self.assertEqual(proc.stderr, "")

    def test_eof_exits_cleanly_and_state_persists(self) -> None:
        self.assertEqual(self.run_script("block 5.5.5.5\n").returncode, 0)
        proc = self.run_script("list blocked\nexit\n")
        self.assertIn("5.5.5.5", proc.stdout)
        self.assertIn("Central encerrada", self.log_text())

    def test_version_flag(self) -> None:
        proc = self.run_script("", "--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("1.0.0", proc.stdout)


if __name__ == "__main__":
    unittest.main()
