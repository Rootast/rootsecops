import argparse
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("configure", Path(__file__).resolve().parents[1] / "configure.py")
configure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(configure)


class ConfigurationTests(unittest.TestCase):
    def test_domains_are_bare_valid_hostnames(self):
        self.assertEqual(configure.hostname("API.Example.com"), "api.example.com")
        for value in ("https://example.com", "host/path", "host:80", "*.test", "-bad.test", "bad..test"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                configure.hostname(value)

    def test_secrets_are_unique_private_and_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / ".env"
            configure.configure(target, "ui.example.com", "api.example.com")
            original = target.read_text()
            values = dict(line.split("=", 1) for line in original.splitlines() if line and not line.startswith("#"))
            secret_values = [values[key] for key in ("DJANGO_SECRET_KEY", "ADMIN_PASSWORD", "POSTGRES_PASSWORD")]
            self.assertEqual(len(set(secret_values)), 3)
            self.assertTrue(all(len(value) >= 32 for value in secret_values))
            self.assertEqual(values["FRONT_DOMAIN"], "ui.example.com")
            self.assertEqual(values["COMPOSE_PROJECT_NAME"], "rootsecops")
            self.assertEqual(values["POSTGRES_DB"], "rootsecops")
            self.assertEqual(values["POSTGRES_USER"], "rootsecops")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                configure.configure(target, "other.example.com", "api.example.com")
            self.assertEqual(target.read_text(), original)

    def test_same_domain_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / ".env"
            with self.assertRaises(ValueError):
                configure.configure(target, "same.test", "same.test")
            self.assertFalse(target.exists())
