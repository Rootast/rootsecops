import os
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase


class BootstrapAdminCommandTests(TestCase):
    def test_creates_superuser_from_environment(self):
        env = {
            "ADMIN_USERNAME": "env-admin",
            "ADMIN_PASSWORD": "first-secure-password",
            "ADMIN_EMAIL": "admin@example.com",
        }

        with patch.dict(os.environ, env, clear=False):
            call_command("bootstrap_admin", stdout=StringIO())

        user = get_user_model().objects.get(username="env-admin")
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_active)
        self.assertEqual(user.email, "admin@example.com")
        self.assertTrue(user.check_password("first-secure-password"))

    def test_updates_existing_admin_password_and_email(self):
        User = get_user_model()
        user = User.objects.create_user(
            username="env-admin",
            password="old-password",
            email="old@example.com",
        )
        env = {
            "ADMIN_USERNAME": "env-admin",
            "ADMIN_PASSWORD": "new-secure-password",
            "ADMIN_EMAIL": "new@example.com",
        }

        with patch.dict(os.environ, env, clear=False):
            call_command("bootstrap_admin", stdout=StringIO())

        user.refresh_from_db()
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertEqual(user.email, "new@example.com")
        self.assertTrue(user.check_password("new-secure-password"))

    def test_requires_username_and_password_together(self):
        env = {"ADMIN_USERNAME": "env-admin", "ADMIN_PASSWORD": "", "ADMIN_EMAIL": ""}

        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(CommandError):
                call_command("bootstrap_admin", stdout=StringIO())
