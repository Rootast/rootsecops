from django.contrib import admin
from django.test import SimpleTestCase

from config.celery import app


class BrandingTests(SimpleTestCase):
    def test_admin_uses_public_project_name(self):
        self.assertEqual(admin.site.site_header, "RootSecOps Administration")
        self.assertEqual(admin.site.site_title, "RootSecOps Admin")

    def test_celery_uses_public_project_namespace(self):
        self.assertEqual(app.main, "rootsecops")
