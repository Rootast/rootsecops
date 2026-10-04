from django.test import TestCase


class HealthCheckTests(TestCase):
    def test_health_check_verifies_database(self):
        response = self.client.get("/health/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})
