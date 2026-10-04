from django.core.management.base import BaseCommand

from scanner_engine.core.registry import seed_scanner_configs


class Command(BaseCommand):
    help = "Create or update default scanner tool configurations."

    def handle(self, *args, **options):
        seed_scanner_configs()
        self.stdout.write(self.style.SUCCESS("Scanner configurations seeded."))
