import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Create or update the administrator configured through ADMIN_* environment variables."

    def handle(self, *args, **options):
        username = os.getenv("ADMIN_USERNAME", "").strip()
        password = os.getenv("ADMIN_PASSWORD", "")
        email = os.getenv("ADMIN_EMAIL", "").strip()

        if not username and not password:
            self.stdout.write("Admin bootstrap skipped: ADMIN_USERNAME and ADMIN_PASSWORD are not set.")
            return
        if not username or not password:
            raise CommandError("ADMIN_USERNAME and ADMIN_PASSWORD must both be set.")

        User = get_user_model()
        user, created = User.objects.get_or_create(username=username)
        changed_fields = []

        for field in ("is_staff", "is_superuser", "is_active"):
            if not getattr(user, field):
                setattr(user, field, True)
                changed_fields.append(field)

        if email and user.email != email:
            user.email = email
            changed_fields.append("email")

        if not user.check_password(password):
            user.set_password(password)
            changed_fields.append("password")

        if changed_fields:
            user.save(update_fields=changed_fields)

        action = "created" if created else "updated"
        self.stdout.write(self.style.SUCCESS(f'Administrator "{username}" {action}.'))
