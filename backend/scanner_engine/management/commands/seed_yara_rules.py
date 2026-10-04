from pathlib import Path
from django.conf import settings
from django.core.management.base import BaseCommand
from scanner_engine.models import YaraRule, ScannerConfig


class Command(BaseCommand):
    help = "Load YARA rules from var/yara_rules directory into database"

    def handle(self, *args, **options):
        yara_rules_dir = settings.YARA_RULES_DIR

        if not yara_rules_dir.exists():
            self.stdout.write(
                self.style.ERROR(f"❌ YARA rules directory not found: {yara_rules_dir}")
            )
            return

        rule_files = []
        for suffix in ("*.yar", "*.yara", "*.rules"):
            rule_files.extend(yara_rules_dir.rglob(suffix))

        if not rule_files:
            self.stdout.write(
                self.style.WARNING(f"⚠️  No YARA rule files found in {yara_rules_dir}")
            )
            return

        created_count = 0
        updated_count = 0

        for rule_file in sorted(rule_files):
            name = rule_file.stem
            file_path = str(rule_file.absolute())

            rule, created = YaraRule.objects.get_or_create(
                name=name,
                defaults={
                    'file_path': file_path,
                    'is_active': True
                }
            )

            if created:
                created_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f"✓ Created: {name}")
                )
            else:
                # Update file path in case it changed
                rule.file_path = file_path
                rule.save(update_fields=['file_path'])
                updated_count += 1

        # Update ScannerConfig to point to the rules directory
        ScannerConfig.objects.filter(tool_name='yara').update(
            local_db_path=str(yara_rules_dir.absolute())
        )

        summary = f"\n📊 Summary:\n  Created: {created_count}\n  Updated: {updated_count}\n"
        self.stdout.write(self.style.SUCCESS(summary))
        self.stdout.write(
            self.style.SUCCESS(
                f"✓ YARA rules loaded successfully!\n"
                f"  Total rules: {created_count + updated_count}\n"
                f"  Rules directory: {yara_rules_dir.absolute()}"
            )
        )
