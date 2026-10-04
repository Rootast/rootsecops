from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("scanner_engine", "0004_metadata_category"),
    ]

    operations = [
        migrations.AddField(
            model_name="scannerconfig",
            name="binary_update_command",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="scannerconfig",
            name="database_update_command",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="scannerconfig",
            name="db_check_enabled",
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name="scannerconfig",
            name="version_crawler_enabled",
            field=models.BooleanField(default=True),
        ),
        migrations.CreateModel(
            name="ToolState",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("active", models.BooleanField(default=True)),
                (
                    "health_state",
                    models.CharField(
                        choices=[("unknown", "Unknown"), ("healthy", "Healthy"), ("unhealthy", "Unhealthy")],
                        default="unknown",
                        max_length=24,
                    ),
                ),
                (
                    "action_state",
                    models.CharField(
                        choices=[
                            ("idle", "Idle"),
                            ("checking", "Checking"),
                            ("updating", "Updating"),
                            ("failed", "Failed"),
                            ("success", "Success"),
                        ],
                        default="idle",
                        max_length=24,
                    ),
                ),
                ("current_version", models.CharField(blank=True, default="", max_length=128)),
                ("latest_version", models.CharField(blank=True, default="", max_length=128)),
                ("database_version", models.CharField(blank=True, default="", max_length=256)),
                ("database_status", models.CharField(blank=True, default="", max_length=128)),
                ("last_checked_at", models.DateTimeField(blank=True, null=True)),
                ("last_db_checked_at", models.DateTimeField(blank=True, null=True)),
                ("last_updated_at", models.DateTimeField(blank=True, null=True)),
                ("last_db_updated_at", models.DateTimeField(blank=True, null=True)),
                ("last_error", models.TextField(blank=True, default="")),
                ("logs", models.JSONField(blank=True, default=list)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "tool",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="state",
                        to="scanner_engine.scannerconfig",
                    ),
                ),
            ],
            options={
                "ordering": ["tool__category", "tool__tool_name"],
            },
        ),
    ]
