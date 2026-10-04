# Generated for the RootSecOps backend scaffold.

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="ScanTask",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("input_type", models.CharField(choices=[("IMAGE", "Docker Image"), ("DOCKERFILE", "Dockerfile"), ("GIT", "Git Repository")], max_length=20)),
                ("target", models.TextField()),
                ("status", models.CharField(choices=[("PENDING", "Pending"), ("PROCESSING", "Processing"), ("SUCCESS", "Success"), ("FAILED", "Failed")], default="PENDING", max_length=20)),
                ("progress", models.PositiveSmallIntegerField(default=0)),
                ("options", models.JSONField(blank=True, default=dict)),
                ("logs", models.JSONField(blank=True, default=list)),
                ("raw_results", models.JSONField(blank=True, default=dict)),
                ("normalized_results", models.JSONField(blank=True, default=dict)),
                ("summary", models.JSONField(blank=True, default=dict)),
                ("error_message", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.CreateModel(
            name="ScannerConfig",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("tool_name", models.CharField(max_length=64, unique=True)),
                ("display_name", models.CharField(blank=True, default="", max_length=128)),
                ("category", models.CharField(choices=[("preprocessing", "Pre-processing"), ("sbom", "SBOM"), ("vulnerability", "Vulnerability"), ("secret", "Secret"), ("misconfiguration", "Misconfiguration"), ("malware", "Malware")], max_length=32)),
                ("executable_path", models.CharField(blank=True, default="", max_length=512)),
                ("local_db_path", models.CharField(blank=True, default="", max_length=1024)),
                ("is_offline_mode", models.BooleanField(default=True)),
                ("extra_args", models.JSONField(blank=True, default=list)),
                ("env", models.JSONField(blank=True, default=dict)),
                ("enabled", models.BooleanField(default=True)),
                ("supported_input_types", models.JSONField(blank=True, default=list)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["category", "tool_name"]},
        ),
        migrations.CreateModel(
            name="YaraRule",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=255, unique=True)),
                ("file_path", models.CharField(max_length=1024)),
                ("is_active", models.BooleanField(default=True)),
                ("uploaded_at", models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
