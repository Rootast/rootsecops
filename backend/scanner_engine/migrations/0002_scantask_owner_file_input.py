from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("scanner_engine", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="scantask",
            name="owner",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="scan_tasks",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AlterField(
            model_name="scantask",
            name="input_type",
            field=models.CharField(
                choices=[
                    ("IMAGE", "Docker Image"),
                    ("DOCKERFILE", "Dockerfile"),
                    ("GIT", "Git Repository"),
                    ("FILE", "File"),
                ],
                max_length=20,
            ),
        ),
    ]
