from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scanner_engine", "0003_security_groups"),
    ]

    operations = [
        migrations.AlterField(
            model_name="scannerconfig",
            name="category",
            field=models.CharField(
                choices=[
                    ("preprocessing", "Pre-processing"),
                    ("sbom", "SBOM"),
                    ("vulnerability", "Vulnerability"),
                    ("secret", "Secret"),
                    ("misconfiguration", "Misconfiguration"),
                    ("malware", "Malware"),
                    ("metadata", "Metadata"),
                ],
                max_length=32,
            ),
        ),
    ]
