from django.db import migrations


def create_security_groups(apps, schema_editor):
    Group = apps.get_model("auth", "Group")
    for name in ("security-admin", "analyst"):
        Group.objects.get_or_create(name=name)


class Migration(migrations.Migration):
    dependencies = [
        ("scanner_engine", "0002_scantask_owner_file_input"),
    ]

    operations = [
        migrations.RunPython(create_security_groups, migrations.RunPython.noop),
    ]
