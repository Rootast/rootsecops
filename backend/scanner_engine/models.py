import uuid

from django.conf import settings
from django.db import models


class ScanTask(models.Model):
    class InputType(models.TextChoices):
        IMAGE = "IMAGE", "Docker Image"
        DOCKERFILE = "DOCKERFILE", "Dockerfile"
        GIT = "GIT", "Git Repository"
        FILE = "FILE", "File"

    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        PROCESSING = "PROCESSING", "Processing"
        SUCCESS = "SUCCESS", "Success"
        FAILED = "FAILED", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="scan_tasks",
        null=True,
        blank=True,
    )
    input_type = models.CharField(max_length=20, choices=InputType.choices)
    target = models.TextField()
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    progress = models.PositiveSmallIntegerField(default=0)
    options = models.JSONField(default=dict, blank=True)
    logs = models.JSONField(default=list, blank=True)
    raw_results = models.JSONField(default=dict, blank=True)
    normalized_results = models.JSONField(default=dict, blank=True)
    summary = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.get_input_type_display()} {self.target[:80]}"


class ScannerConfig(models.Model):
    class Category(models.TextChoices):
        PREPROCESSING = "preprocessing", "Pre-processing"
        SBOM = "sbom", "SBOM"
        VULNERABILITY = "vulnerability", "Vulnerability"
        SECRET = "secret", "Secret"
        MISCONFIGURATION = "misconfiguration", "Misconfiguration"
        MALWARE = "malware", "Malware"
        METADATA = "metadata", "Metadata"

    tool_name = models.CharField(max_length=64, unique=True)
    display_name = models.CharField(max_length=128, blank=True, default="")
    category = models.CharField(max_length=32, choices=Category.choices)
    executable_path = models.CharField(max_length=512, blank=True, default="")
    local_db_path = models.CharField(max_length=1024, blank=True, default="")
    is_offline_mode = models.BooleanField(default=True)
    extra_args = models.JSONField(default=list, blank=True)
    env = models.JSONField(default=dict, blank=True)
    enabled = models.BooleanField(default=True)
    version_crawler_enabled = models.BooleanField(default=True)
    db_check_enabled = models.BooleanField(default=True)
    supported_input_types = models.JSONField(default=list, blank=True)
    binary_update_command = models.JSONField(default=list, blank=True)
    database_update_command = models.JSONField(default=list, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["category", "tool_name"]

    def __str__(self):
        return self.display_name or self.tool_name


class YaraRule(models.Model):
    name = models.CharField(max_length=255, unique=True)
    file_path = models.CharField(max_length=1024)
    is_active = models.BooleanField(default=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class ToolState(models.Model):
    class Health(models.TextChoices):
        UNKNOWN = "unknown", "Unknown"
        HEALTHY = "healthy", "Healthy"
        UNHEALTHY = "unhealthy", "Unhealthy"

    class ActionState(models.TextChoices):
        IDLE = "idle", "Idle"
        CHECKING = "checking", "Checking"
        UPDATING = "updating", "Updating"
        FAILED = "failed", "Failed"
        SUCCESS = "success", "Success"

    tool = models.OneToOneField(ScannerConfig, on_delete=models.CASCADE, related_name="state")
    active = models.BooleanField(default=True)
    health_state = models.CharField(max_length=24, choices=Health.choices, default=Health.UNKNOWN)
    action_state = models.CharField(max_length=24, choices=ActionState.choices, default=ActionState.IDLE)
    current_version = models.CharField(max_length=128, blank=True, default="")
    latest_version = models.CharField(max_length=128, blank=True, default="")
    database_version = models.CharField(max_length=256, blank=True, default="")
    database_status = models.CharField(max_length=128, blank=True, default="")
    last_checked_at = models.DateTimeField(null=True, blank=True)
    last_db_checked_at = models.DateTimeField(null=True, blank=True)
    last_updated_at = models.DateTimeField(null=True, blank=True)
    last_db_updated_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True, default="")
    logs = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["tool__category", "tool__tool_name"]

    def __str__(self):
        return f"{self.tool.tool_name} state"
