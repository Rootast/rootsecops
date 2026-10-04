import json

from django.contrib.auth import get_user_model
from rest_framework import serializers

from .display import display_target, sanitize_for_display
from .models import ScanTask, ScannerConfig, ToolState, YaraRule


INPUT_TYPE_ALIASES = {
    "docker": ScanTask.InputType.IMAGE,
    "docker_image": ScanTask.InputType.IMAGE,
    "image": ScanTask.InputType.IMAGE,
    "IMAGE": ScanTask.InputType.IMAGE,
    "dockerfile": ScanTask.InputType.DOCKERFILE,
    "DOCKERFILE": ScanTask.InputType.DOCKERFILE,
    "repo": ScanTask.InputType.GIT,
    "git": ScanTask.InputType.GIT,
    "github": ScanTask.InputType.GIT,
    "GIT": ScanTask.InputType.GIT,
    "file": ScanTask.InputType.FILE,
    "malware_file": ScanTask.InputType.FILE,
    "FILE": ScanTask.InputType.FILE,
}


class ScanCreateSerializer(serializers.Serializer):
    input_type = serializers.CharField(required=False)
    asset_type = serializers.CharField(required=False, write_only=True)
    target = serializers.CharField()
    options = serializers.JSONField(required=False, default=dict)
    github_token = serializers.CharField(required=False, allow_blank=True, write_only=True)

    def validate(self, attrs):
        raw_type = attrs.get("input_type") or attrs.get("asset_type")
        if not raw_type:
            raise serializers.ValidationError({"input_type": "input_type or asset_type is required."})
        normalized = INPUT_TYPE_ALIASES.get(str(raw_type))
        if not normalized:
            allowed = sorted(INPUT_TYPE_ALIASES)
            raise serializers.ValidationError({"input_type": f"Unsupported input type. Use one of: {allowed}"})
        attrs["input_type"] = normalized

        options = attrs.get("options") or {}
        if isinstance(options, str):
            try:
                options = json.loads(options)
            except json.JSONDecodeError as exc:
                raise serializers.ValidationError({"options": "options must be valid JSON."}) from exc
        token = attrs.pop("github_token", "")
        if token:
            options["github_token"] = token
        attrs["options"] = options
        return attrs


class ScanStatusSerializer(serializers.ModelSerializer):
    owner = serializers.SerializerMethodField()
    logs = serializers.SerializerMethodField()
    toolStatus = serializers.SerializerMethodField()
    activeTool = serializers.SerializerMethodField()

    class Meta:
        model = ScanTask
        fields = [
            "id",
            "owner",
            "status",
            "progress",
            "logs",
            "toolStatus",
            "activeTool",
            "created_at",
            "updated_at",
            "error_message",
        ]

    def get_owner(self, obj):
        return obj.owner.username if obj.owner else None

    def get_logs(self, obj):
        return sanitize_for_display(obj.logs or [], obj)

    def get_toolStatus(self, obj):
        normalized_status = (obj.normalized_results or {}).get("toolStatus")
        if normalized_status:
            return normalized_status
        return (obj.raw_results or {}).get("_tool_status", [])

    def get_activeTool(self, obj):
        for item in reversed(self.get_toolStatus(obj)):
            if item.get("status") == "running":
                return item.get("tool")
        return None


class ScanResultSerializer(serializers.ModelSerializer):
    task = serializers.SerializerMethodField()

    class Meta:
        model = ScanTask
        fields = [
            "task",
            "metadata",
            "cves",
            "secrets",
            "misconfigurations",
            "malware",
            "malwareScore",
            "scanScore",
            "sbom",
            "errors",
            "toolStatus",
            "raw_results",
            "summary",
        ]

    metadata = serializers.SerializerMethodField()
    cves = serializers.SerializerMethodField()
    secrets = serializers.SerializerMethodField()
    misconfigurations = serializers.SerializerMethodField()
    malware = serializers.SerializerMethodField()
    malwareScore = serializers.SerializerMethodField()
    scanScore = serializers.SerializerMethodField()
    sbom = serializers.SerializerMethodField()
    errors = serializers.SerializerMethodField()
    toolStatus = serializers.SerializerMethodField()
    raw_results = serializers.SerializerMethodField()

    def get_task(self, obj):
        return ScanStatusSerializer(obj).data

    def get_metadata(self, obj):
        metadata = dict((obj.normalized_results or {}).get("metadata", {}))
        metadata["asset"] = display_target(obj)
        return sanitize_for_display(metadata, obj)

    def get_cves(self, obj):
        return (obj.normalized_results or {}).get("cves", [])

    def get_secrets(self, obj):
        return (obj.normalized_results or {}).get("secrets", [])

    def get_misconfigurations(self, obj):
        return (obj.normalized_results or {}).get("misconfigurations", [])

    def get_malware(self, obj):
        return (obj.normalized_results or {}).get("malware", [])

    def get_malwareScore(self, obj):
        return (obj.normalized_results or {}).get("malwareScore", {})

    def get_scanScore(self, obj):
        return (obj.normalized_results or {}).get("scanScore", {})

    def get_sbom(self, obj):
        return (obj.normalized_results or {}).get("sbom", [])

    def get_errors(self, obj):
        return sanitize_for_display((obj.normalized_results or {}).get("errors", []), obj)

    def get_toolStatus(self, obj):
        return (obj.normalized_results or {}).get("toolStatus", [])

    def get_raw_results(self, obj):
        return sanitize_for_display(obj.raw_results or {}, obj)


class RecentScanSerializer(serializers.ModelSerializer):
    id = serializers.SerializerMethodField()
    taskId = serializers.SerializerMethodField()
    target = serializers.SerializerMethodField()
    type = serializers.SerializerMethodField()
    icon = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    severity = serializers.SerializerMethodField()
    updatedAt = serializers.SerializerMethodField()

    class Meta:
        model = ScanTask
        fields = ["id", "taskId", "target", "type", "icon", "status", "severity", "updatedAt"]

    def get_id(self, obj):
        return str(obj.id)[:5]

    def get_taskId(self, obj):
        return str(obj.id)

    def get_target(self, obj):
        return display_target(obj)

    def get_type(self, obj):
        return obj.get_input_type_display()

    def get_icon(self, obj):
        return {
            ScanTask.InputType.IMAGE: "docker",
            ScanTask.InputType.GIT: "github",
            ScanTask.InputType.DOCKERFILE: "file",
            ScanTask.InputType.FILE: "file",
        }.get(obj.input_type, "file")

    def get_status(self, obj):
        return {
            ScanTask.Status.SUCCESS: "Completed",
            ScanTask.Status.FAILED: "Failed",
            ScanTask.Status.PROCESSING: "Running",
            ScanTask.Status.PENDING: "Running",
        }.get(obj.status, obj.status)

    def get_severity(self, obj):
        summary = obj.summary or {}
        return {
            "Critical": int(summary.get("critical", 0)),
            "High": int(summary.get("high", 0)),
            "Medium": int(summary.get("medium", 0)),
            "Low": int(summary.get("low", 0)),
        }

    def get_updatedAt(self, obj):
        return obj.updated_at.isoformat()


class YaraRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = YaraRule
        fields = ["id", "name", "file_path", "is_active", "uploaded_at"]


class ScannerConfigSerializer(serializers.ModelSerializer):
    state = serializers.SerializerMethodField()

    class Meta:
        model = ScannerConfig
        fields = [
            "id",
            "tool_name",
            "display_name",
            "category",
            "enabled",
            "version_crawler_enabled",
            "db_check_enabled",
            "executable_path",
            "is_offline_mode",
            "local_db_path",
            "extra_args",
            "env",
            "supported_input_types",
            "binary_update_command",
            "database_update_command",
            "state",
            "updated_at",
        ]

    def get_state(self, obj):
        state, _ = ToolState.objects.get_or_create(tool=obj)
        return ToolStateSerializer(state).data


class ToolStateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ToolState
        fields = [
            "active",
            "health_state",
            "action_state",
            "current_version",
            "latest_version",
            "database_version",
            "database_status",
            "last_checked_at",
            "last_db_checked_at",
            "last_updated_at",
            "last_db_updated_at",
            "last_error",
            "logs",
            "metadata",
            "updated_at",
        ]


User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    roles = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "username", "email", "is_active", "is_staff", "is_superuser", "roles", "date_joined"]

    def get_roles(self, obj):
        roles = list(obj.groups.values_list("name", flat=True))
        if obj.is_superuser and "superuser" not in roles:
            roles.append("superuser")
        if obj.is_staff and "staff" not in roles:
            roles.append("staff")
        return roles


class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    roles = serializers.ListField(child=serializers.CharField(), required=False, write_only=True)

    class Meta:
        model = User
        fields = ["id", "username", "email", "password", "is_active", "is_staff", "roles"]

    def create(self, validated_data):
        roles = validated_data.pop("roles", [])
        password = validated_data.pop("password")
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        if roles:
            from django.contrib.auth.models import Group

            normalized_roles = ["admin" if role == "security-admin" else role for role in roles]
            user.groups.set([Group.objects.get_or_create(name=role)[0] for role in normalized_roles if role in {"admin", "analyst"}])
            if "admin" in normalized_roles:
                user.is_staff = True
                user.save(update_fields=["is_staff"])
        return user
