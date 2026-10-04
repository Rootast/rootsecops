import logging
import threading
import uuid
from uuid import UUID

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import close_old_connections
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.shortcuts import get_object_or_404
from django.utils.text import get_valid_filename
from django.utils import timezone
from rest_framework import status
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from .models import ScanTask, ScannerConfig, ToolState, YaraRule
from .permissions import IsAdminOrSecurityManager
from .serializers import (
    RecentScanSerializer,
    ScanCreateSerializer,
    ScanResultSerializer,
    ScanStatusSerializer,
    ScannerConfigSerializer,
    UserCreateSerializer,
    UserSerializer,
    ToolStateSerializer,
    YaraRuleSerializer,
)
from .tasks import crawl_tool_updates_task, process_scan_task, process_tool_action_task


audit_logger = logging.getLogger("scanner_engine.audit")


def audit_event(request, action: str, message: str, level: int = logging.INFO, **metadata):
    actor = getattr(request, "user", None)
    audit_logger.log(
        level,
        message,
        extra={
            "module_name": "api",
            "event_action": action,
            "actor_id": getattr(actor, "id", None),
            "actor_username": getattr(actor, "username", "anonymous"),
            "client_ip": _client_ip(request),
            "request_path": getattr(request, "path", ""),
            "request_method": getattr(request, "method", ""),
            **metadata,
        },
    )


def request_data_without_files(request):
    data = {}
    for key, value in request.data.items():
        if key in request.FILES:
            continue
        data[key] = value
    return data


def user_scan_queryset(user):
    queryset = ScanTask.objects.all()
    if user.is_staff or user.is_superuser or user.groups.filter(name__in=["admin", "security-admin"]).exists():
        return queryset
    return queryset.filter(owner=user)


def save_untrusted_upload(upload, destination_dir=None, max_size=None):
    max_size = max_size or settings.MAX_UPLOAD_SIZE
    if upload.size > max_size:
        raise ValueError(f"File exceeds max upload size of {max_size} bytes.")
    upload_dir = destination_dir or settings.SCANNER_WORK_DIR.parent / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    safe_name = get_valid_filename(upload.name) or "upload.bin"
    destination = upload_dir / f"{timezone.now().strftime('%Y%m%d%H%M%S%f')}_{uuid.uuid4().hex}_{safe_name}"
    with destination.open("wb+") as handle:
        for chunk in upload.chunks():
            handle.write(chunk)
    return destination


class DashboardAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        tasks = user_scan_queryset(request.user)
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        clean_images = 0

        for task in tasks:
            task_summary = task.summary or {}
            for key in summary:
                summary[key] += int(task_summary.get(key, 0))
            if task.status == ScanTask.Status.SUCCESS and sum(int(task_summary.get(k, 0)) for k in summary) == 0:
                clean_images += 1

        trend_rows = (
            tasks.annotate(day=TruncDate("created_at"))
            .values("day")
            .annotate(scans=Count("id"))
            .order_by("day")
        )
        trend = [
            {"day": row["day"].strftime("%a") if row["day"] else "", "scans": row["scans"]}
            for row in trend_rows
        ][-7:]

        active_workers = 1 if getattr(settings, "SCANNER_RUN_INLINE", True) else 0
        payload = {
            "metrics": {
                "totalScans": tasks.count(),
                "criticalVulnerabilities": summary["critical"],
                "cleanImages": clean_images,
                "activeWorkers": active_workers,
            },
            "vulnerabilityDistribution": [
                {"name": "Critical", "value": summary["critical"]},
                {"name": "High", "value": summary["high"]},
                {"name": "Medium", "value": summary["medium"]},
                {"name": "Low", "value": summary["low"]},
            ],
            "scanTrend": trend,
            "recentScans": RecentScanSerializer(tasks[:10], many=True).data,
            "workers": [
                {
                    "hostname": "inline-worker" if active_workers else "celery-worker",
                    "status": "active" if active_workers else "idle",
                    "load": "local" if active_workers else "unknown",
                }
            ],
        }
        return Response(payload)


class ScanCreateAPIView(APIView):
    parser_classes = [JSONParser, MultiPartParser, FormParser]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request_data_without_files(request)
        upload = request.FILES.get("file")
        if upload:
            raw_type = data.get("input_type") or data.get("asset_type")
            is_file_sandbox_upload = str(raw_type).lower() in {"file", "malware_file"}
            if is_file_sandbox_upload and not settings.FILE_SANDBOX_ENABLED:
                return Response({"detail": "File sandbox is disabled."}, status=status.HTTP_400_BAD_REQUEST)
            upload_dir = settings.FILE_SANDBOX_STORAGE_DIR if is_file_sandbox_upload else None
            max_size = settings.FILE_SANDBOX_MAX_UPLOAD_SIZE if is_file_sandbox_upload else settings.MAX_UPLOAD_SIZE
            try:
                destination = save_untrusted_upload(upload, upload_dir, max_size)
            except ValueError as exc:
                return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
            data["target"] = str(destination)

        serializer = ScanCreateSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        options = serializer.validated_data.get("options", {})
        options.setdefault("client_ip", _client_ip(request))
        task = ScanTask.objects.create(
            input_type=serializer.validated_data["input_type"],
            target=serializer.validated_data["target"],
            options=options,
            status=ScanTask.Status.PENDING,
            owner=request.user,
        )

        if getattr(settings, "SCANNER_RUN_INLINE", True):
            def run_inline_task():
                close_old_connections()
                try:
                    process_scan_task.apply(args=[str(task.id)])
                finally:
                    close_old_connections()

            threading.Thread(target=run_inline_task, daemon=True).start()
        else:
            process_scan_task.delay(str(task.id))

        task.refresh_from_db()
        return Response(
            {"task_id": str(task.id), "id": str(task.id), "status": task.status, "progress": task.progress},
            status=status.HTTP_202_ACCEPTED,
        )


class ScanStatusAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, task_id: UUID):
        task = get_object_or_404(user_scan_queryset(request.user), id=task_id)
        return Response(ScanStatusSerializer(task).data)


class ScanResultsAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, task_id: UUID):
        task = get_object_or_404(user_scan_queryset(request.user), id=task_id)
        return Response(ScanResultSerializer(task).data)


class YaraRuleUploadAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsAdminOrSecurityManager]

    def post(self, request):
        upload = request.FILES.get("file")
        name = request.data.get("name")
        is_active = str(request.data.get("is_active", "true")).lower() == "true"

        if not upload or not name:
            return Response({"detail": "name and file are required"}, status=status.HTTP_400_BAD_REQUEST)
        if not (upload.name.endswith(".yar") or upload.name.endswith(".yara") or upload.name.endswith(".rules")):
            return Response({"detail": "Invalid rule extension"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            destination = save_untrusted_upload(upload, settings.YARA_RULES_DIR)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        rule, _ = YaraRule.objects.update_or_create(
            name=name,
            defaults={"file_path": str(destination), "is_active": is_active},
        )
        return Response(YaraRuleSerializer(rule).data, status=status.HTTP_201_CREATED)


class ToolStatusAPIView(APIView):
    permission_classes = [IsAdminOrSecurityManager]

    def get(self, request):
        queryset = ScannerConfig.objects.all()
        return Response(ScannerConfigSerializer(queryset, many=True).data)

    def post(self, request):
        serializer = ScannerConfigSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        tool = serializer.save()
        return Response(ScannerConfigSerializer(tool).data, status=status.HTTP_201_CREATED)


class ScannerConfigDetailAPIView(APIView):
    permission_classes = [IsAdminOrSecurityManager]

    def patch(self, request, tool_name: str):
        tool = get_object_or_404(ScannerConfig, tool_name=tool_name)
        state_data = {}
        if "active" in request.data:
            state_data["active"] = _request_bool(request.data.get("active"))
        serializer = ScannerConfigSerializer(tool, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save(updated_at=timezone.now())
        if state_data:
            state, _ = ToolState.objects.get_or_create(tool=tool)
            for key, value in state_data.items():
                setattr(state, key, value)
            state.save(update_fields=[*state_data, "updated_at"])
            tool.refresh_from_db()
        return Response(serializer.data)

    def delete(self, request, tool_name: str):
        tool = get_object_or_404(ScannerConfig, tool_name=tool_name)
        tool.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ToolActionAPIView(APIView):
    permission_classes = [IsAdminOrSecurityManager]

    allowed_actions = {"check_version", "check_database", "update_binary", "update_database"}

    def post(self, request, tool_name: str):
        tool = get_object_or_404(ScannerConfig, tool_name=tool_name)
        action = request.data.get("action", "")
        if action not in self.allowed_actions:
            return Response({"detail": "Unsupported tool action."}, status=status.HTTP_400_BAD_REQUEST)
        if action == "update_binary" and not tool.binary_update_command:
            return Response(
                {
                    "detail": (
                        "Binary update is not configured for this tool. "
                        f"Set {tool.tool_name.upper().replace('-', '_')}_UPDATE_COMMAND or configure binary_update_command in admin."
                    ),
                    "state": ToolStateSerializer(ToolState.objects.get_or_create(tool=tool)[0]).data,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        state, _ = ToolState.objects.get_or_create(tool=tool)
        if state.action_state in {ToolState.ActionState.CHECKING, ToolState.ActionState.UPDATING}:
            return Response(
                {"detail": f"{tool_name} is already {state.action_state}.", "state": ToolStateSerializer(state).data},
                status=status.HTTP_409_CONFLICT,
            )

        state.action_state = ToolState.ActionState.CHECKING if action.startswith("check_") else ToolState.ActionState.UPDATING
        state.last_error = ""
        state.save(update_fields=["action_state", "last_error", "updated_at"])
        _dispatch_tool_action(tool_name, action)
        return Response({"tool": tool_name, "action": action, "state": ToolStateSerializer(state).data}, status=status.HTTP_202_ACCEPTED)


class ToolCrawlerAPIView(APIView):
    permission_classes = [IsAdminOrSecurityManager]

    def post(self, request):
        _dispatch_crawler()
        return Response({"detail": "Tool crawler started."}, status=status.HTTP_202_ACCEPTED)


class AdminConfigAPIView(APIView):
    permission_classes = [IsAdminOrSecurityManager]

    def put(self, request):
        tools_payload = request.data.get("tools", {})
        if not isinstance(tools_payload, dict):
            return Response({"detail": "tools must be an object keyed by tool name."}, status=status.HTTP_400_BAD_REQUEST)

        updated = []
        for tool_name, patch in tools_payload.items():
            if not isinstance(patch, dict):
                continue
            tool = get_object_or_404(ScannerConfig, tool_name=tool_name)
            state_patch = {}
            if "active" in patch:
                state_patch["active"] = _request_bool(patch.pop("active"))
            serializer = ScannerConfigSerializer(tool, data=patch, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save(updated_at=timezone.now())
            if state_patch:
                state, _ = ToolState.objects.get_or_create(tool=tool)
                for key, value in state_patch.items():
                    setattr(state, key, value)
                state.save(update_fields=[*state_patch, "updated_at"])
            tool.refresh_from_db()
            updated.append(ScannerConfigSerializer(tool).data)
        return Response({"tools": updated})


class FileUploadAPIView(APIView):
    """Upload temporary files for scanning (Dockerfile, etc)"""
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        upload = request.FILES.get("file")
        input_type = request.data.get("input_type", "DOCKERFILE")

        if not upload:
            return Response(
                {"detail": "file is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            destination = save_untrusted_upload(upload)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {
                "file_path": str(destination),
                "file_name": upload.name,
                "input_type": input_type,
                "size": upload.size,
            },
            status=status.HTTP_201_CREATED,
        )


class MeAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserSerializer(request.user).data)


class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if refresh_token:
            try:
                RefreshToken(refresh_token).blacklist()
            except TokenError:
                pass
        audit_event(request, "auth.logout", "User logged out.", target_user_id=request.user.id, target_username=request.user.username)
        return Response({"detail": "Logged out"}, status=status.HTTP_200_OK)


class UserManagementAPIView(APIView):
    permission_classes = [IsAdminOrSecurityManager]

    def get(self, request):
        return Response(UserSerializer(get_user_model().objects.order_by("username"), many=True).data)

    def post(self, request):
        serializer = UserCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        audit_event(
            request,
            "user.created",
            f"User account created: {user.username}",
            target_user_id=user.id,
            target_username=user.username,
            target_email=user.email,
            target_is_active=user.is_active,
            target_is_staff=user.is_staff,
            target_roles=list(user.groups.values_list("name", flat=True)),
            response_status=201,
        )
        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)


class UserDetailAPIView(APIView):
    permission_classes = [IsAdminOrSecurityManager]

    def patch(self, request, user_id: int):
        user = get_object_or_404(get_user_model(), id=user_id)
        if user.is_superuser and request.user.id != user.id:
            audit_event(
                request,
                "user.update_denied",
                f"Denied attempt to modify superuser account: {user.username}",
                logging.WARNING,
                target_user_id=user.id,
                target_username=user.username,
                reason="superuser_protected",
                response_status=400,
            )
            return Response({"detail": "Superuser accounts cannot be modified here."}, status=status.HTTP_400_BAD_REQUEST)
        before = {
            "is_active": user.is_active,
            "is_staff": user.is_staff,
            "roles": list(user.groups.values_list("name", flat=True)),
        }
        if "is_active" in request.data:
            user.is_active = _request_bool(request.data.get("is_active"))
        if "is_staff" in request.data:
            user.is_staff = _request_bool(request.data.get("is_staff"))
        if "roles" in request.data:
            from django.contrib.auth.models import Group

            roles = [role for role in request.data.get("roles", []) if role in {"admin", "analyst"}]
            user.groups.set([Group.objects.get_or_create(name=role)[0] for role in roles])
        user.save()
        after = {
            "is_active": user.is_active,
            "is_staff": user.is_staff,
            "roles": list(user.groups.values_list("name", flat=True)),
        }
        audit_event(
            request,
            "user.updated",
            f"User account updated: {user.username}",
            target_user_id=user.id,
            target_username=user.username,
            before=before,
            after=after,
            response_status=200,
        )
        return Response(UserSerializer(user).data)

    def delete(self, request, user_id: int):
        user = get_object_or_404(get_user_model(), id=user_id)
        if user.id == request.user.id:
            audit_event(
                request,
                "user.delete_denied",
                f"Denied attempt to delete own account: {user.username}",
                logging.WARNING,
                target_user_id=user.id,
                target_username=user.username,
                reason="self_delete_denied",
                response_status=400,
            )
            return Response({"detail": "You cannot delete your own account."}, status=status.HTTP_400_BAD_REQUEST)
        if user.is_superuser:
            audit_event(
                request,
                "user.delete_denied",
                f"Denied attempt to delete superuser account: {user.username}",
                logging.WARNING,
                target_user_id=user.id,
                target_username=user.username,
                reason="superuser_protected",
                response_status=400,
            )
            return Response({"detail": "Superuser accounts cannot be deleted here."}, status=status.HTTP_400_BAD_REQUEST)
        deleted_user = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_active": user.is_active,
            "is_staff": user.is_staff,
            "roles": list(user.groups.values_list("name", flat=True)),
        }
        user.delete()
        audit_event(
            request,
            "user.deleted",
            f"User account deleted: {deleted_user['username']}",
            target_user_id=deleted_user["id"],
            target_username=deleted_user["username"],
            deleted_user=deleted_user,
            response_status=204,
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


def _client_ip(request):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def _dispatch_tool_action(tool_name: str, action: str) -> None:
    if getattr(settings, "SCANNER_RUN_INLINE", True):
        def run_inline():
            close_old_connections()
            try:
                process_tool_action_task.apply(args=[tool_name, action])
            finally:
                close_old_connections()

        threading.Thread(target=run_inline, daemon=True).start()
    else:
        process_tool_action_task.delay(tool_name, action)


def _dispatch_crawler() -> None:
    if getattr(settings, "SCANNER_RUN_INLINE", True):
        def run_inline():
            close_old_connections()
            try:
                crawl_tool_updates_task.apply()
            finally:
                close_old_connections()

        threading.Thread(target=run_inline, daemon=True).start()
    else:
        crawl_tool_updates_task.delay()


def _request_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
