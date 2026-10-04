from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import (
    DashboardAPIView,
    AdminConfigAPIView,
    LogoutAPIView,
    MeAPIView,
    ScannerConfigDetailAPIView,
    ScanCreateAPIView,
    ScanResultsAPIView,
    ScanStatusAPIView,
    ToolStatusAPIView,
    ToolActionAPIView,
    ToolCrawlerAPIView,
    UserManagementAPIView,
    UserDetailAPIView,
    YaraRuleUploadAPIView,
    FileUploadAPIView,
)

urlpatterns = [
    path("api/v1/auth/login/", TokenObtainPairView.as_view(), name="token-obtain-pair"),
    path("api/v1/auth/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("api/v1/auth/logout/", LogoutAPIView.as_view(), name="auth-logout"),
    path("api/v1/auth/me/", MeAPIView.as_view(), name="auth-me"),
    path("api/v1/dashboard/", DashboardAPIView.as_view(), name="dashboard"),
    path("api/v1/scans/", ScanCreateAPIView.as_view(), name="scan-create"),
    path("api/v1/scans/<uuid:task_id>/status/", ScanStatusAPIView.as_view(), name="scan-status"),
    path("api/v1/scans/<uuid:task_id>/results/", ScanResultsAPIView.as_view(), name="scan-results"),
    path("api/v1/upload-file/", FileUploadAPIView.as_view(), name="file-upload"),
    path("api/v1/tools/", ToolStatusAPIView.as_view(), name="tool-status"),
    path("api/v1/admin/users/", UserManagementAPIView.as_view(), name="admin-users"),
    path("api/v1/admin/users/<int:user_id>/", UserDetailAPIView.as_view(), name="admin-user-detail"),
    path("api/v1/admin/config/", AdminConfigAPIView.as_view(), name="admin-config"),
    path("api/v1/admin/tools/", ToolStatusAPIView.as_view(), name="admin-tools"),
    path("api/v1/admin/tools/crawler/", ToolCrawlerAPIView.as_view(), name="admin-tool-crawler"),
    path("api/v1/admin/tools/<str:tool_name>/", ScannerConfigDetailAPIView.as_view(), name="admin-tool-detail"),
    path("api/v1/admin/tools/<str:tool_name>/actions/", ToolActionAPIView.as_view(), name="admin-tool-action"),
    path("api/v1/admin/yara-rules/", YaraRuleUploadAPIView.as_view(), name="admin-yara-rules"),
]
