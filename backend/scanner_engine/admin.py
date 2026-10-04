from django.contrib import admin

from .models import ScanTask, ScannerConfig, ToolState, YaraRule

admin.site.site_header = "RootSecOps Administration"
admin.site.site_title = "RootSecOps Admin"
admin.site.index_title = "Security Administration"


@admin.register(ScanTask)
class ScanTaskAdmin(admin.ModelAdmin):
    list_display = ("id", "input_type", "target", "status", "progress", "created_at")
    list_filter = ("input_type", "status", "created_at")
    search_fields = ("id", "target")
    readonly_fields = ("id", "created_at", "updated_at")


@admin.register(ScannerConfig)
class ScannerConfigAdmin(admin.ModelAdmin):
    list_display = ("tool_name", "category", "enabled", "version_crawler_enabled", "db_check_enabled", "is_offline_mode", "updated_at")
    list_filter = ("category", "enabled", "is_offline_mode")
    search_fields = ("tool_name", "display_name", "executable_path")


@admin.register(YaraRule)
class YaraRuleAdmin(admin.ModelAdmin):
    list_display = ("name", "file_path", "is_active", "uploaded_at")
    list_filter = ("is_active",)


@admin.register(ToolState)
class ToolStateAdmin(admin.ModelAdmin):
    list_display = ("tool", "active", "health_state", "action_state", "current_version", "latest_version", "updated_at")
    list_filter = ("health_state", "action_state", "active")
    readonly_fields = ("updated_at",)
    search_fields = ("name", "file_path")
