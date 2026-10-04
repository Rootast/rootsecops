from celery import shared_task

from scanner_engine.core.orchestrator import run_scan
from scanner_engine.core.tool_updates import (
    check_tool_database,
    check_tool_version,
    crawl_enabled_tools,
    update_tool_binary,
    update_tool_database,
)
from scanner_engine.models import ScanTask, ScannerConfig


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=1)
def process_scan_task(self, task_id: str):
    task = ScanTask.objects.get(id=task_id)
    task.status = ScanTask.Status.PROCESSING
    task.progress = 5
    task.error_message = ""
    task.logs = [f"[INFO] Scan {task.id} accepted"]
    task.save(update_fields=["status", "progress", "error_message", "logs", "updated_at"])

    try:
        output = run_scan(task)
        task.raw_results = output["raw_results"]
        task.normalized_results = output["normalized_results"]
        task.summary = output["summary"]
        task.logs = output["logs"]
        task.progress = 100
        tool_status = output["raw_results"].get("_tool_status", [])
        successful_tools = [item for item in tool_status if item.get("status") == "success"]
        task.status = ScanTask.Status.SUCCESS if successful_tools else ScanTask.Status.FAILED
        if not successful_tools:
            task.error_message = "No scanner completed successfully. Check tool installation errors in logs/results."
        task.save(
            update_fields=[
                "raw_results",
                "normalized_results",
                "summary",
                "logs",
                "error_message",
                "progress",
                "status",
                "updated_at",
            ]
        )
        return {"task_id": str(task.id), "status": task.status}
    except Exception as exc:
        task.status = ScanTask.Status.FAILED
        task.error_message = str(exc)[:4000]
        task.logs = [*task.logs, f"[ERROR] {task.error_message}"]
        task.save(update_fields=["status", "error_message", "logs", "updated_at"])
        raise


@shared_task(bind=True, autoretry_for=(), max_retries=0)
def process_tool_action_task(self, tool_name: str, action: str):
    config = ScannerConfig.objects.get(tool_name=tool_name)
    actions = {
        "check_version": check_tool_version,
        "check_database": check_tool_database,
        "update_binary": update_tool_binary,
        "update_database": update_tool_database,
    }
    if action not in actions:
        raise ValueError(f"Unsupported tool action: {action}")
    state = actions[action](config)
    return {"tool": tool_name, "action": action, "state": state.action_state}


@shared_task(bind=True, autoretry_for=(), max_retries=0)
def crawl_tool_updates_task(self):
    states = crawl_enabled_tools()
    return {"checked": len(states)}
