from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import ScanTask


def display_target(task: ScanTask) -> str:
    if task.input_type in {ScanTask.InputType.DOCKERFILE, ScanTask.InputType.FILE}:
        return Path(str(task.target)).name
    return task.target


def sanitize_for_display(value: Any, task: ScanTask) -> Any:
    full_target = str(task.target)
    short_target = display_target(task)
    if isinstance(value, str):
        sanitized = value.replace(full_target, short_target)
        if task.input_type in {ScanTask.InputType.DOCKERFILE, ScanTask.InputType.FILE}:
            return sanitized.replace(str(Path(full_target).parent) + "/", "")
        return sanitized
    if isinstance(value, list):
        return [sanitize_for_display(item, task) for item in value]
    if isinstance(value, dict):
        return {key: sanitize_for_display(item, task) for key, item in value.items()}
    return value
