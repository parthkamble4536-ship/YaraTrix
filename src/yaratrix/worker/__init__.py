"""Worker module for YaraTrix v2 distributed scanning."""

from .celery_app import celery_app
from .tasks import scan_file_async

__all__ = ["celery_app", "scan_file_async"]
