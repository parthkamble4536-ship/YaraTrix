"""
YaraTrix Celery Application Configuration

Connects to Redis as the message broker and result backend.
The broker URL is read from the environment variable CELERY_BROKER_URL,
defaulting to a local Redis instance for development.
"""

import os

from celery import Celery

# Redis URL for both broker (task queue) and backend (result storage)
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

celery_app = Celery(
    "yaratrix",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
    include=["yaratrix.worker.tasks"],  # Auto-discover tasks
)

celery_app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    # Timezone
    timezone="UTC",
    enable_utc=True,
    # Task reliability settings
    task_acks_late=True,  # Acknowledge task only AFTER completion
    worker_prefetch_multiplier=1,  # One task per worker at a time (fair dispatch)
    # Result expiry: keep results in Redis for 24 hours
    result_expires=86400,
    # Task time limit (max 10 minutes per scan)
    task_time_limit=600,
    task_soft_time_limit=540,
)
