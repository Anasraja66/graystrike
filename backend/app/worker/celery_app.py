"""
Celery Worker Configuration — Graceful fallback if Celery/Redis not running
"""
from app.core.config import settings

try:
    from celery import Celery
    celery_app = Celery(
        "apt_agents",
        broker=settings.REDIS_URL,
        backend=settings.REDIS_URL,
        include=["app.worker.tasks"]
    )
    celery_app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_acks_late=True,
        worker_prefetch_multiplier=1,
    )
except ImportError:
    celery_app = None
