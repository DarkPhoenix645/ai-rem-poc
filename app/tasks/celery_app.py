from celery import Celery

from app.config import get_settings

settings = get_settings()

# Create Celery app
celery_app = Celery(
    "iam-scanner",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.tasks.scan_tasks"]
)

# Configuration
celery_app.conf.update(
    task_serializer=settings.celery_task_serializer,
    accept_content=[settings.celery_accept_content],
    result_serializer=settings.celery_result_serializer,
    timezone=settings.celery_timezone,
    enable_utc=settings.celery_enable_utc,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_max_tasks_per_child=100,
)
