"""
Celery Task Scheduler and Configuration for SentinelAI
Supports both Linux and native Windows execution.
"""
from celery import Celery
import os
import sys
import asyncio
import logging

# Set up logging
logger = logging.getLogger(__name__)

# Initialize Celery
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
celery_app = Celery(
    'sentinelai',
    broker=redis_url,
    backend=redis_url
)

# Configure Celery
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

# On Windows, default 'prefork' pool is unsupported by OS fork(). Enforce 'solo' pool.
if sys.platform == 'win32':
    celery_app.conf.update(
        worker_pool='solo',
    )

# Dummy ScanScheduler class to satisfy api/main.py imports
class ScanScheduler:
    """
    Scheduler interface for registering periodic scans
    """
    @staticmethod
    def schedule_scan(target_url: str, cron_expression: str) -> str:
        logger.info(f"Scheduled periodic scan for {target_url} with cron {cron_expression}")
        return "dummy_schedule_id"

# Backend background celery task to execute scans
@celery_app.task(name="sentinelai.automation.scheduler.run_scan_task")
def run_scan_task(target_url: str, max_depth: int = 3, max_pages: int = 100, modules: list = None) -> dict:
    """
    Celery task running a security scan inside Celery worker context
    """
    logger.info(f"Celery task run_scan_task started for target: {target_url}")
    
    from ..core.scanner import SecurityScanner, ScanConfig
    from ..models.database import async_session_maker
    
    if modules is None:
        modules = ['injection', 'xss', 'auth', 'config', 'api']
        
    async def _async_scan():
        config = ScanConfig(
            target_url=target_url,
            max_depth=max_depth,
            max_pages=max_pages,
            included_modules=modules,
            ai_analysis=True
        )
        async with async_session_maker() as session:
            scanner = SecurityScanner(config, db_session=session)
            status = await scanner.start_scan()
            report = scanner.get_report()
            await scanner.close()
            return report

    # Run the async scan inside synchronous Celery worker thread
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
    if loop.is_running():
        new_loop = asyncio.new_event_loop()
        try:
            result = new_loop.run_until_complete(_async_scan())
        finally:
            new_loop.close()
    else:
        result = loop.run_until_complete(_async_scan())
        
    logger.info(f"Celery task run_scan_task completed for target: {target_url}")
    return result
