"""
Async Worker Pool - Alert Triage Service
AI-Augmented SOC

Priority-based async worker pool for LLM triage. Handles incident-scale
alert volume by:
- Processing high-severity alerts first
- Running configurable concurrent LLM calls
- Circuit breaker: skip LLM for low-severity when queue is deep
"""

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Optional, Dict, Any, Callable, Awaitable

logger = logging.getLogger(__name__)

# Priority: lower number = higher priority
SEVERITY_PRIORITY = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}


class JobStatus:
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CIRCUIT_BREAKER = "circuit_breaker"


@dataclass(order=True)
class PriorityJob:
    """A prioritized triage job. Lower priority number = processed first."""
    priority: int
    job_id: str = field(compare=False)
    alert_data: Dict[str, Any] = field(compare=False)
    created_at: float = field(compare=False, default_factory=time.time)
    callback_url: Optional[str] = field(compare=False, default=None)


@dataclass
class JobResult:
    """Result of an async triage job."""
    job_id: str
    status: str
    alert_id: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: Optional[str] = None
    completed_at: Optional[str] = None
    processing_time_ms: Optional[int] = None
    circuit_breaker_applied: bool = False


class WorkerPool:
    """
    Async worker pool with priority queue and circuit breaker.

    Workers consume from a priority queue (high severity first).
    When queue depth exceeds threshold, low-severity alerts get
    ML-only results without LLM analysis.
    """

    def __init__(
        self,
        analyze_fn: Callable,
        ml_only_fn: Optional[Callable] = None,
        worker_count: int = 3,
        queue_threshold: int = 50,
        circuit_breaker_enabled: bool = True,
    ):
        self.analyze_fn = analyze_fn
        self.ml_only_fn = ml_only_fn
        self.worker_count = worker_count
        self.queue_threshold = queue_threshold
        self.circuit_breaker_enabled = circuit_breaker_enabled

        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._results: Dict[str, JobResult] = {}
        self._workers: list = []
        self._running = False
        self._jobs_processed = 0
        self._jobs_circuit_broken = 0

    async def start(self):
        """Start worker tasks."""
        if self._running:
            return
        self._running = True
        for i in range(self.worker_count):
            task = asyncio.create_task(self._worker(f"worker-{i}"))
            self._workers.append(task)
        logger.info(f"Worker pool started: {self.worker_count} workers")

    async def stop(self):
        """Stop all workers gracefully."""
        self._running = False
        # Send poison pills
        for _ in self._workers:
            await self._queue.put(PriorityJob(priority=999, job_id="STOP", alert_data={}))
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        logger.info("Worker pool stopped")

    def submit(self, alert_data: Dict[str, Any], callback_url: Optional[str] = None) -> str:
        """
        Submit an alert for async triage. Returns job_id immediately.

        High-severity alerts are processed first via priority queue.
        """
        job_id = f"job-{uuid.uuid4().hex[:8]}"
        alert_id = alert_data.get("alert_id", "unknown")

        # Determine priority from rule_level or explicit severity
        rule_level = alert_data.get("rule_level", 5)
        if rule_level >= 12:
            priority = SEVERITY_PRIORITY["critical"]
        elif rule_level >= 10:
            priority = SEVERITY_PRIORITY["high"]
        elif rule_level >= 7:
            priority = SEVERITY_PRIORITY["medium"]
        else:
            priority = SEVERITY_PRIORITY["low"]

        job = PriorityJob(
            priority=priority,
            job_id=job_id,
            alert_data=alert_data,
            callback_url=callback_url,
        )

        self._results[job_id] = JobResult(
            job_id=job_id,
            status=JobStatus.QUEUED,
            alert_id=alert_id,
            created_at=datetime.utcnow().isoformat(),
        )

        self._queue.put_nowait(job)
        logger.info(
            f"Job {job_id} queued: alert={alert_id}, priority={priority}, "
            f"queue_depth={self._queue.qsize()}"
        )
        return job_id

    def get_job(self, job_id: str) -> Optional[JobResult]:
        """Get the status/result of a job."""
        return self._results.get(job_id)

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "queue_depth": self._queue.qsize(),
            "workers": self.worker_count,
            "jobs_processed": self._jobs_processed,
            "jobs_circuit_broken": self._jobs_circuit_broken,
            "circuit_breaker_active": (
                self.circuit_breaker_enabled
                and self._queue.qsize() > self.queue_threshold
            ),
        }

    async def _worker(self, name: str):
        """Worker loop: consume from priority queue and process."""
        logger.debug(f"{name} started")

        while self._running:
            try:
                job = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            if job.job_id == "STOP":
                break

            job_result = self._results.get(job.job_id)
            if not job_result:
                continue

            job_result.status = JobStatus.PROCESSING
            start_time = time.time()

            try:
                # Circuit breaker: skip LLM for low-priority when queue is deep
                if (
                    self.circuit_breaker_enabled
                    and self._queue.qsize() > self.queue_threshold
                    and job.priority >= SEVERITY_PRIORITY["medium"]
                    and self.ml_only_fn is not None
                ):
                    logger.info(
                        f"{name}: Circuit breaker for {job.job_id} "
                        f"(queue={self._queue.qsize()}, priority={job.priority})"
                    )
                    result = await self.ml_only_fn(job.alert_data)
                    job_result.circuit_breaker_applied = True
                    self._jobs_circuit_broken += 1
                else:
                    result = await self.analyze_fn(job.alert_data)

                elapsed = int((time.time() - start_time) * 1000)

                if result is not None:
                    job_result.status = JobStatus.COMPLETED
                    job_result.result = (
                        result.model_dump(mode="json")
                        if hasattr(result, "model_dump")
                        else result
                    )
                else:
                    job_result.status = JobStatus.FAILED
                    job_result.error = "Analysis returned None"

                job_result.completed_at = datetime.utcnow().isoformat()
                job_result.processing_time_ms = elapsed
                self._jobs_processed += 1

                logger.info(
                    f"{name}: {job.job_id} {job_result.status} in {elapsed}ms"
                )

            except Exception as e:
                job_result.status = JobStatus.FAILED
                job_result.error = str(e)
                job_result.completed_at = datetime.utcnow().isoformat()
                logger.error(f"{name}: {job.job_id} failed: {e}")

            finally:
                self._queue.task_done()

        logger.debug(f"{name} stopped")
