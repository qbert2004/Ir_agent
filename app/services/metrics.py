"""
Metrics Service
Tracks application metrics (in-memory, resets on restart).

Note on locking: MetricsService is called from both sync and async contexts.
threading.Lock is used intentionally — increment() is a microsecond operation,
so it never blocks the event loop meaningfully. asyncio.Lock would require
await on every counter increment throughout the codebase.
"""
from typing import Dict, Any
from datetime import datetime
from threading import Lock


class MetricsService:
    """Simple in-memory metrics tracking."""

    def __init__(self):
        self._metrics: Dict[str, Any] = {
            "total_events": 0,
            "ai_analyzed": 0,
            "threats_detected": 0,
            "sent_to_betterstack": 0,
            "failed_betterstack": 0,
            "last_event_time": None,
            "start_time": datetime.utcnow().isoformat(),
        }
        self._lock = Lock()

    def increment(self, metric: str, value: int = 1) -> None:
        """Increment a counter metric."""
        with self._lock:
            if metric in self._metrics and isinstance(self._metrics[metric], int):
                self._metrics[metric] += value
            else:
                self._metrics[metric] = value

    def set(self, metric: str, value: Any) -> None:
        """Set a metric value."""
        with self._lock:
            self._metrics[metric] = value

    def get(self, metric: str) -> Any:
        """Get a metric value."""
        with self._lock:
            return self._metrics.get(metric)

    def get_all(self) -> Dict[str, Any]:
        """Get a snapshot of all metrics with derived calculations."""
        with self._lock:
            metrics = self._metrics.copy()

        total = metrics.get("total_events", 0)
        detected = metrics.get("threats_detected", 0)
        metrics["threat_detection_rate"] = (
            round((detected / total) * 100, 2) if total > 0 else 0.0
        )
        return metrics

    def reset(self) -> None:
        """Reset all counters (useful for testing)."""
        with self._lock:
            self._metrics = {
                "total_events": 0,
                "ai_analyzed": 0,
                "threats_detected": 0,
                "sent_to_betterstack": 0,
                "failed_betterstack": 0,
                "last_event_time": None,
                "start_time": datetime.utcnow().isoformat(),
            }


# Singleton
metrics_service = MetricsService()
