"""
Metrics Service
Tracks application metrics
"""
from typing import Dict, Any
from datetime import datetime
from threading import Lock


class MetricsService:
    """Simple in-memory metrics tracking"""

    def __init__(self):
        self._metrics: Dict[str, Any] = {
            "total_events": 0,
            "ai_analyzed": 0,
            "threats_detected": 0,
            "sent_to_betterstack": 0,
            "failed_betterstack": 0,
            "last_event_time": None,
            "start_time": datetime.utcnow().isoformat()
        }
        self._lock = Lock()

    def increment(self, metric: str, value: int = 1):
        """Increment a metric"""
        with self._lock:
            if metric in self._metrics:
                self._metrics[metric] += value
            else:
                self._metrics[metric] = value

    def set(self, metric: str, value: Any):
        """Set a metric value"""
        with self._lock:
            self._metrics[metric] = value

    def get(self, metric: str) -> Any:
        """Get a metric value"""
        with self._lock:
            return self._metrics.get(metric)

    def get_all(self) -> Dict[str, Any]:
        """Get all metrics"""
        with self._lock:
            metrics = self._metrics.copy()

        # Calculate derived metrics
        if metrics["total_events"] > 0:
            metrics["threat_detection_rate"] = round(
                (metrics["threats_detected"] / metrics["total_events"]) * 100,
                2
            )
        else:
            metrics["threat_detection_rate"] = 0.0

        return metrics

    def reset(self):
        """Reset all metrics"""
        with self._lock:
            self._metrics = {
                "total_events": 0,
                "ai_analyzed": 0,
                "threats_detected": 0,
                "sent_to_betterstack": 0,
                "failed_betterstack": 0,
                "last_event_time": None,
                "start_time": datetime.utcnow().isoformat()
            }


# Global instance
metrics_service = MetricsService()