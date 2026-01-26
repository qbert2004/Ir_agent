"""
Investigation Service
Сервис для интеграции Cyber Incident Investigator в FastAPI
"""
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from cyber_incident_investigator import CyberIncidentInvestigator, InvestigationReport
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)


class InvestigationService:
    """
    Сервис для управления расследованиями инцидентов
    """

    _instance: Optional['InvestigationService'] = None
    _investigator: Optional[CyberIncidentInvestigator] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if self._investigator is None:
            try:
                self._investigator = CyberIncidentInvestigator()
                logger.info("Cyber Incident Investigator initialized")
            except Exception as e:
                logger.error(f"Failed to initialize investigator: {e}")
                self._investigator = None

    @property
    def investigator(self) -> Optional[CyberIncidentInvestigator]:
        return self._investigator

    @property
    def is_available(self) -> bool:
        return self._investigator is not None

    async def start_investigation(self, incident_id: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Начать новое расследование

        Args:
            incident_id: ID инцидента
            events: События для анализа

        Returns:
            Результат запуска расследования
        """
        if not self.is_available:
            return {
                "status": "unavailable",
                "message": "Investigation service not available"
            }

        try:
            result_id = await self._investigator.start_investigation(incident_id, events)

            return {
                "status": "success",
                "incident_id": result_id,
                "message": "Investigation completed successfully"
            }
        except Exception as e:
            logger.error(f"Investigation failed: {e}")
            return {
                "status": "error",
                "message": str(e)
            }

    def get_report(self, incident_id: str, format: str = "text") -> Optional[str]:
        """
        Получить отчет о расследовании

        Args:
            incident_id: ID инцидента
            format: "text" или "json"

        Returns:
            Отчет или None
        """
        if not self.is_available:
            return None

        try:
            return self._investigator.get_investigation_report(incident_id, format=format)
        except Exception as e:
            logger.error(f"Failed to get report: {e}")
            return None

    def list_investigations(self) -> List[str]:
        """Список всех расследований"""
        if not self.is_available:
            return []

        return self._investigator.list_investigations()

    def get_statistics(self) -> Dict[str, Any]:
        """Статистика"""
        if not self.is_available:
            return {"status": "unavailable"}

        return {
            "status": "available",
            "total_investigations": len(self._investigator.investigations),
            "investigations": self._investigator.list_investigations()
        }


# Глобальный экземпляр
investigation_service = InvestigationService()
