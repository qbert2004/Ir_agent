"""
Investigation API Router
API для запуска и управления расследованиями инцидентов
"""
from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

from app.services.investigation_service import investigation_service

router = APIRouter(prefix="/investigation", tags=["Investigation"])


class InvestigationRequest(BaseModel):
    """Запрос на расследование"""
    incident_id: str = Field(..., description="Уникальный ID инцидента")
    events: List[Dict[str, Any]] = Field(..., description="События для расследования")


@router.get("/status")
async def get_investigator_status():
    """
    Статус агента-расследователя
    """
    if not investigation_service.is_available:
        raise HTTPException(status_code=503, detail="Investigation service unavailable")

    stats = investigation_service.get_statistics()

    return {
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        **stats
    }


@router.post("/start")
async def start_investigation(request: InvestigationRequest):
    """
    Начать новое расследование кибер-инцидента

    Агент проведет полное расследование:
    1. Классификация типа инцидента
    2. Построение timeline атаки
    3. Извлечение IoC
    4. TTP анализ (MITRE ATT&CK)
    5. Root cause analysis
    6. Impact assessment
    7. Containment & remediation план
    8. Генерация отчета

    Args:
        request: ID инцидента и события для анализа

    Returns:
        Результат расследования
    """
    if not investigation_service.is_available:
        raise HTTPException(status_code=503, detail="Investigation service unavailable")

    if not request.events:
        raise HTTPException(status_code=400, detail="Events list cannot be empty")

    result = await investigation_service.start_investigation(
        request.incident_id,
        request.events
    )

    if result["status"] == "error":
        raise HTTPException(status_code=500, detail=result["message"])

    return result


@router.get("/list")
async def list_investigations():
    """
    Список всех расследований
    """
    if not investigation_service.is_available:
        raise HTTPException(status_code=503, detail="Investigation service unavailable")

    investigations = investigation_service.list_investigations()

    return {
        "total": len(investigations),
        "investigations": investigations
    }


@router.get("/{incident_id}/report")
async def get_investigation_report(incident_id: str, format: str = "text"):
    """
    Получить отчет о расследовании

    Args:
        incident_id: ID инцидента
        format: "text" или "json"

    Returns:
        Детальный отчет о расследовании
    """
    if not investigation_service.is_available:
        raise HTTPException(status_code=503, detail="Investigation service unavailable")

    if format not in ["text", "json"]:
        raise HTTPException(status_code=400, detail="Format must be 'text' or 'json'")

    report = investigation_service.get_report(incident_id, format=format)

    if report is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if format == "json":
        import json
        return json.loads(report)
    else:
        return {"report": report}


@router.post("/example")
async def run_example_investigation():
    """
    Запустить пример расследования ransomware атаки

    Демонстрирует работу агента на примере типичной ransomware атаки
    """
    if not investigation_service.is_available:
        raise HTTPException(status_code=503, detail="Investigation service unavailable")

    # Пример событий ransomware
    example_events = [
        {
            "timestamp": "2024-01-15T08:30:00Z",
            "event_id": "4624",
            "hostname": "WS-USER01",
            "event_type": "logon",
            "user": "john.doe",
            "description": "User logged in"
        },
        {
            "timestamp": "2024-01-15T08:35:00Z",
            "event_id": "4688",
            "hostname": "WS-USER01",
            "event_type": "process_creation",
            "process_name": "outlook.exe",
            "user": "john.doe",
            "description": "Outlook opened"
        },
        {
            "timestamp": "2024-01-15T08:37:00Z",
            "event_id": "4688",
            "hostname": "WS-USER01",
            "event_type": "process_creation",
            "process_name": "invoice_2024.exe",
            "parent_process": "outlook.exe",
            "user": "john.doe",
            "description": "Suspicious executable from email"
        },
        {
            "timestamp": "2024-01-15T08:38:00Z",
            "hostname": "WS-USER01",
            "event_type": "network",
            "destination_ip": "185.220.101.45",
            "destination_port": 443,
            "description": "Outbound connection to suspicious IP"
        },
        {
            "timestamp": "2024-01-15T08:40:00Z",
            "event_id": "4688",
            "hostname": "WS-USER01",
            "event_type": "process_creation",
            "process_name": "cmd.exe",
            "command_line": "cmd.exe /c vssadmin delete shadows /all /quiet",
            "description": "Shadow copies deletion"
        },
        {
            "timestamp": "2024-01-15T08:42:00Z",
            "hostname": "WS-USER01",
            "event_type": "file_access",
            "file_path": "C:\\Users\\john.doe\\Documents\\report.xlsx",
            "access_type": "write",
            "description": "File encryption started"
        },
        {
            "timestamp": "2024-01-15T08:45:00Z",
            "hostname": "WS-USER01",
            "event_type": "file_creation",
            "file_path": "C:\\Users\\john.doe\\Desktop\\README_DECRYPT.txt",
            "description": "Ransom note created"
        }
    ]

    incident_id = f"EXAMPLE-{datetime.utcnow().timestamp()}"

    result = await investigation_service.start_investigation(incident_id, example_events)

    if result["status"] == "success":
        # Получаем отчет
        report = investigation_service.get_report(result["incident_id"], format="json")

        return {
            "status": "success",
            "incident_id": result["incident_id"],
            "message": "Example investigation completed",
            "report_preview": "Get full report at /investigation/{incident_id}/report"
        }
    else:
        raise HTTPException(status_code=500, detail=result.get("message", "Failed"))
