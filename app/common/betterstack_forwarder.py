# app/common/betterstack_forwarder.py
"""
Better Stack Forwarder - ПРОСТАЯ ВЕРСИЯ
Просто отправляет события в Better Stack БЕЗ AI обработки
"""
import httpx
import logging
from typing import Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class BetterStackForwarder:
    """Отправляет логи в Better Stack"""

    def __init__(self, source_token: str):
        self.source_token = source_token
        # Твой Better Stack host
        self.url = "https://s1564996.eu-nbg-2.betterstackdata.com"
        self.client = httpx.AsyncClient(timeout=10.0)

        if source_token:
            logger.info(f"OK Better Stack forwarder initialized")
        else:
            logger.warning("WARNING  No Better Stack token")

    async def send_event(self, event: Dict[str, Any]) -> bool:
        """Отправляет одно событие в Better Stack"""
        if not self.source_token:
            return False

        try:
            # Формируем лог для Better Stack
            log_entry = {
                "dt": event.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                "message": event.get("message", self._format_message(event)),
                "level": event.get("level", "info"),

                # Основные поля
                "hostname": event.get("hostname", "unknown"),
                "event_type": event.get("event_type", "WindowsEvent"),
                "event_id": event.get("event_id", "unknown"),
                "channel": event.get("channel", "unknown"),
                "user": event.get("user", "N/A"),
            }

            # Добавляем дополнительные поля если есть
            if event.get("process_name"):
                log_entry["process"] = event["process_name"]
            if event.get("command_line"):
                log_entry["command"] = event["command_line"][:500]
            if event.get("script_block_text"):
                log_entry["script"] = event["script_block_text"][:500]
            if event.get("source_ip"):
                log_entry["source_ip"] = event["source_ip"]
            if event.get("process_id"):
                log_entry["process_id"] = str(event["process_id"])

            # Отправляем
            response = await self.client.post(
                self.url,
                json=log_entry,
                headers={
                    "Authorization": f"Bearer {self.source_token}",
                    "Content-Type": "application/json"
                }
            )

            if response.status_code in [200, 201, 202, 204]:
                return True
            else:
                logger.error(f"Better Stack error: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Failed to send to Better Stack: {e}")
            return False

    def _format_message(self, event: Dict[str, Any]) -> str:
        """Форматирует читаемое сообщение"""
        parts = []

        # Event info
        parts.append(f"[EventID {event.get('event_id', 'unknown')}]")
        parts.append(f"{event.get('user', 'N/A')}@{event.get('hostname', 'unknown')}")

        # Command или process
        if event.get("command_line"):
            cmd = event["command_line"][:80]
            parts.append(f"CMD: {cmd}")
        elif event.get("process_name"):
            parts.append(f"Process: {event['process_name']}")
        elif event.get("script_block_text"):
            script = event["script_block_text"][:80]
            parts.append(f"Script: {script}")

        return " | ".join(parts)

    async def close(self):
        """Закрыть клиент"""
        await self.client.aclose()