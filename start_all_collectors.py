"""
Unified IR-Agent Collector
Объединённый сборщик ВСЕГО:
- Windows Security Events (расширенный)
- PowerShell Activity
- Process & Network Monitoring
- System Metrics (CPU, Memory, Disk, Network)
- Service Health
- Real-time Anomaly Detection
"""
import win32evtlog
import win32service
import win32serviceutil
import psutil
import platform
import socket
import time
import requests
import json
from datetime import datetime
from typing import Dict, Any, List
from collections import defaultdict
import ctypes
import os

# ==================== НАСТРОЙКИ ====================
API_URL = os.getenv("API_URL", "http://localhost:9000/ingest/telemetry")
API_TOKEN = os.getenv("MY_API_TOKEN", "")
BETTER_STACK_TOKEN = os.getenv("BETTER_STACK_SOURCE_TOKEN", "")
BETTER_STACK_URL = os.getenv("BETTER_STACK_URL", "https://s1564996.eu-nbg-2.betterstackdata.com")

# Интервалы сбора
EVENT_CHECK_INTERVAL = 10  # События каждые 10 секунд
METRICS_INTERVAL = 30      # Метрики каждые 30 секунд
BATCH_SIZE = 100

# ==================== КОНФИГУРАЦИЯ МОНИТОРИНГА ====================
EVENT_CHANNELS = {
    "Security": {
        "event_ids": [
            4688, 4689,  # Process Creation/Termination
            4624, 4625, 4648,  # Logon events
            4672,  # Special Privileges
            4720, 4722, 4723, 4724, 4725, 4726,  # User Account Management
            4732, 4733, 4756,  # Group Management
            4740,  # Account Lockout
            4768, 4769,  # Kerberos
            5140, 5145,  # Network Share Access
        ],
        "severity_map": {
            4625: "warning", 4740: "warning",
            4720: "info", 4688: "info",
        }
    },
    "Microsoft-Windows-PowerShell/Operational": {
        "event_ids": [4103, 4104, 4105, 4106],
        "severity_map": {4104: "warning"}
    },
    "System": {
        "event_ids": [7045, 7036, 7040, 1074, 6005, 6006],
        "severity_map": {7045: "warning", 1074: "info"}
    },
    "Application": {
        "event_ids": [1000, 1001, 1002],
        "severity_map": {1000: "warning", 1001: "warning", 1002: "error"}
    }
}

SUSPICIOUS_KEYWORDS = [
    "invoke-expression", "iex", "invoke-command", "downloadstring", "downloadfile",
    "invoke-webrequest", "iwr", "curl", "wget", "-enc", "-e ", "frombase64",
    "mimikatz", "invoke-mimikatz", "dumpcreds", "powersploit", "empire",
    "bloodhound", "rubeus", "bypass", "noprofile", "-nop", "hidden",
    "amsi", "etw", "reflection", "psexec", "winrs", "wmic process",
    "sekurlsa", "lsadump", "ntds.dit", "procdump", "comsvcs.dll",
]

SUSPICIOUS_PROCESSES = [
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe", "psexec.exe", "wmic.exe",
]

CRITICAL_SERVICES = [
    'EventLog', 'WinDefend', 'W32Time', 'Dnscache', 'BITS',
    'wuauserv', 'Schedule', 'LanmanServer', 'RpcSs', 'SamSs',
]


class UnifiedCollector:
    """Единый коллектор для всех типов данных"""

    def __init__(self):
        self.hostname = socket.gethostname()
        self.last_record_numbers = {}
        self.event_stats = defaultdict(int)
        self.metrics_stats = {"iterations": 0, "anomalies": 0}
        self.last_metrics_time = time.time()

        # Для детекции аномалий
        self.process_baseline = {}
        self.network_baseline = {}

        self._print_banner()

    def _print_banner(self):
        """Красивый баннер"""
        print("=" * 80)
        print("🚀 UNIFIED IR-AGENT COLLECTOR")
        print("=" * 80)
        print(f"🖥️  Hostname: {self.hostname}")
        print(f"💻 OS: {platform.system()} {platform.release()}")
        print(f"📡 API: {API_URL}")
        print(f"🤖 Pipeline: Collector → API → ML+Agent → Better Stack")
        print("-" * 80)
        print("📌 MONITORING:")
        total_events = sum(len(ch['event_ids']) for ch in EVENT_CHANNELS.values())
        print(f"  • {total_events} Windows Event types")
        print(f"  • {len(CRITICAL_SERVICES)} Critical Services")
        print(f"  • {len(SUSPICIOUS_KEYWORDS)} Suspicious Patterns")
        print(f"  • System Metrics (CPU, Memory, Disk, Network)")
        print(f"  • Process & Network Monitoring")
        print("-" * 80)
        print(f"⏱️  Events: every {EVENT_CHECK_INTERVAL}s | Metrics: every {METRICS_INTERVAL}s")
        print("=" * 80 + "\n")

    # ==================== WINDOWS EVENTS ====================

    def collect_windows_events(self) -> List[Dict]:
        """Собирает Windows события из всех каналов"""
        all_events = []

        for channel, config in EVENT_CHANNELS.items():
            try:
                events = self._read_events_from_channel(channel, config)
                if events:
                    all_events.extend(events)
                    print(f"  📥 {channel}: {len(events)} events")
            except Exception as e:
                print(f"  ⚠️  {channel}: {e}")

        return all_events

    def _read_events_from_channel(self, channel: str, config: Dict) -> List[Dict]:
        """Читает события из канала"""
        try:
            hand = win32evtlog.OpenEventLog(None, channel)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            events = []

            while len(events) < BATCH_SIZE:
                records = win32evtlog.ReadEventLog(hand, flags, 0)
                if not records:
                    break

                for record in records:
                    if channel in self.last_record_numbers:
                        if record.RecordNumber <= self.last_record_numbers[channel]:
                            win32evtlog.CloseEventLog(hand)
                            return events

                    event_id = record.EventID & 0xFFFF
                    if event_id in config["event_ids"]:
                        event = self._parse_event(record, channel, config)
                        if event:
                            events.append(event)
                            self.event_stats[f"{channel}:{event_id}"] += 1

                    if len(events) >= BATCH_SIZE:
                        break

            if records:
                self.last_record_numbers[channel] = records[0].RecordNumber

            win32evtlog.CloseEventLog(hand)
            return events

        except Exception as e:
            return []

    def _parse_event(self, record, channel: str, config: Dict) -> Dict:
        """Парсит событие"""
        event_id = record.EventID & 0xFFFF
        strings = record.StringInserts or []

        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "hostname": self.hostname,
            "data_type": "security_event",
            "event_id": event_id,
            "channel": channel,
            "source_name": record.SourceName,
        }

        severity_map = config.get("severity_map", {})
        event["severity"] = severity_map.get(event_id, "info")

        # Парсим по типу
        try:
            if event_id == 4688:
                event.update(self._parse_process_creation(strings))
            elif event_id == 4624:
                event.update(self._parse_logon(strings, success=True))
            elif event_id == 4625:
                event.update(self._parse_logon(strings, success=False))
            elif event_id == 4104:
                event.update(self._parse_powershell(strings))
            elif event_id == 7045:
                event.update(self._parse_service_installed(strings))
            elif event_id in [4720, 4722, 4725, 4726]:
                event.update(self._parse_user_change(strings, event_id))
            else:
                event["message"] = " | ".join(str(s) for s in strings[:3] if s)
        except:
            pass

        event["suspicious"] = self._is_suspicious(event)
        if event["suspicious"]:
            event["severity"] = "warning"

        return event

    def _parse_process_creation(self, strings: List) -> Dict:
        try:
            return {
                "action": "process_creation",
                "user": strings[1] if len(strings) > 1 else "SYSTEM",
                "process_name": strings[5] if len(strings) > 5 else "",
                "process_id": strings[4] if len(strings) > 4 else "",
                "command_line": strings[8] if len(strings) > 8 else "",
                "parent_process": strings[13] if len(strings) > 13 else "",
                "message": f"Process: {strings[5] if len(strings) > 5 else ''}",
            }
        except:
            return {}

    def _parse_logon(self, strings: List, success: bool) -> Dict:
        try:
            if success:
                return {
                    "action": "logon_success",
                    "user": strings[5] if len(strings) > 5 else "",
                    "logon_type": strings[8] if len(strings) > 8 else "",
                    "source_ip": strings[18] if len(strings) > 18 else "",
                    "message": f"Logon: {strings[5] if len(strings) > 5 else ''}",
                }
            else:
                return {
                    "action": "logon_failure",
                    "user": strings[5] if len(strings) > 5 else "",
                    "source_ip": strings[19] if len(strings) > 19 else "",
                    "failure_reason": strings[10] if len(strings) > 10 else "",
                    "message": f"Failed logon: {strings[5] if len(strings) > 5 else ''}",
                }
        except:
            return {}

    def _parse_powershell(self, strings: List) -> Dict:
        try:
            script_text = strings[2] if len(strings) > 2 else ""
            return {
                "action": "powershell_execution",
                "user": strings[1] if len(strings) > 1 else "",
                "script_block_text": script_text[:1000],
                "message": "PowerShell script executed",
            }
        except:
            return {}

    def _parse_service_installed(self, strings: List) -> Dict:
        try:
            return {
                "action": "service_installed",
                "service_name": strings[0] if len(strings) > 0 else "",
                "service_file": strings[1] if len(strings) > 1 else "",
                "message": f"Service: {strings[0] if len(strings) > 0 else ''}",
            }
        except:
            return {}

    def _parse_user_change(self, strings: List, event_id: int) -> Dict:
        actions = {4720: "user_created", 4722: "user_enabled",
                   4725: "user_disabled", 4726: "user_deleted"}
        try:
            return {
                "action": actions.get(event_id, "user_change"),
                "user": strings[0] if len(strings) > 0 else "",
                "target_user": strings[4] if len(strings) > 4 else "",
                "message": f"User: {actions.get(event_id, 'change')}",
            }
        except:
            return {}

    def _is_suspicious(self, event: Dict) -> bool:
        """Проверка на подозрительность"""
        text_fields = [
            event.get("command_line", ""),
            event.get("script_block_text", ""),
            event.get("service_file", ""),
        ]
        combined = " ".join(text_fields).lower()

        if any(kw in combined for kw in SUSPICIOUS_KEYWORDS):
            return True

        process = event.get("process_name", "").lower()
        if any(sp in process for sp in SUSPICIOUS_PROCESSES):
            return True

        if event.get("action") in ["logon_failure", "service_installed"]:
            return True

        return False

    # ==================== SYSTEM METRICS ====================

    def collect_system_metrics(self) -> Dict:
        """Собирает системные метрики"""
        metrics = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "hostname": self.hostname,
            "data_type": "system_metrics",
            "platform": platform.system(),
        }

        # CPU
        cpu_percent = psutil.cpu_percent(interval=1)
        metrics.update({
            "cpu_percent": cpu_percent,
            "cpu_count": psutil.cpu_count(),
        })

        # Memory
        mem = psutil.virtual_memory()
        metrics.update({
            "memory_total_mb": round(mem.total / (1024**2), 2),
            "memory_used_mb": round(mem.used / (1024**2), 2),
            "memory_percent": mem.percent,
            "memory_available_mb": round(mem.available / (1024**2), 2),
        })

        # Disk
        disk = psutil.disk_usage('C:/')
        disk_io = psutil.disk_io_counters()
        metrics.update({
            "disk_total_gb": round(disk.total / (1024**3), 2),
            "disk_used_gb": round(disk.used / (1024**3), 2),
            "disk_percent": disk.percent,
            "disk_read_bytes": disk_io.read_bytes,
            "disk_write_bytes": disk_io.write_bytes,
        })

        # Network
        net = psutil.net_io_counters()
        connections = psutil.net_connections(kind='inet')
        metrics.update({
            "net_bytes_sent": net.bytes_sent,
            "net_bytes_recv": net.bytes_recv,
            "net_packets_sent": net.packets_sent,
            "net_packets_recv": net.packets_recv,
            "active_connections": len(connections),
            "established_connections": len([c for c in connections if c.status == 'ESTABLISHED']),
        })

        # Processes
        processes = list(psutil.process_iter(['name', 'cpu_percent']))
        metrics["total_processes"] = len(processes)

        # Аномалии
        anomalies = self._detect_metric_anomalies(metrics)
        metrics.update(anomalies)

        return metrics

    def _detect_metric_anomalies(self, metrics: Dict) -> Dict:
        """Детекция аномалий в метриках"""
        anomalies = []
        severity = "info"

        if metrics['cpu_percent'] > 90:
            anomalies.append("Critical CPU (>90%)")
            severity = "critical"
        elif metrics['cpu_percent'] > 70:
            anomalies.append("High CPU (>70%)")
            severity = "warning"

        if metrics['memory_percent'] > 90:
            anomalies.append("Critical Memory (>90%)")
            severity = "critical"
        elif metrics['memory_percent'] > 80:
            anomalies.append("High Memory (>80%)")
            severity = "warning"

        if metrics['disk_percent'] > 95:
            anomalies.append("Disk full (>95%)")
            severity = "critical"
        elif metrics['disk_percent'] > 85:
            anomalies.append("Disk filling (>85%)")
            severity = "warning"

        return {
            "has_anomalies": len(anomalies) > 0,
            "anomalies": ", ".join(anomalies) if anomalies else "None",
            "anomaly_count": len(anomalies),
            "severity": severity,
            "message": f"CPU:{metrics['cpu_percent']:.1f}% MEM:{metrics['memory_percent']:.1f}% DISK:{metrics['disk_percent']:.1f}%"
        }

    # ==================== PROCESS & NETWORK MONITORING ====================

    def collect_process_monitoring(self) -> List[Dict]:
        """Мониторинг подозрительных процессов"""
        events = []

        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            try:
                pinfo = proc.info
                if not pinfo['name']:
                    continue

                cmdline = " ".join(pinfo.get('cmdline', []) or [])
                if any(kw in cmdline.lower() for kw in SUSPICIOUS_KEYWORDS):
                    events.append({
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "hostname": self.hostname,
                        "data_type": "process_monitoring",
                        "action": "suspicious_process",
                        "process_name": pinfo['name'],
                        "process_id": pinfo['pid'],
                        "user": pinfo.get('username', 'SYSTEM'),
                        "command_line": cmdline[:500],
                        "suspicious": True,
                        "severity": "warning",
                        "message": f"Suspicious: {pinfo['name']}",
                    })
            except:
                continue

        return events

    def collect_network_monitoring(self) -> List[Dict]:
        """Мониторинг сетевых аномалий"""
        events = []

        try:
            connections = psutil.net_connections(kind='inet')
            remote_ips = defaultdict(int)

            for conn in connections:
                if conn.raddr:
                    remote_ips[conn.raddr.ip] += 1

            for ip, count in remote_ips.items():
                if count > 20 and ip not in ['127.0.0.1', '::1']:
                    events.append({
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "hostname": self.hostname,
                        "data_type": "network_monitoring",
                        "action": "high_connection_count",
                        "remote_ip": ip,
                        "connection_count": count,
                        "suspicious": True,
                        "severity": "warning",
                        "message": f"High connections to {ip}: {count}",
                    })
        except:
            pass

        return events

    def collect_service_health(self) -> List[Dict]:
        """Проверка критичных сервисов"""
        events = []

        for service in CRITICAL_SERVICES:
            try:
                status = win32serviceutil.QueryServiceStatus(service)[1]
                if status != win32service.SERVICE_RUNNING:
                    events.append({
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "hostname": self.hostname,
                        "data_type": "service_monitoring",
                        "action": "service_down",
                        "service_name": service,
                        "suspicious": True,
                        "severity": "error",
                        "message": f"Service down: {service}",
                    })
            except:
                continue

        return events

    # ==================== ОТПРАВКА ДАННЫХ ====================

    def send_to_api(self, data: List[Dict]) -> bool:
        """
        Отправка в IR-Agent API для ML фильтрации + Agent анализа.
        API сам решает что отправлять в Better Stack.
        """
        if not data:
            return True

        try:
            response = requests.post(
                API_URL,
                json=data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {API_TOKEN}",
                },
                timeout=10
            )
            if response.status_code == 200:
                result = response.json()
                return result.get("status") == "success"
            return False
        except requests.exceptions.ConnectionError:
            print(f"  ⚠️  API not available at {API_URL}")
            return False
        except Exception as e:
            print(f"  ⚠️  API error: {e}")
            return False

    def _map_severity(self, severity: str) -> str:
        return {"critical": "error", "error": "error",
                "warning": "warn", "info": "info"}.get(severity, "info")

    # ==================== ГЛАВНЫЙ ЦИКЛ ====================

    def run(self):
        """Главный цикл сборщика"""
        print("🚀 Starting unified monitoring...\n")

        iteration = 0

        try:
            while True:
                iteration += 1
                current_time = time.time()

                print(f"\n{'='*80}")
                print(f"[{iteration}] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"{'='*80}")

                all_data = []

                # 1. Windows Events (всегда)
                print("📋 WINDOWS EVENTS:")
                events = self.collect_windows_events()
                if events:
                    suspicious = sum(1 for e in events if e.get("suspicious"))
                    print(f"  ✅ Total: {len(events)} | Suspicious: {suspicious}")
                    all_data.extend(events)
                else:
                    print("  ✓ No new events")

                # 2. System Metrics (по расписанию)
                if current_time - self.last_metrics_time >= METRICS_INTERVAL:
                    print("\n📊 SYSTEM METRICS:")
                    metrics = self.collect_system_metrics()
                    print(f"  CPU: {metrics['cpu_percent']:.1f}% | "
                          f"MEM: {metrics['memory_percent']:.1f}% | "
                          f"DISK: {metrics['disk_percent']:.1f}%")

                    if metrics['has_anomalies']:
                        print(f"  ⚠️  Anomalies: {metrics['anomalies']}")
                        self.metrics_stats["anomalies"] += 1

                    all_data.append(metrics)
                    self.last_metrics_time = current_time
                    self.metrics_stats["iterations"] += 1

                # 3. Process Monitoring
                print("\n🔍 RUNTIME MONITORING:")
                proc_events = self.collect_process_monitoring()
                if proc_events:
                    print(f"  ⚠️  Suspicious processes: {len(proc_events)}")
                    all_data.extend(proc_events)

                net_events = self.collect_network_monitoring()
                if net_events:
                    print(f"  🌐 Network anomalies: {len(net_events)}")
                    all_data.extend(net_events)

                svc_events = self.collect_service_health()
                if svc_events:
                    print(f"  🔧 Service issues: {len(svc_events)}")
                    all_data.extend(svc_events)

                if not (proc_events or net_events or svc_events):
                    print("  ✓ No issues detected")

                # 4. Отправка в API (ML фильтрация + Agent анализ → Better Stack)
                if all_data:
                    print(f"\n📤 Sending {len(all_data)} items to API for ML+Agent processing...")
                    if self.send_to_api(all_data):
                        print("  ✅ Sent to API → ML filter → Agent analysis → Better Stack")
                    else:
                        print("  ❌ Failed to send to API")

                # 5. Статистика каждые 10 итераций
                if iteration % 10 == 0:
                    self._print_stats()

                print(f"\n⏱️  Next check in {EVENT_CHECK_INTERVAL}s...")
                time.sleep(EVENT_CHECK_INTERVAL)

        except KeyboardInterrupt:
            print("\n\n🛑 Stopping unified collector...")
            self._print_stats()
            print("\n✅ Shutdown complete")

    def _print_stats(self):
        """Статистика работы"""
        print("\n" + "=" * 80)
        print("📊 STATISTICS")
        print("=" * 80)
        print(f"Metrics collected: {self.metrics_stats['iterations']} times")
        print(f"Anomalies detected: {self.metrics_stats['anomalies']}")

        if self.event_stats:
            print("\nTop Event Types:")
            for key, count in sorted(self.event_stats.items(),
                                    key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {key}: {count}")
        print("=" * 80)


def check_admin():
    """Проверка прав администратора"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("🔷 UNIFIED IR-AGENT COLLECTOR")
    print("=" * 80 + "\n")

    if not check_admin():
        print("❌ This script requires Administrator privileges!")
        print("Right-click and select 'Run as Administrator'\n")
        input("Press Enter to exit...")
        exit(1)

    collector = UnifiedCollector()
    collector.run()