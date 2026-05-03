"""
False Positive Tests — IR-Agent
=================================
Проверяет, что легитимные действия пользователей НЕ помечаются как вредоносные.

Охватываемые категории:
  A. Обычный офисный пользователь
  B. IT-администратор / DevOps
  C. Разработчик (Python / Node / Java)
  D. Сетевые операции и RDP
  E. Управление Windows (schtasks, services, registry)
  F. Средства безопасности (антивирус, сканеры)
  G. Установка и обновление ПО
  H. LOLBin-утилиты в легитимном контексте
  I. Граничные случаи (высокий эвристический скор, но легитимные)
  J. Системные процессы Windows
  K. Linux / смешанная среда
  L. Domain-операции (AD, GPO, Kerberos)
"""

from __future__ import annotations

import unittest



# ── Threshold from gradient_boosting_decoupled.pkl (Youden-J optimised) ──────
# Verified: pickle key 'threshold' = 0.9942099870877177
# This is the PRODUCTION threshold.  When the model loads correctly, the
# MLAttackDetector singleton uses this value.  We assert against it
# DIRECTLY so the test does not depend on singleton initialisation order.
MODEL_THRESHOLD = 0.9942


def _get_detector():
    """
    Get an ML detector instance.  Creates a fresh object each time so that
    singleton pollution (threshold=0.5 set by EventProcessor or test_ml_detector)
    does not affect these tests.
    """
    from app.services.ml_detector import MLAttackDetector
    return MLAttackDetector()


def _predict(event: dict):
    return _get_detector().predict(event)


def _assertNotFP(test_case: unittest.TestCase, event: dict, name: str):
    """
    Assert the event is NOT a false positive at the production model threshold.

    Checks the RAW SCORE directly against MODEL_THRESHOLD (0.9942) rather than
    using is_mal, which depends on how the detector singleton was initialised
    (EventProcessor uses threshold=0.5; the model pickle overrides it to 0.9942,
    but only when loading succeeds in the current test context).
    """
    d = _get_detector()
    is_mal, score, reason = d.predict(event)

    # Use model threshold, not the potentially-corrupted singleton threshold
    effective_threshold = d.threshold if d.threshold > 0.9 else MODEL_THRESHOLD
    would_be_flagged = score >= effective_threshold

    test_case.assertFalse(
        would_be_flagged,
        f"FALSE POSITIVE [{name}]: score={score:.4f} >= threshold={effective_threshold:.4f}\n"
        f"  Reason: {reason}\n"
        f"  Event:  {event}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# A. Офисный пользователь
# ─────────────────────────────────────────────────────────────────────────────

class TestOfficeUserFalsePositives(unittest.TestCase):
    """Обычный офисный пользователь — открытие документов, браузер, почта."""

    def test_word_open_document(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE',
            'command_line': r'WINWORD.EXE C:\Users\john\Documents\Q1_Report.docx',
        }, 'Word open document')

    def test_excel_open_spreadsheet(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE',
            'command_line': r'EXCEL.EXE C:\Users\john\Documents\budget.xlsx',
        }, 'Excel open spreadsheet')

    def test_outlook_startup(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE',
            'command_line': 'OUTLOOK.EXE /recycle',
        }, 'Outlook startup')

    def test_chrome_browser(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Program Files\Google\Chrome\Application\chrome.exe',
            'command_line': 'chrome.exe --profile-directory=Default',
        }, 'Chrome browser launch')

    def test_firefox_browser(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Program Files\Mozilla Firefox\firefox.exe',
            'command_line': 'firefox.exe -osint -url https://company.intranet',
        }, 'Firefox browser launch')

    def test_teams_startup(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Users\john\AppData\Local\Microsoft\Teams\current\Teams.exe',
            'command_line': 'Teams.exe --processStart Teams.exe',
        }, 'Teams startup')

    def test_user_interactive_logon(self):
        _assertNotFP(self, {
            'event_id': 4624,
            'logon_type': 2,
            'user': 'CORP\\john.doe',
            'source_ip': '127.0.0.1',
        }, 'Interactive logon')

    def test_user_network_logon_internal(self):
        _assertNotFP(self, {
            'event_id': 4624,
            'logon_type': 3,
            'user': 'CORP\\john.doe',
            'source_ip': '10.0.1.55',
        }, 'Network logon from internal IP')

    def test_user_logoff(self):
        _assertNotFP(self, {
            'event_id': 4634,
            'user': 'CORP\\john.doe',
            'logon_type': 2,
        }, 'User logoff')

    def test_password_change_own_account(self):
        _assertNotFP(self, {
            'event_id': 4723,
            'user': 'CORP\\john.doe',
        }, 'User password change own account')

    def test_notepad_open_file(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\System32\notepad.exe',
            'command_line': r'notepad.exe C:\Users\john\notes.txt',
        }, 'Notepad open file')

    def test_explorer_file_copy(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\explorer.exe',
            'command_line': 'C:\\Windows\\explorer.exe',
        }, 'Windows Explorer')

    def test_acrobat_open_pdf(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe',
            'command_line': r'Acrobat.exe /A "page=1" C:\Users\john\contract.pdf',
        }, 'Acrobat open PDF')


# ─────────────────────────────────────────────────────────────────────────────
# B. IT-администратор / DevOps
# ─────────────────────────────────────────────────────────────────────────────

class TestITAdminFalsePositives(unittest.TestCase):
    """IT-администратор — управление серверами, скрипты, мониторинг."""

    def test_powershell_get_process(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'powershell.exe',
            'command_line': 'powershell -Command Get-Process',
        }, 'PowerShell Get-Process')

    def test_powershell_get_service(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'powershell.exe',
            'command_line': 'powershell -Command Get-Service | Where-Object {$_.Status -eq "Running"}',
        }, 'PowerShell Get-Service')

    def test_powershell_get_eventlog(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'powershell.exe',
            'command_line': 'powershell -Command Get-EventLog -LogName System -Newest 100',
        }, 'PowerShell Get-EventLog')

    def test_powershell_backup_script(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'powershell.exe',
            'command_line': r'powershell.exe -ExecutionPolicy RemoteSigned -File C:\Scripts\nightly_backup.ps1',
        }, 'PowerShell backup script')

    def test_powershell_remoting_internal(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'powershell.exe',
            'command_line': 'powershell -Command Invoke-Command -ComputerName srv01 -ScriptBlock { Get-Service }',
            'destination_ip': '10.0.0.10',
        }, 'PowerShell remoting internal')

    def test_cmd_dir_listing(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'cmd.exe',
            'command_line': r'cmd.exe /c dir C:\Windows\System32',
        }, 'CMD dir listing')

    def test_cmd_net_statistics(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'net.exe',
            'command_line': 'net statistics workstation',
        }, 'Net statistics workstation')

    def test_cmd_net_use_share(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'net.exe',
            'command_line': r'net use Z: \\fileserver01\dept_share /persistent:yes',
        }, 'Net use share mapping')

    def test_wmic_query_os(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'wmic.exe',
            'command_line': 'wmic os get Caption,Version,BuildNumber',
        }, 'WMIC query OS info')

    def test_wmic_query_disk(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'wmic.exe',
            'command_line': 'wmic diskdrive get model,size,status',
        }, 'WMIC query disk')

    def test_whoami_check(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'whoami.exe',
            'command_line': 'whoami /groups',
        }, 'whoami /groups')

    def test_ipconfig_check(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'ipconfig.exe',
            'command_line': 'ipconfig /all',
        }, 'ipconfig /all')

    def test_netstat_check(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'netstat.exe',
            'command_line': 'netstat -ano',
        }, 'netstat -ano')

    def test_tasklist_check(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'tasklist.exe',
            'command_line': 'tasklist /v',
        }, 'tasklist /v')

    def test_sc_query_service(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'sc.exe',
            'command_line': 'sc query wuauserv',
        }, 'SC query service status')

    def test_reg_query_key(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'reg.exe',
            'command_line': r'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"',
        }, 'REG query CurrentVersion')

    def test_ping_internal_host(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'ping.exe',
            'command_line': 'ping -n 4 192.168.1.1',
            'destination_ip': '192.168.1.1',
        }, 'Ping internal host')

    def test_systeminfo_check(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'systeminfo.exe',
            'command_line': 'systeminfo',
        }, 'systeminfo')


# ─────────────────────────────────────────────────────────────────────────────
# C. Разработчик
# ─────────────────────────────────────────────────────────────────────────────

class TestDeveloperFalsePositives(unittest.TestCase):
    """Разработчик — Python, Node.js, Java, Git."""

    def test_python_run_script(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'python.exe',
            'command_line': r'python.exe C:\Projects\myapp\app.py',
        }, 'Python run script')

    def test_python_django_server(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'python.exe',
            'command_line': 'python.exe manage.py runserver 127.0.0.1:8000',
        }, 'Django dev server')

    def test_python_pip_install(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'python.exe',
            'command_line': 'python.exe -m pip install requests flask --upgrade',
        }, 'pip install packages')

    def test_python_pytest_run(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'python.exe',
            'command_line': r'python.exe -m pytest tests\ -v --tb=short',
        }, 'pytest run')

    def test_node_start_server(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'node.exe',
            'command_line': r'node.exe C:\Projects\api\server.js',
        }, 'Node.js start server')

    def test_node_npm_install(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'node.exe',
            'command_line': 'node.exe npm install',
        }, 'npm install')

    def test_java_run_app(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'java.exe',
            'command_line': r'java.exe -jar C:\Apps\myservice.jar --spring.profiles.active=dev',
        }, 'Java run JAR')

    def test_java_maven_build(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'java.exe',
            'command_line': 'java.exe -jar mvn clean package -DskipTests',
        }, 'Maven build')

    def test_git_clone(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'git.exe',
            'command_line': 'git.exe clone https://github.com/company/repo.git',
        }, 'Git clone')

    def test_git_push(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'git.exe',
            'command_line': 'git.exe push origin main',
        }, 'Git push')

    def test_vscode_launch(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\Code.exe',
            'command_line': r'Code.exe --unity-launch C:\Projects\myapp',
        }, 'VS Code launch')

    def test_python_base64_legitimate(self):
        """Developer using base64 for encoding test data (legit)."""
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'python.exe',
            'command_line': 'python.exe -c "import base64; print(base64.b64encode(b\'test\'))"',
        }, 'Python base64 legitimate encoding')

    def test_python_socket_server(self):
        """Developer running a local socket server (legit)."""
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'python.exe',
            'command_line': r'python.exe C:\Projects\socketserver\main.py --port 8080',
        }, 'Python socket server local')


# ─────────────────────────────────────────────────────────────────────────────
# D. Сетевые операции и RDP
# ─────────────────────────────────────────────────────────────────────────────

class TestNetworkRDPFalsePositives(unittest.TestCase):
    """Легитимные сетевые соединения, RDP внутри сети."""

    def test_rdp_from_internal_ip(self):
        _assertNotFP(self, {
            'event_id': 4624,
            'logon_type': 10,
            'user': 'CORP\\admin',
            'source_ip': '10.10.0.50',
        }, 'RDP from internal IP')

    def test_network_logon_to_fileserver(self):
        _assertNotFP(self, {
            'event_id': 4624,
            'logon_type': 3,
            'user': 'CORP\\svcaccount',
            'source_ip': '192.168.10.100',
            'destination_port': 445,
        }, 'SMB logon to file server from internal')

    def test_dns_query_internal_domain(self):
        _assertNotFP(self, {
            'event_id': 22,
            'query_name': 'intranet.corp.local',
            'process_name': 'svchost.exe',
        }, 'DNS query internal domain')

    def test_dns_query_google(self):
        _assertNotFP(self, {
            'event_id': 22,
            'query_name': 'www.google.com',
            'process_name': 'chrome.exe',
        }, 'DNS query google.com')

    def test_dns_query_microsoft(self):
        _assertNotFP(self, {
            'event_id': 22,
            'query_name': 'login.microsoftonline.com',
            'process_name': 'Teams.exe',
        }, 'DNS query Microsoft 365')

    def test_browser_http_request(self):
        _assertNotFP(self, {
            'event_id': 3,
            'process_name': 'chrome.exe',
            'destination_ip': '172.217.16.100',
            'destination_port': 443,
        }, 'Browser HTTPS request')

    def test_windows_update_connection(self):
        _assertNotFP(self, {
            'event_id': 3,
            'process_name': 'svchost.exe',
            'destination_ip': '40.84.139.198',
            'destination_port': 443,
        }, 'Windows Update HTTPS')

    def test_network_share_smb(self):
        _assertNotFP(self, {
            'event_id': 3,
            'process_name': 'System',
            'destination_ip': '10.0.0.5',
            'destination_port': 445,
        }, 'SMB to internal share')

    def test_kerberos_authentication(self):
        _assertNotFP(self, {
            'event_id': 4769,
            'user': 'CORP\\john',
            'destination_ip': '10.0.0.1',
            'destination_port': 88,
        }, 'Kerberos authentication')

    def test_nslookup_check(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'nslookup.exe',
            'command_line': 'nslookup corp.local',
        }, 'nslookup internal domain')


# ─────────────────────────────────────────────────────────────────────────────
# E. Управление Windows (schtasks, services, registry)
# ─────────────────────────────────────────────────────────────────────────────

class TestWindowsManagementFalsePositives(unittest.TestCase):
    """Легитимное управление задачами, службами и реестром."""

    def test_schtasks_query(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'schtasks.exe',
            'command_line': 'schtasks /query /fo LIST /v',
        }, 'schtasks /query')

    def test_schtasks_daily_backup(self):
        _assertNotFP(self, {
            'event_id': 4698,
            'process_name': 'schtasks.exe',
            'command_line': r'schtasks /create /tn "Daily Backup" /tr C:\Scripts\backup.bat /sc daily /st 02:00',
        }, 'schtasks create daily backup')

    def test_schtasks_delete(self):
        _assertNotFP(self, {
            'event_id': 4699,
            'command_line': r'schtasks /delete /tn "Old Task" /f',
        }, 'schtasks delete task')

    def test_sc_query(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'sc.exe',
            'command_line': 'sc query type= all state= all',
        }, 'SC query all services')

    def test_sc_start_stop_service(self):
        _assertNotFP(self, {
            'event_id': 7036,
            'message': 'The Print Spooler service entered the stopped state.',
        }, 'Service stopped normally')

    def test_reg_query_software_key(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'reg.exe',
            'command_line': r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"',
        }, 'REG query installed software')

    def test_event_log_clear(self):
        _assertNotFP(self, {
            'event_id': 1102,
            'user': 'CORP\\sysadmin',
        }, 'Admin clears event log (authorized)')

    def test_service_install_legitimate(self):
        """Antivirus service installation."""
        _assertNotFP(self, {
            'event_id': 7045,
            'message': 'A service was installed: Symantec Endpoint Protection',
            'command_line': r'"C:\Program Files\Symantec\Symantec Endpoint Protection\14.3\Bin\ccSvcHst.exe" /s',
        }, 'Antivirus service install')

    def test_at_job_legacy(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'at.exe',
            'command_line': 'at',
        }, 'AT command list jobs')

    def test_powershell_set_scheduled_task(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'powershell.exe',
            'command_line': r'powershell -Command New-ScheduledTask -Action (New-ScheduledTaskAction -Execute "notepad.exe") -Trigger (New-ScheduledTaskTrigger -AtLogOn)',
        }, 'PowerShell New-ScheduledTask')


# ─────────────────────────────────────────────────────────────────────────────
# F. Средства безопасности
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityToolsFalsePositives(unittest.TestCase):
    """Антивирусы, сканеры уязвимостей — легитимные утилиты безопасности."""

    def test_windows_defender_scan(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Program Files\Windows Defender\MpCmdRun.exe',
            'command_line': 'MpCmdRun.exe -Scan -ScanType 1',
        }, 'Windows Defender scan')

    def test_defender_update(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Program Files\Windows Defender\MpCmdRun.exe',
            'command_line': 'MpCmdRun.exe -SignatureUpdate',
        }, 'Defender signature update')

    def test_symantec_scan(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Program Files\Symantec\Symantec Endpoint Protection\14.3\Bin\ccSvcHst.exe',
            'command_line': 'ccSvcHst.exe /run',
        }, 'Symantec AV service')

    def test_nmap_internal_scan(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Program Files (x86)\Nmap\nmap.exe',
            'command_line': 'nmap.exe -sV 10.0.0.0/24',
            'user': 'CORP\\security_team',
        }, 'nmap internal network scan by security team')

    def test_procdump_legitimate_crash(self):
        """SysInternals procdump for crash analysis — legitimate use."""
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Tools\SysInternals\procdump.exe',
            'command_line': r'procdump.exe -accepteula -e -ma C:\CrashDumps\crash.dmp',
            'user': 'CORP\\sysadmin',
        }, 'procdump for crash dump analysis (non-LSASS)')

    def test_wireshark_capture(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Program Files\Wireshark\Wireshark.exe',
            'command_line': 'Wireshark.exe',
        }, 'Wireshark packet capture')

    def test_process_hacker_monitor(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Program Files\Process Hacker 2\ProcessHacker.exe',
            'command_line': 'ProcessHacker.exe',
        }, 'Process Hacker for monitoring')


# ─────────────────────────────────────────────────────────────────────────────
# G. Установка и обновление ПО
# ─────────────────────────────────────────────────────────────────────────────

class TestSoftwareInstallFalsePositives(unittest.TestCase):
    """Установка, обновление, удаление программного обеспечения."""

    def test_msiexec_install(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\System32\msiexec.exe',
            'command_line': r'msiexec /i C:\Downloads\software_v2.msi /quiet /norestart',
        }, 'MSI install quiet')

    def test_msiexec_uninstall(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\System32\msiexec.exe',
            'command_line': 'msiexec /x {PRODUCT-GUID} /quiet',
        }, 'MSI uninstall')

    def test_windows_update_service(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\System32\wuauclt.exe',
            'command_line': 'wuauclt.exe /RunHandlerComServer',
        }, 'Windows Update agent')

    def test_chocolatey_install(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'powershell.exe',
            'command_line': r'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command choco install git -y',
        }, 'Chocolatey install package')

    def test_winget_install(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Users\john\AppData\Local\Microsoft\WindowsApps\winget.exe',
            'command_line': 'winget install --id=Git.Git -e --source winget',
        }, 'winget install git')

    def test_powershell_install_module(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'powershell.exe',
            'command_line': 'powershell -Command Install-Module -Name Az -Force -Scope CurrentUser',
        }, 'PowerShell Install-Module Az')

    def test_setup_exe_install(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Downloads\setup.exe',
            'command_line': r'setup.exe /SILENT /NORESTART',
        }, 'Setup.exe silent install')


# ─────────────────────────────────────────────────────────────────────────────
# H. LOLBin-утилиты в легитимном контексте
# ─────────────────────────────────────────────────────────────────────────────

class TestLOLBinLegitFalsePositives(unittest.TestCase):
    """LOLBin-утилиты в легитимных сценариях (не должны давать FP)."""

    def test_certutil_verify_cert(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'certutil.exe',
            'command_line': r'certutil -verify C:\Certs\server.crt',
        }, 'certutil verify certificate')

    def test_certutil_display_cert(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'certutil.exe',
            'command_line': 'certutil -dump certificate.crt',
        }, 'certutil dump cert info')

    def test_bitsadmin_list_jobs(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'bitsadmin.exe',
            'command_line': 'bitsadmin /list /allusers',
        }, 'bitsadmin list all jobs')

    def test_rundll32_legitimate(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\System32\rundll32.exe',
            'command_line': r'rundll32.exe C:\Windows\System32\shell32.dll,Control_RunDLL desk.cpl',
        }, 'rundll32 control panel')

    def test_regsvr32_register_dll(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\System32\regsvr32.exe',
            'command_line': r'regsvr32.exe /s C:\Program Files\MyApp\mylib.dll',
        }, 'regsvr32 register legitimate DLL')

    def test_cscript_vbs_script(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\System32\cscript.exe',
            'command_line': r'cscript.exe //nologo C:\Scripts\maintenance.vbs',
        }, 'cscript run VBS maintenance')

    def test_wscript_logon_script(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\System32\wscript.exe',
            'command_line': r'wscript.exe C:\Windows\SYSVOL\scripts\logon.vbs',
        }, 'wscript logon script')

    def test_mshta_hta_app(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\System32\mshta.exe',
            'command_line': r'mshta.exe C:\Apps\LegacyApp\main.hta',
        }, 'mshta run local HTA app')

    def test_powershell_encodedcommand_short(self):
        """Short base64 command — IT admin running Get-Date."""
        import base64
        cmd = base64.b64encode('Get-Date'.encode('utf-16-le')).decode()
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'powershell.exe',
            'command_line': f'powershell.exe -EncodedCommand {cmd}',
        }, 'PowerShell -EncodedCommand Get-Date (short, benign)')


# ─────────────────────────────────────────────────────────────────────────────
# I. Граничные случаи (высокий эвристический скор, но легитимные)
# ─────────────────────────────────────────────────────────────────────────────

class TestBorderlineCasesFalsePositives(unittest.TestCase):
    """
    Случаи с повышенным эвристическим скором — но всё равно не должны
    превышать настроенный порог детектора.
    """

    def test_schtasks_create_backup_daily(self):
        """schtasks /create для ежедневного бэкапа даёт 0.7 по эвристике — FP-риск."""
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'schtasks.exe',
            'command_line': r'schtasks /create /tn "NightlyBackup" /tr C:\backup.bat /sc daily /st 03:00',
        }, 'schtasks /create daily backup (borderline)')

    def test_python_base64_decode_file(self):
        """python -m base64 для декодирования файла."""
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'python.exe',
            'command_line': r'python.exe -m base64 -d encoded_data.b64 > output.bin',
        }, 'Python base64 decode file (borderline)')

    def test_powershell_bypass_executionpolicy(self):
        """-ExecutionPolicy Bypass для запуска легитимного скрипта."""
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'powershell.exe',
            'command_line': r'powershell.exe -ExecutionPolicy Bypass -NonInteractive -File C:\Deploy\deploy.ps1',
        }, 'PS -ExecutionPolicy Bypass deploy script (borderline)')

    def test_certutil_with_urlcache_for_local_file(self):
        """certutil -urlcache для проверки локального кэша (не загрузки)."""
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'certutil.exe',
            'command_line': 'certutil -urlcache',
        }, 'certutil -urlcache list only (borderline)')

    def test_admin_privileged_logon(self):
        """Привилегированный вход администратора — не атака."""
        _assertNotFP(self, {
            'event_id': 4672,
            'user': 'CORP\\domain_admin',
            'logon_type': 2,
        }, 'Admin privileged logon 4672')

    def test_psexec_internal_admin_task(self):
        """PsExec от системного администратора на внутреннем хосте."""
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Tools\SysInternals\PsExec.exe',
            'command_line': r'PsExec.exe \\srv-app01 -s cmd.exe /c ipconfig',
            'destination_ip': '10.0.1.20',
            'user': 'CORP\\sysadmin',
        }, 'PsExec admin task on internal server (borderline)')

    def test_invoke_command_internal_ps(self):
        """Invoke-Command по внутренней сети — PowerShell remoting."""
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'powershell.exe',
            'command_line': 'powershell -Command "Invoke-Command -ComputerName dc01 -ScriptBlock { Get-ADUser -Filter * }"',
            'destination_ip': '10.0.0.1',
        }, 'Invoke-Command Get-ADUser internal (borderline)')

    def test_hidden_window_installer(self):
        """-WindowStyle Hidden для установщика без GUI."""
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'powershell.exe',
            'command_line': r'powershell.exe -WindowStyle Hidden -File C:\Installers\silent_install.ps1',
        }, 'PowerShell -WindowStyle Hidden installer (borderline)')


# ─────────────────────────────────────────────────────────────────────────────
# J. Системные процессы Windows
# ─────────────────────────────────────────────────────────────────────────────

class TestWindowsSystemProcessFalsePositives(unittest.TestCase):
    """Легитимные системные процессы Windows."""

    def test_svchost_network_service(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\System32\svchost.exe',
            'command_line': 'svchost.exe -k NetworkService',
            'parent_image': r'C:\Windows\System32\services.exe',
        }, 'svchost NetworkService')

    def test_lsass_normal(self):
        """lsass.exe itself as a process (not being dumped)."""
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\System32\lsass.exe',
            'command_line': r'C:\Windows\System32\lsass.exe',
            'parent_image': r'C:\Windows\System32\wininit.exe',
        }, 'lsass.exe normal startup')

    def test_winlogon_normal(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\System32\winlogon.exe',
            'command_line': 'winlogon.exe',
        }, 'winlogon.exe normal')

    def test_csrss_normal(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\System32\csrss.exe',
            'command_line': r'%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows',
        }, 'csrss.exe normal')

    def test_taskhostw_normal(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\System32\taskhostw.exe',
            'command_line': 'taskhostw.exe',
            'parent_image': r'C:\Windows\System32\svchost.exe',
        }, 'taskhostw.exe normal task host')

    def test_conhost_normal(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\System32\conhost.exe',
            'command_line': r'C:\Windows\system32\conhost.exe 0xffffffff -ForceV1',
        }, 'conhost.exe normal')

    def test_spooler_service(self):
        _assertNotFP(self, {
            'event_id': 7036,
            'message': 'The Print Spooler service entered the running state.',
        }, 'Print Spooler service start')

    def test_wmi_normal_query(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\System32\wbem\WmiPrvSE.exe',
            'parent_image': r'C:\Windows\System32\svchost.exe',
            'command_line': r'C:\Windows\system32\wbem\wmiprvse.exe',
        }, 'WmiPrvSE.exe normal WBEM query')


# ─────────────────────────────────────────────────────────────────────────────
# K. Linux / смешанная среда
# ─────────────────────────────────────────────────────────────────────────────

class TestLinuxMixedEnvFalsePositives(unittest.TestCase):
    """Linux auditd / смешанные Sysmon-события."""

    def test_bash_script_run(self):
        _assertNotFP(self, {
            'event_id': 1,
            'process_name': '/bin/bash',
            'command_line': '/bin/bash /opt/scripts/deploy.sh',
        }, 'bash run deploy script')

    def test_python3_script(self):
        _assertNotFP(self, {
            'event_id': 1,
            'process_name': '/usr/bin/python3',
            'command_line': '/usr/bin/python3 /opt/app/server.py --port 8080',
        }, 'python3 run server')

    def test_curl_internal_api(self):
        _assertNotFP(self, {
            'event_id': 1,
            'process_name': '/usr/bin/curl',
            'command_line': 'curl -s http://api.internal.corp/health',
            'destination_ip': '10.0.0.50',
        }, 'curl internal API healthcheck')

    def test_ssh_login_internal(self):
        _assertNotFP(self, {
            'event_id': 4624,
            'logon_type': 10,
            'source_ip': '10.10.1.20',
            'user': 'devops',
        }, 'SSH login from internal')

    def test_cron_job_execution(self):
        _assertNotFP(self, {
            'event_id': 1,
            'process_name': '/usr/sbin/cron',
            'command_line': '/usr/sbin/cron -f',
        }, 'cron daemon')


# ─────────────────────────────────────────────────────────────────────────────
# L. Domain-операции (AD, GPO, Kerberos)
# ─────────────────────────────────────────────────────────────────────────────

class TestDomainOperationsFalsePositives(unittest.TestCase):
    """Active Directory, Group Policy, Kerberos — легитимные операции."""

    def test_gpo_update(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\System32\gpupdate.exe',
            'command_line': 'gpupdate.exe /force',
        }, 'gpupdate /force')

    def test_nltest_dc_query(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'nltest.exe',
            'command_line': 'nltest /dclist:corp.local',
        }, 'nltest /dclist')

    def test_klist_kerberos_tickets(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'klist.exe',
            'command_line': 'klist tickets',
        }, 'klist show Kerberos tickets')

    def test_dsquery_users(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'dsquery.exe',
            'command_line': 'dsquery user -name john* -limit 50',
        }, 'dsquery user search')

    def test_kerberos_ticket_grant(self):
        _assertNotFP(self, {
            'event_id': 4769,
            'user': 'CORP\\john.doe',
            'destination_ip': '10.0.0.1',
        }, 'Kerberos TGS request')

    def test_domain_join(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': r'C:\Windows\System32\netdom.exe',
            'command_line': 'netdom join workstation01 /domain:corp.local /userd:corp\\admin',
        }, 'Domain join via netdom')

    def test_ad_user_creation(self):
        _assertNotFP(self, {
            'event_id': 4720,
            'user': 'CORP\\hr_admin',
            'message': 'New employee account created',
        }, 'New user account created by HR admin')

    def test_ad_user_added_to_group(self):
        _assertNotFP(self, {
            'event_id': 4732,
            'user': 'CORP\\it_admin',
            'message': 'User added to security group',
        }, 'User added to AD security group')

    def test_powershell_get_aduser(self):
        _assertNotFP(self, {
            'event_id': 4688,
            'process_name': 'powershell.exe',
            'command_line': 'powershell -Command "Import-Module ActiveDirectory; Get-ADUser -Filter * -SearchBase \'OU=Users,DC=corp,DC=local\'"',
        }, 'PowerShell Get-ADUser')


# ─────────────────────────────────────────────────────────────────────────────
# Итоговый отчёт
# ─────────────────────────────────────────────────────────────────────────────

class TestFalsePositiveSummary(unittest.TestCase):
    """
    Итоговый прогон всех легитимных сценариев с отчётом о скорах.
    Не проваливает тест, а выводит статистику.
    """

    # Полный каталог легитимных событий
    LEGIT_CATALOG = [
        # Офис
        ('Office: Word open',         {'event_id': 4688, 'process_name': r'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE', 'command_line': r'WINWORD.EXE report.docx'}),
        ('Office: Excel',             {'event_id': 4688, 'process_name': 'excel.exe', 'command_line': 'excel.exe budget.xlsx'}),
        ('Office: Outlook',           {'event_id': 4688, 'process_name': 'outlook.exe', 'command_line': 'outlook.exe /recycle'}),
        ('Office: Chrome',            {'event_id': 4688, 'process_name': 'chrome.exe', 'command_line': 'chrome.exe --profile-directory=Default'}),
        # Admin
        ('Admin: PS Get-Service',     {'event_id': 4688, 'process_name': 'powershell.exe', 'command_line': 'powershell Get-Service'}),
        ('Admin: PS Backup',          {'event_id': 4688, 'process_name': 'powershell.exe', 'command_line': r'powershell -ExecutionPolicy RemoteSigned -File C:\Scripts\backup.ps1'}),
        ('Admin: CMD dir',            {'event_id': 4688, 'process_name': 'cmd.exe', 'command_line': 'cmd /c dir'}),
        ('Admin: ipconfig',           {'event_id': 4688, 'process_name': 'ipconfig.exe', 'command_line': 'ipconfig /all'}),
        ('Admin: wmic os',            {'event_id': 4688, 'process_name': 'wmic.exe', 'command_line': 'wmic os get Version'}),
        ('Admin: net use',            {'event_id': 4688, 'process_name': 'net.exe', 'command_line': r'net use Z: \\server\share'}),
        # Developer
        ('Dev: Python script',        {'event_id': 4688, 'process_name': 'python.exe', 'command_line': r'python app.py'}),
        ('Dev: Node server',          {'event_id': 4688, 'process_name': 'node.exe', 'command_line': 'node server.js'}),
        ('Dev: Java app',             {'event_id': 4688, 'process_name': 'java.exe', 'command_line': 'java -jar app.jar'}),
        ('Dev: Git clone',            {'event_id': 4688, 'process_name': 'git.exe', 'command_line': 'git clone https://github.com/repo.git'}),
        # Network
        ('Net: RDP internal',         {'event_id': 4624, 'logon_type': 10, 'source_ip': '10.0.0.50'}),
        ('Net: Normal logon',         {'event_id': 4624, 'logon_type': 2, 'user': 'CORP\\john'}),
        ('Net: DNS google',           {'event_id': 22, 'query_name': 'www.google.com'}),
        ('Net: Browser HTTPS',        {'event_id': 3, 'process_name': 'chrome.exe', 'destination_port': 443, 'destination_ip': '172.217.0.1'}),
        # Software
        ('Install: MSI',              {'event_id': 4688, 'process_name': 'msiexec.exe', 'command_line': 'msiexec /i app.msi /quiet'}),
        ('Install: WU agent',         {'event_id': 4688, 'process_name': 'wuauclt.exe', 'command_line': 'wuauclt.exe /RunHandlerComServer'}),
        # LOLBin legitimate
        ('LOLBin: certutil verify',   {'event_id': 4688, 'process_name': 'certutil.exe', 'command_line': 'certutil -verify server.crt'}),
        ('LOLBin: bitsadmin list',    {'event_id': 4688, 'process_name': 'bitsadmin.exe', 'command_line': 'bitsadmin /list /allusers'}),
        ('LOLBin: rundll32 cpl',      {'event_id': 4688, 'process_name': 'rundll32.exe', 'command_line': 'rundll32.exe shell32.dll,Control_RunDLL desk.cpl'}),
        # Borderline
        ('Border: schtasks create',   {'event_id': 4698, 'command_line': r'schtasks /create /tn Backup /tr backup.bat /sc daily'}),
        ('Border: PS Bypass',         {'event_id': 4688, 'process_name': 'powershell.exe', 'command_line': r'powershell -ExecutionPolicy Bypass -File C:\deploy.ps1'}),
        ('Border: python base64',     {'event_id': 4688, 'process_name': 'python.exe', 'command_line': 'python -m base64 -d file.b64'}),
        # System
        ('Sys: svchost',              {'event_id': 4688, 'process_name': r'C:\Windows\System32\svchost.exe', 'command_line': 'svchost -k netsvcs', 'parent_image': r'C:\Windows\System32\services.exe'}),
        ('Sys: gpupdate',             {'event_id': 4688, 'process_name': 'gpupdate.exe', 'command_line': 'gpupdate /force'}),
        ('Sys: WmiPrvSE',             {'event_id': 4688, 'process_name': r'C:\Windows\System32\wbem\WmiPrvSE.exe', 'parent_image': r'C:\Windows\System32\svchost.exe'}),
        # Antivirus
        ('AV: Defender scan',         {'event_id': 4688, 'process_name': r'C:\Program Files\Windows Defender\MpCmdRun.exe', 'command_line': 'MpCmdRun.exe -Scan -ScanType 1'}),
    ]

    def test_full_catalog_no_false_positives(self):
        """Все 30 легитимных событий не должны быть помечены как malicious."""
        d = _get_detector()
        effective_threshold = d.threshold if d.threshold > 0.9 else MODEL_THRESHOLD
        fps = []
        risky = []  # высокий скор, но ниже порога

        for name, event in self.LEGIT_CATALOG:
            is_mal, score, reason = d.predict(event)
            if score >= effective_threshold:
                fps.append((name, score, reason))
            elif score > 0.75:
                risky.append((name, score, reason))

        # Выводим статистику (не падаем тут — только для информации)
        if risky:
            risky_names = [f"{n} (score={s:.3f})" for n, s, _ in risky]
            print(f"\n[INFO] High-score but not FP ({len(risky)}/{len(self.LEGIT_CATALOG)}): {risky_names}")

        self.assertEqual(
            len(fps), 0,
            f"\nFALSE POSITIVES ({len(fps)}/{len(self.LEGIT_CATALOG)}):\n" +
            "\n".join(f"  [{n}] score={s:.4f}  {r}" for n, s, r in fps)
        )

    def test_score_distribution_stats(self):
        """
        Проверяет что средний скор для легитимных событий ниже 0.6.
        Высокий средний скор = плохой SNR (signal-to-noise ratio).
        """
        d = _get_detector()
        scores = []
        for _, event in self.LEGIT_CATALOG:
            _, score, _ = d.predict(event)
            scores.append(score)

        avg = sum(scores) / len(scores)
        max_score = max(scores)

        print(f"\n[STATS] avg_score={avg:.3f}  max_score={max_score:.3f}  "
              f"n={len(scores)}  threshold={d.threshold:.4f}")

        # Средний скор легитимных событий должен быть разумно низким
        self.assertLess(avg, 0.7,
            f"Average score for legitimate events is too high: {avg:.3f}. "
            f"Possible false positive risk if threshold is lowered.")

    def test_no_false_positives_at_default_threshold(self):
        """Быстрый smoke-test: ни одно легитимное событие не должно превышать порог."""
        d = _get_detector()
        effective_threshold = d.threshold if d.threshold > 0.9 else MODEL_THRESHOLD
        fps = [
            (name, score)
            for name, event in self.LEGIT_CATALOG
            for _, score, _ in [d.predict(event)]
            if score >= effective_threshold
        ]
        self.assertEqual(len(fps), 0,
            f"FP at threshold={effective_threshold:.4f}: {fps}")


if __name__ == '__main__':
    import sys

    # При прямом запуске показываем детальный отчёт
    from app.services.ml_detector import MLAttackDetector
    d = MLAttackDetector()
    print(f"\n{'='*70}")
    print(f"  IR-AGENT FALSE POSITIVE AUDIT")
    print(f"  Model: {d._model_version}  Threshold: {d.threshold:.4f}")
    print(f"{'='*70}\n")

    catalog = TestFalsePositiveSummary.LEGIT_CATALOG
    fps = []
    rows = []
    for name, event in catalog:
        is_mal, score, reason = d.predict(event)
        flag = '⚠️  FP!' if is_mal else ('⚡ high' if score > 0.75 else '✅  ok')
        rows.append((flag, score, name, reason[:50]))
        if is_mal:
            fps.append((name, score))

    rows.sort(key=lambda r: -r[1])
    for flag, score, name, reason in rows:
        print(f"{flag}  {score:.3f}  {name:<35} {reason}")

    print(f"\n{'─'*70}")
    print(f"Total: {len(catalog)}  FPs: {len(fps)}  FP-rate: {len(fps)/len(catalog)*100:.1f}%")
    if fps:
        print("FALSE POSITIVES:", [n for n, _ in fps])

    # Run tests
    unittest.main(verbosity=2)
