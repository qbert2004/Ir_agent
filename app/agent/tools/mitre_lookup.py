"""MITRE ATT&CK technique lookup tool."""

from app.agent.tools.base import BaseTool, ToolParameter, ToolResult

# Embedded MITRE ATT&CK knowledge base (key techniques)
MITRE_TECHNIQUES = {
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials from the OS. Techniques include LSASS memory dumps, SAM database extraction, and DCSync.",
        "subtechniques": ["T1003.001 LSASS Memory", "T1003.002 SAM", "T1003.003 NTDS", "T1003.004 LSA Secrets", "T1003.006 DCSync"],
        "mitigations": ["Credential Access Protection", "Privileged Account Management", "Password Policies"],
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "subtechniques": ["T1059.001 PowerShell", "T1059.003 Windows Command Shell", "T1059.005 Visual Basic", "T1059.007 JavaScript"],
        "mitigations": ["Execution Prevention", "Code Signing", "Antivirus/Antimalware"],
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "description": "Adversaries inject code into processes to evade defenses and elevate privileges.",
        "subtechniques": ["T1055.001 DLL Injection", "T1055.002 PE Injection", "T1055.003 Thread Execution Hijacking", "T1055.012 Process Hollowing"],
        "mitigations": ["Behavior Prevention", "Privileged Account Management"],
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use valid accounts to log into remote services for lateral movement.",
        "subtechniques": ["T1021.001 RDP", "T1021.002 SMB/Windows Admin Shares", "T1021.003 DCOM", "T1021.006 Windows Remote Management"],
        "mitigations": ["MFA", "Network Segmentation", "Privileged Account Management"],
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Execution, Persistence, Privilege Escalation",
        "description": "Adversaries may schedule tasks for execution at a specified date/time for persistence or privilege escalation.",
        "subtechniques": ["T1053.005 Scheduled Task", "T1053.003 Cron"],
        "mitigations": ["Audit", "Operating System Configuration", "Privileged Account Management"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability (ransomware).",
        "subtechniques": [],
        "mitigations": ["Data Backup", "Behavior Prevention"],
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access to victim systems.",
        "subtechniques": ["T1566.001 Spearphishing Attachment", "T1566.002 Spearphishing Link", "T1566.003 Spearphishing via Service"],
        "mitigations": ["User Training", "Antivirus/Antimalware", "Network Intrusion Prevention"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Initial Access, Persistence, Privilege Escalation",
        "description": "Adversaries may obtain and abuse valid account credentials for initial access, persistence, or privilege escalation.",
        "subtechniques": ["T1078.001 Default Accounts", "T1078.002 Domain Accounts", "T1078.003 Local Accounts", "T1078.004 Cloud Accounts"],
        "mitigations": ["MFA", "Password Policies", "Privileged Account Management"],
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence, Privilege Escalation",
        "description": "Adversaries may configure system settings to automatically execute a program during boot or logon.",
        "subtechniques": ["T1547.001 Registry Run Keys", "T1547.004 Winlogon Helper DLL", "T1547.009 Shortcut Modification"],
        "mitigations": ["Restrict Registry Permissions", "Software Configuration"],
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using OSI application layer protocols to avoid detection.",
        "subtechniques": ["T1071.001 Web Protocols", "T1071.002 File Transfer Protocols", "T1071.004 DNS"],
        "mitigations": ["Network Intrusion Prevention", "Network Filtering"],
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over a different protocol than the C2 channel.",
        "subtechniques": ["T1048.001 Symmetric Encrypted", "T1048.002 Asymmetric Encrypted", "T1048.003 Unencrypted"],
        "mitigations": ["DLP", "Network Segmentation", "Network Filtering"],
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": "Adversaries may delete or modify artifacts to remove evidence of their presence.",
        "subtechniques": ["T1070.001 Clear Windows Event Logs", "T1070.003 Clear Command History", "T1070.004 File Deletion"],
        "mitigations": ["Encrypt Sensitive Information", "Remote Data Storage", "Restrict File and Directory Permissions"],
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obfuscate payloads to make detection and analysis more difficult.",
        "subtechniques": ["T1027.001 Binary Padding", "T1027.002 Software Packing", "T1027.005 Indicator Removal from Tools"],
        "mitigations": ["Antivirus/Antimalware", "Behavior Prevention"],
    },
    "T1560": {
        "name": "Archive Collected Data",
        "tactic": "Collection",
        "description": "Adversaries may compress and encrypt collected data prior to exfiltration.",
        "subtechniques": ["T1560.001 Archive via Utility", "T1560.002 Archive via Library"],
        "mitigations": ["Audit"],
    },
    "T1204": {
        "name": "User Execution",
        "tactic": "Execution",
        "description": "Adversaries may rely upon user actions to execute malicious content.",
        "subtechniques": ["T1204.001 Malicious Link", "T1204.002 Malicious File"],
        "mitigations": ["User Training", "Network Intrusion Prevention", "Execution Prevention"],
    },
}


class MitreLookupTool(BaseTool):
    """Look up MITRE ATT&CK techniques by ID or keyword."""

    name = "mitre_lookup"
    description = (
        "Look up MITRE ATT&CK techniques by technique ID (e.g., T1003) or "
        "by keyword search (e.g., 'credential dumping', 'lateral movement'). "
        "Returns technique details, sub-techniques, and mitigations."
    )
    parameters = [
        ToolParameter(
            name="technique_id",
            description="MITRE technique ID (e.g., T1003)",
            type="string",
            required=False,
        ),
        ToolParameter(
            name="keyword",
            description="Keyword to search techniques (e.g., 'ransomware', 'phishing')",
            type="string",
            required=False,
        ),
    ]

    def execute(self, **kwargs) -> ToolResult:
        technique_id = kwargs.get("technique_id", "").strip().upper()
        keyword = kwargs.get("keyword", "").strip().lower()

        if not technique_id and not keyword:
            return ToolResult(success=False, output="", error="Provide technique_id or keyword")

        results = []

        if technique_id:
            tech = MITRE_TECHNIQUES.get(technique_id)
            if tech:
                results.append((technique_id, tech))
            else:
                # Search subtechniques
                for tid, t in MITRE_TECHNIQUES.items():
                    for sub in t.get("subtechniques", []):
                        if technique_id in sub:
                            results.append((tid, t))
                            break

        if keyword:
            for tid, tech in MITRE_TECHNIQUES.items():
                searchable = f"{tech['name']} {tech['description']} {tech['tactic']} {' '.join(tech.get('subtechniques', []))}".lower()
                if keyword in searchable:
                    if (tid, tech) not in results:
                        results.append((tid, tech))

        if not results:
            return ToolResult(
                success=True,
                output=f"No MITRE techniques found for: {technique_id or keyword}",
                data={"count": 0},
            )

        lines = []
        for tid, tech in results[:5]:
            lines.append(f"\n{tid}: {tech['name']}")
            lines.append(f"  Tactic(s): {tech['tactic']}")
            lines.append(f"  Description: {tech['description']}")
            if tech.get("subtechniques"):
                lines.append(f"  Sub-techniques: {', '.join(tech['subtechniques'][:5])}")
            if tech.get("mitigations"):
                lines.append(f"  Mitigations: {', '.join(tech['mitigations'])}")

        output = "\n".join(lines)
        return ToolResult(
            success=True,
            output=output[:2000],
            data={"count": len(results)},
        )
