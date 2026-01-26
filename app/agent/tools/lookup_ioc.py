"""IoC (Indicator of Compromise) lookup tool."""

import re
from typing import Dict, List

from app.agent.tools.base import BaseTool, ToolParameter, ToolResult

# Known malicious indicators (expandable database)
KNOWN_MALICIOUS_IPS = {
    "185.220.101.1", "185.220.101.2",  # Tor exit nodes
    "45.33.32.156",  # Commonly flagged scanner
    "192.168.1.100",  # Example internal lateral movement
}

KNOWN_MALICIOUS_DOMAINS = {
    "malware-c2.evil.com", "phishing-kit.badactor.net",
    "exfil-data.darkweb.onion", "update-flash.fakecdn.com",
}

KNOWN_MALICIOUS_HASHES = {
    "e99a18c428cb38d5f260853678922e03": "WannaCry ransomware",
    "d41d8cd98f00b204e9800998ecf8427e": "Empty file (suspicious if unexpected)",
    "5d41402abc4b2a76b9719d911017c592": "Known malware sample",
}

SUSPICIOUS_PROCESSES = {
    "mimikatz.exe": "Credential dumping tool",
    "psexec.exe": "Remote execution (legitimate but often abused)",
    "cobalt": "Potential Cobalt Strike beacon",
    "netcat": "Network utility often used for reverse shells",
    "nc.exe": "Netcat for Windows",
    "procdump.exe": "Memory dumping tool",
    "lazagne.exe": "Credential recovery tool",
    "bloodhound": "AD enumeration tool",
    "sharphound": "BloodHound data collector",
    "rubeus.exe": "Kerberos attack tool",
}


class LookupIoCTool(BaseTool):
    """Check indicators of compromise against known threat databases."""

    name = "lookup_ioc"
    description = (
        "Look up an Indicator of Compromise (IP, domain, hash, or process name) "
        "against known threat databases. Returns whether the indicator is known malicious."
    )
    parameters = [
        ToolParameter(
            name="indicator",
            description="The IoC value to look up (IP, domain, hash, or process name)",
            type="string",
            required=True,
        ),
        ToolParameter(
            name="ioc_type",
            description="Type of IoC: ip, domain, hash, process (auto-detected if not specified)",
            type="string",
            required=False,
        ),
    ]

    def execute(self, **kwargs) -> ToolResult:
        indicator = kwargs.get("indicator", "").strip()
        ioc_type = kwargs.get("ioc_type", "").strip().lower()

        if not indicator:
            return ToolResult(success=False, output="", error="Indicator cannot be empty")

        if not ioc_type:
            ioc_type = self._detect_type(indicator)

        result = self._lookup(indicator.lower(), ioc_type)
        return result

    def _detect_type(self, indicator: str) -> str:
        """Auto-detect IoC type from the value."""
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        hash_pattern = r"^[a-fA-F0-9]{32,64}$"

        if re.match(ip_pattern, indicator):
            return "ip"
        if re.match(hash_pattern, indicator):
            return "hash"
        if "." in indicator and not indicator.endswith(".exe"):
            return "domain"
        return "process"

    def _lookup(self, indicator: str, ioc_type: str) -> ToolResult:
        """Look up the indicator in known databases."""
        found = False
        details = ""

        if ioc_type == "ip":
            if indicator in KNOWN_MALICIOUS_IPS:
                found = True
                details = f"IP {indicator} is KNOWN MALICIOUS (flagged in threat intelligence)"
            else:
                details = f"IP {indicator} not found in known malicious databases"

        elif ioc_type == "domain":
            if indicator in KNOWN_MALICIOUS_DOMAINS:
                found = True
                details = f"Domain {indicator} is KNOWN MALICIOUS (C2/phishing infrastructure)"
            else:
                details = f"Domain {indicator} not found in known malicious databases"

        elif ioc_type == "hash":
            malware_name = KNOWN_MALICIOUS_HASHES.get(indicator)
            if malware_name:
                found = True
                details = f"Hash {indicator} matches: {malware_name}"
            else:
                details = f"Hash {indicator} not found in known malware databases"

        elif ioc_type == "process":
            for proc, desc in SUSPICIOUS_PROCESSES.items():
                if proc in indicator:
                    found = True
                    details = f"Process '{indicator}' matches suspicious tool: {desc}"
                    break
            if not found:
                details = f"Process '{indicator}' not found in suspicious process list"

        else:
            details = f"Unknown IoC type: {ioc_type}"

        status = "MALICIOUS" if found else "NOT FOUND"
        output = f"IoC Lookup Result:\n  Indicator: {indicator}\n  Type: {ioc_type}\n  Status: {status}\n  Details: {details}"

        return ToolResult(
            success=True,
            output=output,
            data={"indicator": indicator, "type": ioc_type, "is_malicious": found},
        )
