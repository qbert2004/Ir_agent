"""
Unified ML Attack Detector for IR-Agent (v2 - Hardened)
Filters incoming events - only malicious go to Better Stack
Trained on EVTX-ATTACK-SAMPLES dataset (4,633 real attack events)

v2 Changes:
- Unicode normalization (homoglyph defense)
- Extended LOLBins (python, java, go, schtasks, wmic, etc.)
- script_block_text, image_loaded, original_filename analysis
- DNS exfiltration detection
- DLL sideloading detection
- Scheduled task / WMI persistence
- Env variable evasion detection
- Token theft / logon type analysis
"""

import os
import re
import pickle
import logging
import unicodedata
from typing import Tuple, Dict, Any, Optional

logger = logging.getLogger("ir-agent")

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "models", "gradient_boosting_model.pkl")


_HOMOGLYPH_MAP = {
    # Cyrillic → Latin
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
    '\u0455': 's', '\u0458': 'j', '\u0460': 'o', '\u0431': 'b',
    '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041a': 'K',
    '\u041c': 'M', '\u041d': 'H', '\u041e': 'O', '\u0420': 'P',
    '\u0421': 'C', '\u0422': 'T', '\u0425': 'X',
    # Turkish / special
    '\u0131': 'i', '\u0130': 'I',
    # Greek
    '\u03b1': 'a', '\u03b5': 'e', '\u03bf': 'o', '\u03c1': 'p',
    '\u0391': 'A', '\u0395': 'E', '\u039f': 'O',
}


def _normalize_unicode(text: str) -> str:
    """Normalize Unicode to ASCII to defeat homoglyph attacks."""
    if not text:
        return ""
    # Step 1: Replace known homoglyphs
    chars = []
    for ch in text:
        chars.append(_HOMOGLYPH_MAP.get(ch, ch))
    text = "".join(chars)
    # Step 2: NFKD decomposition
    normalized = unicodedata.normalize("NFKD", text)
    ascii_text = normalized.encode("ascii", "ignore").decode("ascii")
    # Step 3: Strip evasion chars
    ascii_text = ascii_text.replace('"', '').replace("'", "").replace('`', '')
    return ascii_text


class MLAttackDetector:
    """
    ML-based attack detector for Windows security events.
    Hardened against evasion techniques (Unicode, concat, env vars, LOLBins).
    """

    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold
        self.model = None
        self.scaler = None
        self.metrics = {}
        self._loaded = False

        # --- Extended keyword list ---
        self.suspicious_keywords = [
            # Credential dumping
            'mimikatz', 'sekurlsa', 'lsadump', 'lsass', 'procdump', 'comsvcs',
            'ntds.dit', 'sam', 'dumpcreds',
            # PowerShell abuse
            'invoke-', 'iex', 'invoke-expression', 'invoke-command',
            'downloadstring', 'downloadfile', 'webclient', 'invoke-webrequest',
            'frombase64', 'reflection', 'assembly', 'load',
            'powersploit', 'empire', 'nishang',
            # Encoding / evasion
            'bypass', 'hidden', 'encoded', '-enc', '-e ', 'base64',
            '-nop', 'noprofile', '-windowstyle', '-w hidden',
            'amsi', 'etw',
            # C2 / remote
            'cobalt', 'meterpreter', 'reverse', 'payload', 'exploit',
            'beacon', 'stager', 'shellcode',
            'nc.exe', 'netcat', 'ncat', 'socat',
            # Lateral movement
            'psexec', 'winrs', 'wmic process', 'wmiprvse',
            # Persistence
            'schtasks', '/create', 'onstart', 'onlogon',
            'new-scheduledtask', 'register-scheduledtask',
            'sc create', 'sc config', 'reg add',
            'run /v', 'runonce',
            # Data staging / exfil
            'compress-archive', '7z a', 'rar a',
            # LOLBin commands
            'certutil', 'urlcache', 'bitsadmin', '/transfer',
            'mshta', 'javascript:', 'vbscript:',
            'rundll32', 'regsvr32', '/s /n /u /i:',
            'cmstp', 'installutil', 'msbuild',
            # Network / reverse shell patterns
            'socket', 'subprocess', 'os.dup2', 'connect(',
            'tcpclient', 'nettcpclient',
            '/bin/sh', '/bin/bash', 'chr(',
        ]

        # --- Extended process list ---
        self.suspicious_processes = [
            # Classic LOLBins
            'powershell', 'pwsh', 'cmd.exe', 'wscript', 'cscript',
            'mshta', 'rundll32', 'regsvr32', 'certutil', 'bitsadmin',
            'msiexec', 'cmstp', 'installutil', 'msbuild',
            # Persistence / management
            'schtasks', 'at.exe', 'sc.exe', 'reg.exe', 'net.exe', 'net1.exe',
            # Scripting runtimes (reverse shells)
            'python', 'python3', 'python.exe', 'pythonw.exe',
            'java', 'java.exe', 'javaw.exe',
            'node', 'node.exe',
            'ruby', 'perl', 'php',
            # Recon / lateral
            'wmic', 'wmic.exe', 'wmiprvse',
            'psexec', 'psexec64',
            'nltest', 'dsquery', 'klist',
            'whoami', 'systeminfo', 'ipconfig', 'nslookup',
            'netstat', 'tasklist', 'query',
            # Dumping tools
            'mimikatz', 'procdump', 'processhacker',
        ]

        self.high_risk_event_ids = [
            4688, 4689, 4624, 4625, 4648, 4672,       # Process, Logon
            4698, 4699, 4700, 4701, 4702,               # Scheduled tasks
            7045, 7036,                                   # Service installs
            4104, 4103,                                   # PowerShell
            1, 3, 7, 8, 10, 11, 12, 13, 15, 22, 23, 25, # Sysmon
            4720, 4726, 4732, 4756,                       # User/Group changes
        ]

        # Suspicious DLL load paths
        self._suspicious_dll_paths = [
            'users/public', 'appdata/local/temp', 'downloads',
            'programdata', 'windows/temp', 'recycle',
        ]

        # DNS exfil patterns
        self._dns_exfil_patterns = [
            re.compile(r'[a-zA-Z0-9+/=]{10,}\.[a-zA-Z0-9.-]+\.[a-z]{2,}'),  # base64 subdomain
            re.compile(r'([a-f0-9]{8,}\.){2,}'),  # hex-encoded chunks
            re.compile(r'^[a-zA-Z0-9._-]+\.[a-zA-Z0-9]{8,}\.[a-zA-Z0-9.-]+\.[a-z]{2,}$'),  # data.ENCODED.domain
        ]

        self._load_model()

    def _load_model(self) -> bool:
        """Load trained model."""
        paths = [
            MODEL_PATH,
            "models/gradient_boosting_model.pkl",
            "models/random_forest_model.pkl",
        ]

        for path in paths:
            if os.path.exists(path):
                try:
                    with open(path, 'rb') as f:
                        data = pickle.load(f)
                    self.model = data['model']
                    self.scaler = data['scaler']
                    self.metrics = data.get('metrics', {})
                    self._loaded = True
                    logger.info(f"ML Detector loaded: {path}")
                    return True
                except Exception as e:
                    logger.warning(f"Failed to load {path}: {e}")

        logger.warning("No ML model found - using heuristic detection")
        return False

    def _get_all_text_fields(self, event: Dict[str, Any]) -> str:
        """Combine ALL text fields for analysis, with Unicode normalization."""
        fields = [
            event.get('command_line', ''),
            event.get('CommandLine', ''),
            event.get('script_block_text', ''),
            event.get('ScriptBlockText', ''),
            event.get('image_loaded', ''),
            event.get('ImageLoaded', ''),
            event.get('service_file', ''),
            event.get('ServiceFileName', ''),
            event.get('message', ''),
            event.get('parent_command_line', ''),
            event.get('ParentCommandLine', ''),
        ]
        raw = " ".join(str(f) for f in fields if f)
        return _normalize_unicode(raw).lower()

    def _get_process_name(self, event: Dict[str, Any]) -> str:
        """Get normalized process name."""
        process = str(event.get('process_name', event.get('ProcessName',
                      event.get('Image', '')))).lower()
        return _normalize_unicode(process)

    def _get_original_filename(self, event: Dict[str, Any]) -> str:
        """Get original filename (detects renamed binaries)."""
        return str(event.get('original_filename', event.get(
            'OriginalFileName', ''))).lower()

    def _extract_features(self, event: Dict[str, Any]) -> list:
        """Extract features matching training format + extended features."""
        event_id = 0
        try:
            event_id = int(event.get('event_id', event.get('EventID', 0)) or 0)
        except (ValueError, TypeError):
            event_id = 0

        process = self._get_process_name(event)
        all_text = self._get_all_text_fields(event)
        cmdline = _normalize_unicode(
            str(event.get('command_line', event.get('CommandLine', '')))
        ).lower()
        parent = _normalize_unicode(
            str(event.get('parent_image', event.get('ParentImage', '')))
        ).lower()
        user = str(event.get('user', event.get('SubjectUserName',
                   event.get('TargetUserName', '')))).upper()
        logon_type = 0
        try:
            logon_type = int(event.get('logon_type', event.get('LogonType', 0)) or 0)
        except (ValueError, TypeError):
            logon_type = 0
        dest_port = 0
        try:
            dest_port = int(event.get('destination_port', event.get('DestinationPort', 0)) or 0)
        except (ValueError, TypeError):
            dest_port = 0
        channel = str(event.get('channel', event.get('Channel', 'Security')))

        return [
            event_id,                                                         # 0
            int(event_id in self.high_risk_event_ids),                       # 1
            hash(channel) % 12,                                               # 2
            int(any(p in process for p in self.suspicious_processes)),        # 3
            len(cmdline),                                                     # 4
            sum(1 for kw in self.suspicious_keywords if kw in all_text),     # 5 - uses ALL text
            int(any(x in all_text for x in ['-enc', '-e ', 'base64', 'frombase64'])),  # 6
            int(any(x in all_text for x in ['download', 'webclient', 'invoke-webrequest', 'urlcache'])),  # 7
            int(any(x in all_text for x in ['-w hidden', '-windowstyle h', 'hidden'])),  # 8
            int(any(p in parent for p in self.suspicious_processes)),         # 9
            logon_type,                                                       # 10
            int(logon_type in [3, 10]),                                      # 11
            int(user in ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE']),     # 12
            int('ADMIN' in user),                                             # 13
            dest_port,                                                        # 14
            int(dest_port in [443, 8443, 8080, 4444, 5555, 1337, 1234, 9999, 31337]),  # 15
        ]

    def _check_advanced_indicators(self, event: Dict[str, Any]) -> Tuple[float, list]:
        """
        Check for advanced attack indicators NOT covered by basic features.
        Returns (extra_score, reasons).
        """
        score = 0.0
        reasons = []

        # --- 1. Renamed binary detection ---
        original = self._get_original_filename(event)
        process = self._get_process_name(event)
        if original and process:
            orig_base = original.rsplit('\\', 1)[-1].rsplit('/', 1)[-1]
            proc_base = process.rsplit('\\', 1)[-1].rsplit('/', 1)[-1]
            if orig_base and proc_base and orig_base != proc_base:
                if any(s in orig_base for s in self.suspicious_processes):
                    score += 0.6
                    reasons.append(f"renamed binary ({orig_base} -> {proc_base})")

        # --- 2. DLL sideloading detection ---
        image_loaded = str(event.get('image_loaded', event.get('ImageLoaded', ''))).lower()
        if image_loaded:
            if any(p in image_loaded for p in self._suspicious_dll_paths):
                signed = event.get('signed', event.get('Signed', True))
                if not signed or signed == 'false' or signed is False:
                    score += 0.55
                    reasons.append(f"unsigned DLL from suspicious path")
                else:
                    score += 0.3
                    reasons.append(f"DLL from suspicious path")

        # --- 3. DNS exfiltration detection ---
        query_name = str(event.get('query_name', event.get('QueryName', ''))).lower()
        if query_name:
            dns_hit = False
            for pattern in self._dns_exfil_patterns:
                if pattern.search(query_name):
                    score += 0.6
                    reasons.append(f"DNS exfil pattern: {query_name[:50]}")
                    dns_hit = True
                    break
            # Long subdomain labels = data encoding
            labels = query_name.split('.')
            if any(len(l) > 20 for l in labels):
                score += 0.4
                reasons.append("long DNS subdomain label (data encoding)")
                dns_hit = True
            # High entropy subdomain (base64/hex-like)
            if not dns_hit and len(labels) >= 3:
                subdomain = labels[0]
                if len(subdomain) > 8:
                    alpha = sum(1 for c in subdomain if c.isalpha())
                    digit = sum(1 for c in subdomain if c.isdigit())
                    if digit > 0 and alpha > 0 and (digit / len(subdomain)) > 0.2:
                        score += 0.5
                        reasons.append(f"high-entropy DNS subdomain: {subdomain[:30]}")

        # --- 4. Scheduled task / WMI persistence ---
        all_text = self._get_all_text_fields(event)
        event_id = 0
        try:
            event_id = int(event.get('event_id', event.get('EventID', 0)) or 0)
        except (ValueError, TypeError):
            pass

        if event_id == 4698:  # Scheduled task created
            score += 0.4
            reasons.append("scheduled task created (4698)")
            if any(kw in all_text for kw in ['system', 'onstart', 'onlogon', '/ru']):
                score += 0.15
                reasons.append("task runs as SYSTEM/on boot")

        if event_id == 7045:  # Service installed
            score += 0.45
            reasons.append("new service installed (7045)")

        # --- 5. Token theft / special logon types ---
        logon_type = 0
        try:
            logon_type = int(event.get('logon_type', event.get('LogonType', 0)) or 0)
        except (ValueError, TypeError):
            pass

        if logon_type == 9:  # NewCredentials
            score += 0.4
            reasons.append("NewCredentials logon (token theft)")
        elif logon_type == 10:  # RemoteInteractive (RDP)
            source_ip = str(event.get('source_ip', ''))
            if source_ip and not source_ip.startswith(('10.', '192.168.', '172.', '127.')):
                score += 0.35
                reasons.append(f"external RDP from {source_ip}")

        # --- 6. Env variable evasion ---
        cmdline_raw = str(event.get('command_line', event.get('CommandLine', '')))
        if re.search(r'%[a-zA-Z]+%', cmdline_raw) and re.search(r'set\s+\w+=', cmdline_raw, re.I):
            score += 0.35
            reasons.append("environment variable evasion")

        # --- 7. Script block content (fileless) ---
        script_text = str(event.get('script_block_text', event.get('ScriptBlockText', '')))
        if script_text and len(script_text) > 50:
            script_lower = _normalize_unicode(script_text).lower()
            fileless_indicators = ['reflection', 'assembly', 'load', 'frombase64',
                                   'invoke', 'virtualalloc', 'createthread',
                                   'shellcode', 'getprocaddress', 'kernel32']
            hits = sum(1 for ind in fileless_indicators if ind in script_lower)
            if hits >= 2:
                score += 0.2 * min(hits, 4)
                reasons.append(f"fileless indicators in script ({hits} hits)")

        # --- 8. Network connection anomalies ---
        try:
            _dest_port = int(event.get('destination_port', event.get('DestinationPort', 0)) or 0)
        except (ValueError, TypeError):
            _dest_port = 0

        if event_id == 3:  # Sysmon NetworkConnect
            if _dest_port and _dest_port in [4444, 5555, 1337, 31337, 9999, 1234, 8888]:
                score += 0.45
                reasons.append(f"connection to C2 port {_dest_port}")
            # Any outbound from suspicious process
            dest_ip = str(event.get('destination_ip', event.get('DestinationIp', '')))
            if dest_ip and not dest_ip.startswith(('10.', '192.168.', '172.', '127.', '0.')):
                process_lower = self._get_process_name(event)
                if any(p in process_lower for p in ['powershell', 'cmd', 'python', 'wscript',
                                                      'mshta', 'rundll32', 'regsvr32']):
                    score += 0.35
                    reasons.append(f"outbound from LOLBin to {dest_ip}")

        # --- 9. WMI lateral movement ---
        process_name = self._get_process_name(event)
        if 'wmiprvse' in process_name:
            parent_lower = _normalize_unicode(
                str(event.get('parent_image', event.get('ParentImage', '')))
            ).lower()
            if 'svchost' in parent_lower or not parent_lower:
                score += 0.4
                reasons.append("WMI provider execution (lateral movement indicator)")

        # --- 10. Token theft / explicit credential logon ---
        if event_id == 4648:
            score += 0.35
            reasons.append("explicit credential use (4648)")

        # --- 11. Unsigned image load from user directories ---
        if event_id == 7 and image_loaded:
            if not any(p in image_loaded for p in self._suspicious_dll_paths):
                # Even non-suspicious paths with unsigned DLLs are suspicious for sysmon evt 7
                signed = event.get('signed', event.get('Signed', True))
                if not signed or signed == 'false' or signed is False:
                    score += 0.25
                    reasons.append("unsigned DLL loaded")

        return min(score, 1.0), reasons

    def predict(self, event: Dict[str, Any]) -> Tuple[bool, float, str]:
        """
        Predict if event is malicious.
        Combines ML model + heuristics + advanced indicator checks.

        Returns:
            (is_malicious, confidence, reason)
        """
        features = self._extract_features(event)

        # Base prediction
        if self._loaded and self.model is not None:
            try:
                import numpy as np
                X = np.array([features])
                X_scaled = self.scaler.transform(X)
                base_score = float(self.model.predict_proba(X_scaled)[0][1])
                base_reason = self._build_reason(features, base_score)
            except Exception as e:
                logger.error(f"ML prediction failed: {e}")
                _, base_score, base_reason = self._heuristic_predict(features)
        else:
            _, base_score, base_reason = self._heuristic_predict(features)

        # Advanced indicators
        adv_score, adv_reasons = self._check_advanced_indicators(event)

        # Combine scores (weighted max)
        final_score = min(max(base_score, adv_score, (base_score + adv_score) * 0.7), 1.0)

        # Build combined reason
        all_reasons = base_reason
        if adv_reasons:
            all_reasons += " + " + ", ".join(adv_reasons)

        is_malicious = final_score >= self.threshold
        return is_malicious, final_score, all_reasons

    def _heuristic_predict(self, features: list) -> Tuple[bool, float, str]:
        """Fallback heuristic detection."""
        score = 0.0
        reasons = []

        if features[5] > 0:  # suspicious_keyword_count
            score += 0.25 * min(features[5], 4)
            reasons.append(f"{features[5]} suspicious keywords")
        if features[3]:  # is_suspicious_process
            score += 0.15
            reasons.append("LOLBin")
        if features[6]:  # has_base64
            score += 0.2
            reasons.append("base64")
        if features[7]:  # has_download
            score += 0.15
            reasons.append("download")
        if features[8]:  # has_hidden
            score += 0.15
            reasons.append("hidden")
        if features[9]:  # parent_is_suspicious
            score += 0.1
            reasons.append("suspicious parent")
        if features[1]:  # high risk event id
            score += 0.05
            reasons.append(f"high-risk event {features[0]}")
        if features[11]:  # remote logon
            score += 0.1
            reasons.append("remote logon")
        if features[15]:  # C2 port
            score += 0.2
            reasons.append(f"C2 port {features[14]}")

        score = min(score, 1.0)
        is_malicious = score >= self.threshold
        reason = f"Heuristic: {', '.join(reasons)}" if reasons else "No indicators"
        return is_malicious, score, reason

    def _build_reason(self, features: list, confidence: float) -> str:
        """Build explanation string."""
        indicators = []
        if features[5] > 0:
            indicators.append(f"{features[5]} malicious keywords")
        if features[3]:
            indicators.append("LOLBin process")
        if features[6]:
            indicators.append("base64 encoded")
        if features[7]:
            indicators.append("download command")
        if features[8]:
            indicators.append("hidden window")
        if features[9]:
            indicators.append("suspicious parent")
        if features[15]:
            indicators.append(f"C2 port {features[14]}")

        if indicators:
            return f"ML ({confidence:.0%}): {', '.join(indicators)}"
        return f"ML ({confidence:.0%}): pattern match"

    @property
    def is_ready(self) -> bool:
        return self._loaded

    def get_stats(self) -> Dict:
        return {
            "model_loaded": self._loaded,
            "threshold": self.threshold,
            "metrics": self.metrics
        }


# Singleton
_detector: Optional[MLAttackDetector] = None


def get_detector(threshold: float = 0.5) -> MLAttackDetector:
    """Get ML detector singleton."""
    global _detector
    if _detector is None:
        _detector = MLAttackDetector(threshold=threshold)
    return _detector
