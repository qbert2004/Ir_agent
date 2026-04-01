"""
Unified ML Attack Detector for IR-Agent (v3 - Production)
Filters incoming events - only malicious go to Better Stack

v3 Changes (production model):
- Source-stratified training: EVTX + synthetic -> train, real APT recordings -> val
- Feature engineering v3: 41 features, no structural artifacts
- SMOTE oversampling for minority classes
- Probability calibration via Platt scaling (CalibratedClassifierCV)
- No cmdline_length_norm artifact (was 99.56% Gini importance in v1)
- Prioritizes gradient_boosting_production.pkl if available

v2 Changes (heuristic hardening):
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
from collections import Counter
from typing import Tuple, Dict, Any, Optional, List

logger = logging.getLogger("ir-agent")

_BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
# Priority: decoupled > production > legacy
MODEL_PATH_DECOUPLED   = os.path.join(_BASE_DIR, "models", "gradient_boosting_decoupled.pkl")
MODEL_PATH             = os.path.join(_BASE_DIR, "models", "gradient_boosting_production.pkl")
MODEL_PATH_LEGACY      = os.path.join(_BASE_DIR, "models", "gradient_boosting_model.pkl")


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
    v3: Source-stratified production model with calibrated probability scores.
    """

    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold
        self.model = None
        self.scaler = None
        self.metrics = {}
        self._loaded = False
        self._model_version = "unknown"
        self._feature_names: List[str] = []  # populated when production model is loaded

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
        """Load trained model. Prioritizes production (v3) model."""
        paths = [
            (MODEL_PATH_DECOUPLED, "decoupled_v4"),
            (MODEL_PATH, "production_v3"),
            (MODEL_PATH_LEGACY, "legacy_v1"),
            ("models/gradient_boosting_decoupled.pkl", "decoupled_v4"),
            ("models/gradient_boosting_production.pkl", "production_v3"),
            ("models/gradient_boosting_model.pkl", "legacy_v1"),
            ("models/random_forest_model.pkl", "legacy_rf"),
        ]

        for path, version in paths:
            if os.path.exists(path):
                try:
                    with open(path, 'rb') as f:
                        data = pickle.load(f)
                    self.model = data['model']
                    self.scaler = data['scaler']
                    self.metrics = data.get('metrics', {})
                    self._feature_names = data.get('feature_names', [])
                    self._model_version = version
                    self._loaded = True
                    # Use saved threshold if available (Youden J optimized)
                    saved_threshold = data.get('threshold')
                    if saved_threshold is not None:
                        self.threshold = float(saved_threshold)
                    split = data.get('split_strategy', 'random')
                    acc = self.metrics.get('accuracy', 0)
                    auc = self.metrics.get('roc_auc', 0)
                    logger.info(
                        f"ML Detector loaded: {path} [{version}] "
                        f"split={split} acc={acc:.4f} auc={auc:.4f}"
                    )
                    return True
                except Exception as e:
                    logger.warning(f"Failed to load {path}: {e}")

        logger.warning("No ML model found - using heuristic detection")
        return False

    # --------------------------------------------------------------------------- #
    # Feature extraction v4 (decoupled model — behavioral-dominant, 42 features)
    # --------------------------------------------------------------------------- #

    _INTERNAL_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                          "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                          "127.", "::1", "169.254.", "0.")

    _TOP_EIDS_V4 = [1, 3, 5, 6, 7, 12, 13, 22, 4624, 4688]

    _SUSPICIOUS_REG = [
        r"software\microsoft\windows\currentversion\run",
        r"software\microsoft\windows\currentversion\runonce",
        r"system\currentcontrolset\services",
        r"software\microsoft\windows nt\currentversion\winlogon",
        r"software\microsoft\windows nt\currentversion\image file execution options",
        r"software\classes\clsid", r"sam\sam", r"security\policy\secrets",
    ]
    _BENIGN_REG = [
        r"windows defender", r"windowsupdate", r"windows update",
        r"currentversion\uninstall", r"explorer\recentdocs",
        r"fontsubstitutes", r"fonts", r"dhcp", r"tcpip\parameters\interfaces",
        r"eventlog", r"print\printers",
    ]

    def _extract_features_v4(self, event: Dict[str, Any]) -> List[float]:
        """Feature engineering v4: 42 features, behavioral-dominant, reduced EID coupling."""
        cmdline    = _normalize_unicode(str(event.get('command_line', event.get('CommandLine', '')) or '')).lower()
        process    = _normalize_unicode(str(event.get('process_name', event.get('Image', '')) or '')).lower()
        script     = _normalize_unicode(str(event.get('script_block_text', '') or '')).lower()
        parent     = _normalize_unicode(str(event.get('parent_image', event.get('ParentImage', '')) or '')).lower()
        hashes     = str(event.get('hashes', '') or '')
        dest_ip    = str(event.get('destination_ip', '') or '')
        src_ip     = str(event.get('source_ip', '') or '')
        img_loaded = str(event.get('image_loaded', '') or '').lower()
        target_reg = str(event.get('target_object', '') or '').lower()
        signed     = event.get('signed', None)

        try:
            event_id = int(event.get('event_id', event.get('EventID', 0)) or 0)
        except (ValueError, TypeError):
            event_id = 0
        try:
            port = int(event.get('destination_port', event.get('DestinationPort', 0)) or 0)
        except (ValueError, TypeError):
            port = 0

        all_text = f"{cmdline} {script} {process}"
        f: List[float] = []

        # F01-F10: reduced EID one-hot (10 shared EIDs)
        for eid in self._TOP_EIDS_V4:
            f.append(float(event_id == eid))

        # F11-F18: EID semantic groups
        f.append(float(event_id == 1))                       # process_create
        f.append(float(event_id == 3))                       # network
        f.append(float(event_id == 5))                       # process_end
        f.append(float(event_id == 6))                       # driver_load
        f.append(float(event_id == 7))                       # image_load
        f.append(float(event_id in {12, 13, 14}))            # registry
        f.append(float(event_id in {8, 10}))                 # process_inject
        f.append(float(event_id == 22))                      # dns

        # F19: signed_binary
        path_check = img_loaded or process
        if signed is True or signed == "true" or signed == "True":
            f.append(1.0)
        elif signed is False or signed == "false" or signed == "False":
            f.append(0.0)
        else:
            is_sys = any(p in path_check for p in [
                "windows\\system32", "windows\\syswow64",
                "program files\\windows defender", "program files\\google\\chrome"
            ])
            f.append(1.0 if is_sys else 0.5)

        # F20: system_path_binary
        f.append(float(any(p in path_check for p in [
            "windows\\system32", "windows\\syswow64",
            "program files", "program files (x86)"
        ])))

        # F21: user_appdata_path
        f.append(float(any(p in path_check for p in [
            "appdata", "\\temp\\", "\\tmp\\", "downloads",
            "public", "programdata", "\\users\\public\\"
        ])))

        # F22: registry_suspicious_key
        f.append(float(any(rk in target_reg for rk in self._SUSPICIOUS_REG) if target_reg else False))

        # F23: registry_benign_key
        f.append(float(any(rk in target_reg for rk in self._BENIGN_REG) if target_reg else False))

        # F24: dest_is_internal
        f.append(float(bool(dest_ip) and dest_ip.startswith(self._INTERNAL_PREFIXES)))

        # F25: dest_is_external
        is_ext = bool(dest_ip) and not dest_ip.startswith(self._INTERNAL_PREFIXES) and dest_ip != "0.0.0.0"
        f.append(float(is_ext))

        # F26: dest_suspicious_port
        f.append(float(port in {4444, 1337, 31337, 9090, 3333, 5555, 6666, 7777, 8888}))

        # F27: dest_common_port (benign)
        f.append(float(port in {80, 443, 53, 389, 636, 88, 123, 445, 22, 3389}))

        # F28: kw_count_norm
        kw_count = sum(1 for kw in self._V3_SUSPICIOUS_KEYWORDS if kw in all_text)
        f.append(min(kw_count / 5.0, 1.0))

        # F29: susp_process_exact
        proc_name = process.split('/')[-1].split('\\')[-1]
        f.append(float(any(sp == proc_name for sp in self._V3_SUSPICIOUS_PROCESSES)))

        # F30: susp_process_partial
        f.append(float(any(sp in proc_name for sp in self._V3_SUSPICIOUS_PROCESSES)))

        # F31: base64_encoded
        f.append(float(
            '-enc' in cmdline or 'base64' in cmdline or
            'frombase64' in all_text or 'encodedcommand' in cmdline
        ))

        # F32: lsass_credential
        f.append(float(
            'lsass' in all_text or 'sekurlsa' in all_text or
            'procdump' in all_text or 'comsvcs' in all_text
        ))

        # F33: powershell_bypass
        f.append(float(
            'powershell' in process and
            any(x in cmdline for x in ['-enc', '-nop', 'bypass', 'hidden', 'windowstyle'])
        ))

        # F34: network_download
        f.append(float(any(kw in all_text for kw in [
            'webclient', 'downloadstring', 'invoke-webrequest',
            'urlcache', 'bitsadmin', 'wget', 'curl'
        ])))

        # F35: persistence_kw
        f.append(float(any(kw in all_text for kw in [
            'schtasks /create', 'reg add', 'sc create',
            'runonce', 'onlogon', 'hkcu\\software\\microsoft\\windows\\currentversion\\run'
        ])))

        # F36: defense_evasion
        f.append(float(any(kw in all_text for kw in [
            'bypass', 'amsi', 'etw', '-nop', 'hidden',
            'mshta', 'installutil', 'regsvr32', 'cmstp'
        ])))

        # F37: lateral_movement
        f.append(float(any(kw in all_text for kw in [
            'psexec', 'winrs', 'wmic process', 'invoke-wmimethod', 'dcom'
        ])))

        # F38: has_hashes
        f.append(float(bool(hashes and len(hashes) > 10)))

        # F39: high_entropy_cmdline
        if len(cmdline) > 20:
            unique_ratio = len(set(cmdline)) / len(cmdline)
            f.append(float(unique_ratio > 0.6 and len(cmdline) > 50))
        else:
            f.append(0.0)

        # F40: suspicious_parent
        f.append(float(any(sp in parent for sp in [
            'outlook', 'winword', 'excel', 'powerpnt', 'iexplore', 'firefox', 'chrome'
        ])))

        # F41: network_logon
        f.append(float(str(event.get('logon_type', event.get('LogonType', ''))) in ('3', '10')))

        # F42: external_src_ip
        is_src_internal = src_ip.startswith(self._INTERNAL_PREFIXES)
        f.append(float(bool(src_ip) and not is_src_internal))

        return f

    # --------------------------------------------------------------------------- #
    # Feature extraction v3 (production model)
    # --------------------------------------------------------------------------- #

    _TOP_EVENT_IDS = [
        1, 3, 5, 6, 7, 8, 10, 11, 12, 13, 22,
        4624, 4625, 4648, 4672, 4688,
        4698, 4720, 7045, 4104,
    ]
    _V3_SUSPICIOUS_KEYWORDS = [
        'mimikatz', 'sekurlsa', 'lsadump', 'lsass', 'procdump', 'comsvcs',
        'ntds.dit', 'dumpcreds', 'invoke-', 'iex', 'downloadstring',
        'webclient', 'frombase64', 'reflection', 'powersploit', 'empire',
        'bypass', 'hidden', '-enc', 'base64', '-nop', 'amsi', 'etw',
        'cobalt', 'meterpreter', 'payload', 'beacon', 'shellcode',
        'nc.exe', 'netcat', 'psexec', 'winrs', 'wmic process',
        'schtasks /create', 'sc create', 'reg add',
        'certutil -urlcache', 'bitsadmin /transfer',
        'mshta', 'rundll32', 'regsvr32', 'installutil', 'msbuild',
    ]
    _V3_SUSPICIOUS_PROCESSES = [
        'powershell', 'pwsh', 'wscript', 'cscript', 'mshta',
        'rundll32', 'regsvr32', 'certutil', 'bitsadmin',
        'installutil', 'msbuild', 'wmic', 'psexec',
        'mimikatz', 'procdump',
    ]

    def _extract_features_v3(self, event: Dict[str, Any]) -> List[float]:
        """Feature engineering v3: 41 features matching production model."""
        cmdline = _normalize_unicode(str(event.get('command_line', event.get('CommandLine', '')) or '')).lower()
        process = _normalize_unicode(str(event.get('process_name', event.get('Image', '')) or '')).lower()
        script  = _normalize_unicode(str(event.get('script_block_text', '') or '')).lower()
        parent  = _normalize_unicode(str(event.get('parent_image', event.get('ParentImage', '')) or '')).lower()
        hashes  = str(event.get('hashes', '') or '')
        dest_ip = str(event.get('destination_ip', '') or '')
        src_ip  = str(event.get('source_ip', '') or '')

        try:
            event_id = int(event.get('event_id', event.get('EventID', 0)) or 0)
        except (ValueError, TypeError):
            event_id = 0
        try:
            port = int(event.get('destination_port', event.get('DestinationPort', 0)) or 0)
        except (ValueError, TypeError):
            port = 0

        all_text = f"{cmdline} {script} {process}"
        features: List[float] = []

        # F01-F20: event_id one-hot
        for eid in self._TOP_EVENT_IDS:
            features.append(float(event_id == eid))

        # F21: keyword density
        kw_count = sum(1 for kw in self._V3_SUSPICIOUS_KEYWORDS if kw in all_text)
        features.append(min(kw_count / 5.0, 1.0))

        # F22: suspicious process exact match
        proc_name = process.split('/')[-1].split('\\')[-1]
        features.append(float(any(sp == proc_name for sp in self._V3_SUSPICIOUS_PROCESSES)))

        # F23: suspicious process partial match
        features.append(float(any(sp in proc_name for sp in self._V3_SUSPICIOUS_PROCESSES)))

        # F24: base64/encoded
        features.append(float(
            '-enc' in cmdline or 'base64' in cmdline or
            'frombase64' in all_text or 'encodedcommand' in cmdline
        ))

        # F25: LSASS/credential
        features.append(float(
            'lsass' in all_text or 'sekurlsa' in all_text or
            'procdump' in all_text or 'comsvcs' in all_text
        ))

        # F26: PowerShell bypass
        features.append(float(
            'powershell' in process and
            any(f in cmdline for f in ['-enc', '-nop', 'bypass', 'hidden', 'windowstyle'])
        ))

        # F27: network download
        features.append(float(any(kw in all_text for kw in [
            'webclient', 'downloadstring', 'invoke-webrequest',
            'urlcache', 'bitsadmin', 'wget', 'curl'
        ])))

        # F28: persistence
        features.append(float(any(kw in all_text for kw in [
            'schtasks /create', 'reg add', 'sc create',
            'runonce', 'onlogon', 'hkcu\\software\\microsoft\\windows\\currentversion\\run'
        ])))

        # F29: defense evasion
        features.append(float(any(kw in all_text for kw in [
            'bypass', 'amsi', 'etw', '-nop', 'hidden',
            'mshta', 'installutil', 'regsvr32', 'cmstp'
        ])))

        # F30: lateral movement
        features.append(float(any(kw in all_text for kw in [
            'psexec', 'winrs', 'wmic process', 'invoke-wmimethod', 'dcom'
        ])))

        # F31: has destination IP
        features.append(float(bool(dest_ip) and dest_ip not in ('0.0.0.0', '127.0.0.1', '')))

        # F32: suspicious port
        features.append(float(port in {4444, 1337, 8080, 9090, 3333, 31337, 5555, 6666, 7777}))

        # F33: suspicious process path
        is_system = any(p in process for p in ['windows\\system32', 'windows\\syswow64', 'program files'])
        is_susp_path = any(p in process for p in ['appdata', 'temp', 'downloads', 'public', 'programdata'])
        features.append(float(not is_system and is_susp_path))

        # F34: suspicious parent
        features.append(float(any(sp in parent for sp in [
            'outlook', 'winword', 'excel', 'powerpnt', 'iexplore', 'firefox', 'chrome'
        ])))

        # F35: network logon
        features.append(float(str(event.get('logon_type', event.get('LogonType', ''))) in ('3', '10')))

        # F36: external source IP
        is_internal = src_ip.startswith(('10.', '192.168.', '172.', '127.', '::1', ''))
        features.append(float(bool(src_ip) and not is_internal))

        # F37: registry op
        features.append(float(event_id in {12, 13, 14}))

        # F38: driver/image load
        features.append(float(event_id in {6, 7}))

        # F39: process injection
        features.append(float(event_id in {8, 10}))

        # F40: has hashes
        features.append(float(bool(hashes and len(hashes) > 10)))

        # F41: high entropy cmdline
        if len(cmdline) > 20:
            unique_ratio = len(set(cmdline)) / len(cmdline)
            features.append(float(unique_ratio > 0.6 and len(cmdline) > 50))
        else:
            features.append(0.0)

        return features

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
        Uses v3 features when production model is loaded.

        Returns:
            (is_malicious, confidence, reason)
        """
        # Base prediction
        if self._loaded and self.model is not None:
            try:
                import numpy as np
                # Use v3 features for production model, legacy for others
                if self._model_version == "decoupled_v4":
                    feat_v4 = self._extract_features_v4(event)
                    X = np.array([feat_v4], dtype=np.float32)
                    X_scaled = self.scaler.transform(X)
                    base_score = float(self.model.predict_proba(X_scaled)[0][1])
                    base_reason = self._build_reason_v3(feat_v4, base_score)  # compatible subset
                elif self._model_version == "production_v3":
                    feat_v3 = self._extract_features_v3(event)
                    X = np.array([feat_v3], dtype=np.float32)
                    X_scaled = self.scaler.transform(X)
                    base_score = float(self.model.predict_proba(X_scaled)[0][1])
                    base_reason = self._build_reason_v3(feat_v3, base_score)
                else:
                    features = self._extract_features(event)
                    X = np.array([features])
                    X_scaled = self.scaler.transform(X)
                    base_score = float(self.model.predict_proba(X_scaled)[0][1])
                    base_reason = self._build_reason(features, base_score)
            except Exception as e:
                logger.error(f"ML prediction failed: {e}")
                features = self._extract_features(event)
                _, base_score, base_reason = self._heuristic_predict(features)
        else:
            features = self._extract_features(event)
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
        """Build explanation string (legacy v1 features)."""
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
            return f"ML-v1 ({confidence:.0%}): {', '.join(indicators)}"
        return f"ML-v1 ({confidence:.0%}): pattern match"

    def _build_reason_v3(self, features: List[float], confidence: float) -> str:
        """Build explanation string (production v3 features)."""
        indicators = []
        # F21: kw_count_norm (index 20)
        if features[20] > 0:
            kw_cnt = int(features[20] * 5)
            indicators.append(f"{kw_cnt} suspicious keyword(s)")
        # F22/23: process match (index 21, 22)
        if features[21] or features[22]:
            indicators.append("suspicious process")
        # F24: base64 (index 23)
        if features[23]:
            indicators.append("base64/encoded")
        # F25: lsass (index 24)
        if features[24]:
            indicators.append("credential access")
        # F26: powershell bypass (index 25)
        if features[25]:
            indicators.append("PowerShell bypass")
        # F27: network download (index 26)
        if features[26]:
            indicators.append("network download")
        # F28: persistence (index 27)
        if features[27]:
            indicators.append("persistence")
        # F29: defense evasion (index 28)
        if features[28]:
            indicators.append("defense evasion")
        # F30: lateral movement (index 29)
        if features[29]:
            indicators.append("lateral movement")
        # F32: suspicious port (index 31)
        if features[31]:
            indicators.append("C2 port")
        # F34: suspicious parent (index 33)
        if features[33]:
            indicators.append("Office/browser parent")
        # F37-F39: event type flags (index 36-38)
        if features[36]:
            indicators.append("registry op")
        if features[37]:
            indicators.append("driver load")
        if features[38]:
            indicators.append("process injection")
        # F41: high entropy (index 40)
        if features[40]:
            indicators.append("high-entropy cmdline")

        if indicators:
            return f"ML-v3 ({confidence:.0%}): {', '.join(indicators)}"
        return f"ML-v3 ({confidence:.0%}): event-type match"

    @property
    def is_ready(self) -> bool:
        return self._loaded

    def get_stats(self) -> Dict:
        return {
            "model_loaded": self._loaded,
            "model_version": self._model_version,
            "threshold": self.threshold,
            "n_features": len(self._feature_names) if self._feature_names else "legacy",
            "split_strategy": self.metrics.get("split_strategy", "unknown") if isinstance(self.metrics, dict) else "unknown",
            "metrics": self.metrics,
        }


# Singleton
_detector: Optional[MLAttackDetector] = None


def get_detector(threshold: float = 0.5) -> MLAttackDetector:
    """Get ML detector singleton."""
    global _detector
    if _detector is None:
        _detector = MLAttackDetector(threshold=threshold)
    return _detector
