"""
IoC (Indicator of Compromise) lookup tool.

Multi-provider threat intelligence with local cache:
    1. VirusTotal v3 API  — IP, domain, file hash, URL
    2. AbuseIPDB          — IP reputation (abuse confidence score)
    3. Local hardcoded    — fast offline fallback for demos / tests

Cache: in-memory TTL cache (configurable, default 1 hour) to avoid
       burning API quota on repeated lookups of the same indicator.

Config (via .env):
    VIRUSTOTAL_API_KEY   — VirusTotal API key (free tier: 4 req/min)
    ABUSEIPDB_API_KEY    — AbuseIPDB API key  (free tier: 1000 req/day)
"""
from __future__ import annotations

import os
import re
import time
import logging
from collections import OrderedDict
from typing import Dict, Optional, Tuple

import httpx

from app.agent.tools.base import BaseTool, ToolParameter, ToolResult

logger = logging.getLogger("ir-agent")

# ── Cache ─────────────────────────────────────────────────────────────────────
# LRU cache keyed by "{ioc_type}:{indicator}".
# Each value is (result_dict, expires_at_unix_timestamp).
#
# Two eviction policies run together:
#   - TTL: stale entries are skipped on read and purged on write.
#   - LRU size cap: when the dict exceeds IOC_CACHE_MAX_SIZE the oldest
#     (least-recently-used) entry is dropped.  This prevents unbounded growth
#     during long-running deployments with many unique indicators.
CACHE_TTL = int(os.getenv("IOC_CACHE_TTL_SECONDS", "3600"))        # 1 h default
CACHE_MAX_SIZE = int(os.getenv("IOC_CACHE_MAX_SIZE", "10000"))      # max entries

_CACHE: OrderedDict = OrderedDict()  # {cache_key: (result_dict, expires_at)}

# ── Timeouts ──────────────────────────────────────────────────────────────────
HTTP_TIMEOUT = 10.0  # seconds per provider

# ── Local fallback DB ─────────────────────────────────────────────────────────
# Minimal set for offline / test operation — NOT a substitute for real TI.
_LOCAL_MALICIOUS_IPS = {
    "185.220.101.1", "185.220.101.2", "185.220.101.3",
    "45.33.32.156", "104.244.72.115", "192.42.116.1",
}

_LOCAL_MALICIOUS_DOMAINS = {
    "malware-c2.evil.com", "phishing-kit.badactor.net",
    "exfil-data.darkweb.onion", "update-flash.fakecdn.com",
}

_LOCAL_MALICIOUS_HASHES = {
    "e99a18c428cb38d5f260853678922e03": "WannaCry ransomware",
    "5d41402abc4b2a76b9719d911017c592": "Known malware sample",
}

_SUSPICIOUS_PROCESSES = {
    "mimikatz.exe": "Credential dumping tool",
    "psexec.exe": "Remote execution (often abused)",
    "cobalt": "Potential Cobalt Strike beacon",
    "nc.exe": "Netcat for Windows",
    "procdump.exe": "Memory dumping tool",
    "lazagne.exe": "Credential recovery tool",
    "bloodhound": "AD enumeration tool",
    "rubeus.exe": "Kerberos attack tool",
    "sharphound": "BloodHound data collector",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _cache_get(key: str) -> Optional[dict]:
    entry = _CACHE.get(key)
    if entry is None:
        return None
    result, expires_at = entry
    if time.time() < expires_at:
        # Promote to most-recently-used position
        _CACHE.move_to_end(key)
        return result
    # Entry is expired — remove it eagerly
    del _CACHE[key]
    return None


def _cache_set(key: str, value: dict) -> None:
    _CACHE[key] = (value, time.time() + CACHE_TTL)
    _CACHE.move_to_end(key)
    # Evict least-recently-used entries when over the size cap
    while len(_CACHE) > CACHE_MAX_SIZE:
        _CACHE.popitem(last=False)


def _detect_ioc_type(indicator: str) -> str:
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", indicator):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{32}$", indicator):
        return "hash_md5"
    if re.match(r"^[a-fA-F0-9]{40}$", indicator):
        return "hash_sha1"
    if re.match(r"^[a-fA-F0-9]{64}$", indicator):
        return "hash_sha256"
    if indicator.startswith("http://") or indicator.startswith("https://"):
        return "url"
    if "." in indicator and not indicator.endswith(".exe"):
        return "domain"
    return "process"


# ── Provider functions ────────────────────────────────────────────────────────

def _virustotal_lookup(indicator: str, ioc_type: str) -> Optional[dict]:
    """Query VirusTotal v3. Returns parsed result or None on failure."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return None

    headers = {"x-apikey": api_key}
    try:
        if ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
        elif ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
        elif ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
            url = f"https://www.virustotal.com/api/v3/files/{indicator}"
        elif ioc_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            return None

        resp = httpx.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0
            return {
                "provider": "VirusTotal",
                "malicious_votes": malicious,
                "total_engines": total,
                "score": f"{malicious}/{total}",
                "is_malicious": malicious >= 3,
                "reputation": data.get("reputation", 0),
                "tags": data.get("tags", []),
            }
        elif resp.status_code == 404:
            return {"provider": "VirusTotal", "is_malicious": False, "score": "not found"}
        else:
            logger.warning("VirusTotal returned %d for %s", resp.status_code, indicator)
    except httpx.TimeoutException:
        logger.warning("VirusTotal timeout for %s", indicator)
    except Exception as e:
        logger.warning("VirusTotal error: %s", e)
    return None


def _abuseipdb_lookup(ip: str) -> Optional[dict]:
    """Query AbuseIPDB for IP reputation. Returns parsed result or None."""
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return None

    try:
        resp = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code == 200:
            d = resp.json().get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            return {
                "provider": "AbuseIPDB",
                "abuse_confidence_score": score,
                "total_reports": d.get("totalReports", 0),
                "country_code": d.get("countryCode", ""),
                "isp": d.get("isp", ""),
                "is_malicious": score >= 25,
                "is_tor": d.get("isTor", False),
            }
        elif resp.status_code == 429:
            logger.warning("AbuseIPDB rate limit reached")
    except httpx.TimeoutException:
        logger.warning("AbuseIPDB timeout for %s", ip)
    except Exception as e:
        logger.warning("AbuseIPDB error: %s", e)
    return None


def _local_lookup(indicator: str, ioc_type: str) -> dict:
    """Fast local fallback using hardcoded threat intelligence."""
    lower = indicator.lower()

    if ioc_type == "ip":
        if indicator in _LOCAL_MALICIOUS_IPS:
            return {"provider": "local", "is_malicious": True,
                    "details": "Known malicious IP (local threat DB)"}
    elif ioc_type == "domain":
        if lower in _LOCAL_MALICIOUS_DOMAINS:
            return {"provider": "local", "is_malicious": True,
                    "details": "Known malicious domain (local threat DB)"}
    elif ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
        name = _LOCAL_MALICIOUS_HASHES.get(lower)
        if name:
            return {"provider": "local", "is_malicious": True, "details": name}
    elif ioc_type == "process":
        for proc, desc in _SUSPICIOUS_PROCESSES.items():
            if proc in lower:
                return {"provider": "local", "is_malicious": True, "details": desc}

    return {"provider": "local", "is_malicious": False, "details": "not in local DB"}


# ── Tool ──────────────────────────────────────────────────────────────────────

class LookupIoCTool(BaseTool):
    """
    Check indicators of compromise against multiple threat intelligence sources.

    Providers (in order of priority):
        1. VirusTotal — if VIRUSTOTAL_API_KEY is set
        2. AbuseIPDB  — if ABUSEIPDB_API_KEY is set (IPs only)
        3. Local DB   — always available, offline fallback

    Results are cached for CACHE_TTL seconds (default 1h) to conserve API quota.
    """

    name = "lookup_ioc"
    description = (
        "Look up an Indicator of Compromise (IP, domain, file hash, URL, or process name) "
        "against VirusTotal, AbuseIPDB, and local threat databases. "
        "Returns malicious/clean verdict with confidence scoring."
    )
    parameters = [
        ToolParameter(
            name="indicator",
            description="The IoC value (IP address, domain, MD5/SHA256 hash, URL, or process name)",
            type="string",
            required=True,
        ),
        ToolParameter(
            name="ioc_type",
            description="Type: ip, domain, hash_md5, hash_sha256, url, process (auto-detected if omitted)",
            type="string",
            required=False,
        ),
    ]

    def execute(self, **kwargs) -> ToolResult:
        indicator = kwargs.get("indicator", "").strip()
        ioc_type = kwargs.get("ioc_type", "").strip().lower() or _detect_ioc_type(indicator)

        if not indicator:
            return ToolResult(success=False, output="", error="Indicator cannot be empty")

        cache_key = f"{ioc_type}:{indicator.lower()}"
        cached = _cache_get(cache_key)
        if cached:
            return self._format_result(indicator, ioc_type, cached, from_cache=True)

        # Gather results from all available providers
        results = []

        # VirusTotal (all types except process)
        if ioc_type != "process":
            vt = _virustotal_lookup(indicator, ioc_type)
            if vt:
                results.append(vt)

        # AbuseIPDB (IP only)
        if ioc_type == "ip":
            ab = _abuseipdb_lookup(indicator)
            if ab:
                results.append(ab)

        # Local fallback (always runs)
        results.append(_local_lookup(indicator, ioc_type))

        # Aggregate verdict: malicious if ANY provider flags it
        is_malicious = any(r.get("is_malicious", False) for r in results)

        # Build confidence score (0.0–1.0)
        confidence = self._aggregate_confidence(results, ioc_type)

        aggregated = {
            "is_malicious": is_malicious,
            "confidence": confidence,
            "providers": results,
        }
        _cache_set(cache_key, aggregated)

        return self._format_result(indicator, ioc_type, aggregated, from_cache=False)

    def _aggregate_confidence(self, results: list, ioc_type: str) -> float:
        """Compute a weighted-average confidence score in [0.0, 1.0].

        Each provider contributes:
            weighted_score = provider_confidence * provider_weight
            weighted_total = provider_weight

        Provider weights (reflect reliability):
            VirusTotal  0.60  — many independent AV engines, very reliable
            AbuseIPDB   0.50  — crowd-sourced abuse reports, reliable for IPs
            Local DB    0.30  — small hardcoded list, limited scope

        Bug fix: the previous implementation added 0.7 to score for the local
        provider but only 0.3 to weight_total.  This caused score/weight to
        exceed 1.0 (2.33 after cap), effectively giving the local DB alone
        100 % confidence.  The corrected formula caps local confidence at 0.6
        (an offline list should never express full certainty) and scales it by
        its weight before adding to the running total.
        """
        score = 0.0
        weight_total = 0.0

        for r in results:
            if r["provider"] == "VirusTotal":
                malicious = r.get("malicious_votes", 0)
                total = r.get("total_engines", 1) or 1
                provider_confidence = malicious / total        # [0, 1]
                weight = 0.6
                score += provider_confidence * weight
                weight_total += weight
            elif r["provider"] == "AbuseIPDB":
                provider_confidence = r.get("abuse_confidence_score", 0) / 100  # [0, 1]
                weight = 0.5
                score += provider_confidence * weight
                weight_total += weight
            elif r["provider"] == "local":
                # Binary signal from a small hardcoded list.
                # Cap at 0.6 to reflect limited scope — local DB alone should
                # produce at most ~60 % confidence, not 100 %.
                provider_confidence = 0.6 if r.get("is_malicious") else 0.0
                weight = 0.3
                score += provider_confidence * weight
                weight_total += weight

        if weight_total == 0:
            return 0.0
        return min(score / weight_total, 1.0)

    def _format_result(
        self,
        indicator: str,
        ioc_type: str,
        data: dict,
        from_cache: bool,
    ) -> ToolResult:
        is_malicious = data.get("is_malicious", False)
        confidence = data.get("confidence", 0.0)
        providers = data.get("providers", [])

        status = "MALICIOUS" if is_malicious else "CLEAN"
        lines = [
            f"IoC Lookup: {indicator}",
            f"Type: {ioc_type}  |  Verdict: {status}  |  Confidence: {confidence:.0%}",
            f"{'[CACHED] ' if from_cache else ''}",
        ]

        for p in providers:
            name = p.get("provider", "?")
            if name == "VirusTotal":
                lines.append(f"  VirusTotal: {p.get('score', 'N/A')} engines flagged, "
                             f"reputation={p.get('reputation', 0)}")
            elif name == "AbuseIPDB":
                lines.append(f"  AbuseIPDB: abuse_score={p.get('abuse_confidence_score', 0)}%, "
                             f"reports={p.get('total_reports', 0)}, "
                             f"country={p.get('country_code', '?')}"
                             f"{', TOR exit node' if p.get('is_tor') else ''}")
            elif name == "local":
                if p.get("is_malicious"):
                    lines.append(f"  Local DB: {p.get('details', 'flagged')}")

        output = "\n".join(line for line in lines if line.strip())

        return ToolResult(
            success=True,
            output=output,
            data={
                "indicator": indicator,
                "type": ioc_type,
                "is_malicious": is_malicious,
                "confidence": confidence,
                "providers_queried": [p["provider"] for p in providers],
            },
        )
