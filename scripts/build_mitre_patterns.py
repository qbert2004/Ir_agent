"""
Build extended MITRE ATT&CK patterns from enterprise-attack.json.

Parses the full MITRE Enterprise ATT&CK dataset and generates:
    knowledge_base/mitre_attack/patterns_extended.json

This file is loaded by CyberMLEngine at startup, extending MITRE coverage
from ~22 hardcoded techniques to the full 600+ Enterprise ATT&CK dataset.

Usage:
    py scripts/build_mitre_patterns.py
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
ENTERPRISE_JSON = ROOT / "knowledge_base" / "mitre_attack" / "enterprise-attack.json"
OUTPUT_JSON = ROOT / "knowledge_base" / "mitre_attack" / "patterns_extended.json"

# Windows-relevant tactic mapping (MITRE tactic names → short keys)
TACTIC_MAP = {
    "reconnaissance": "reconnaissance",
    "resource-development": "resource_development",
    "initial-access": "initial_access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege-escalation": "privilege_escalation",
    "defense-evasion": "defense_evasion",
    "credential-access": "credential_access",
    "discovery": "discovery",
    "lateral-movement": "lateral_movement",
    "collection": "collection",
    "command-and-control": "command_and_control",
    "exfiltration": "exfiltration",
    "impact": "impact",
}

# Severity weight by tactic
TACTIC_SEVERITY = {
    "credential_access": 90, "lateral_movement": 85, "exfiltration": 85,
    "impact": 80, "command_and_control": 75, "privilege_escalation": 70,
    "persistence": 65, "execution": 60, "defense_evasion": 55,
    "initial_access": 55, "discovery": 40, "collection": 50,
    "reconnaissance": 30, "resource_development": 25,
}


def _extract_keywords(technique: dict) -> list[str]:
    """Extract searchable keywords from technique description and name."""
    keywords = []
    name = technique.get("name", "").lower()

    # Add normalized name words
    words = re.findall(r"[a-z0-9]+", name)
    keywords.extend(w for w in words if len(w) > 3)

    # Extract tool/technique names from description
    desc = ""
    for ref in technique.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            pass

    for prop in technique.get("x_mitre_detection", "").split():
        w = prop.lower().strip(".,;:")
        if len(w) > 5 and w.isalpha():
            keywords.append(w)

    # Key tool names mentioned in technique aliases
    for alias in technique.get("x_mitre_aliases", []):
        keywords.append(alias.lower())

    return list(set(keywords))[:10]  # cap at 10 keywords per technique


def build_patterns():
    if not ENTERPRISE_JSON.exists():
        print(f"ERROR: {ENTERPRISE_JSON} not found.")
        print("Run: py scripts/download_mitre.py")
        return

    print(f"Loading {ENTERPRISE_JSON.name} ...")
    with open(ENTERPRISE_JSON, encoding="utf-8") as f:
        data = json.load(f)

    objects = data.get("objects", [])
    print(f"Total STIX objects: {len(objects)}")

    # Extract technique-to-tactic mapping
    tactic_by_phase = {}

    patterns = {}
    skipped = 0

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            skipped += 1
            continue

        # Get technique ID
        tech_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("T"):
                tech_id = ref["external_id"]
                break

        if not tech_id:
            continue

        # Skip subtechniques of non-Windows platforms
        platforms = [p.lower() for p in obj.get("x_mitre_platforms", [])]
        if platforms and not any(p in platforms for p in ["windows", "azure ad", "office 365", "saas"]):
            skipped += 1
            continue

        # Get tactics
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactic_short = phase.get("phase_name", "")
                if tactic_short in TACTIC_MAP:
                    tactics.append(TACTIC_MAP[tactic_short])

        if not tactics:
            continue

        tactic = tactics[0]
        name = obj.get("name", "")
        keywords = _extract_keywords(obj)

        patterns[tech_id] = {
            "name": name,
            "tactic": tactic,
            "all_tactics": tactics,
            "keywords": keywords,
            "severity": TACTIC_SEVERITY.get(tactic, 50),
            "description": obj.get("description", "")[:200],
            "is_subtechnique": "." in tech_id,
        }

    print(f"Extracted: {len(patterns)} techniques, skipped: {skipped}")

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(patterns, f, indent=2, ensure_ascii=False)

    print(f"Saved: {OUTPUT_JSON}")
    print(f"File size: {OUTPUT_JSON.stat().st_size / 1024:.1f} KB")

    # Stats
    by_tactic = {}
    for t in patterns.values():
        tactic = t["tactic"]
        by_tactic[tactic] = by_tactic.get(tactic, 0) + 1
    print("\nTechniques by tactic:")
    for tactic, count in sorted(by_tactic.items(), key=lambda x: -x[1]):
        print(f"  {tactic:30s} {count}")


if __name__ == "__main__":
    build_patterns()
