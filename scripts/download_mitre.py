"""Download MITRE ATT&CK Enterprise STIX data and convert to knowledge base format."""

import json
import os
import sys
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUTPUT_DIR = ROOT / "knowledge_base" / "mitre_attack"


def download_mitre_data():
    """Download MITRE ATT&CK STIX bundle."""
    import httpx

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    stix_file = OUTPUT_DIR / "enterprise-attack.json"

    if stix_file.exists():
        print(f"MITRE data already exists at {stix_file}")
        response = input("Re-download? (y/N): ").strip().lower()
        if response != "y":
            return str(stix_file)

    print(f"Downloading MITRE ATT&CK Enterprise from:\n  {MITRE_STIX_URL}")
    print("This may take a moment (~30MB)...")

    response = httpx.get(MITRE_STIX_URL, timeout=120.0, follow_redirects=True)
    response.raise_for_status()

    stix_file.write_bytes(response.content)
    print(f"Downloaded {len(response.content) / 1024 / 1024:.1f} MB to {stix_file}")

    return str(stix_file)


def parse_stix_to_knowledge(stix_path: str):
    """Parse STIX JSON into structured knowledge base documents."""
    print("\nParsing STIX data into knowledge documents...")

    with open(stix_path, "r", encoding="utf-8") as f:
        stix_data = json.load(f)

    objects = stix_data.get("objects", [])
    techniques = []
    tactics = []

    for obj in objects:
        obj_type = obj.get("type", "")

        if obj_type == "attack-pattern":
            # This is a technique
            name = obj.get("name", "")
            description = obj.get("description", "")
            external_refs = obj.get("external_references", [])

            technique_id = ""
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    break

            if not technique_id or not name:
                continue

            kill_chain = obj.get("kill_chain_phases", [])
            tactic_names = [p.get("phase_name", "").replace("-", " ").title() for p in kill_chain]

            platforms = obj.get("x_mitre_platforms", [])

            entry = {
                "id": technique_id,
                "name": name,
                "description": description[:2000],
                "tactics": tactic_names,
                "platforms": platforms,
            }
            techniques.append(entry)

        elif obj_type == "x-mitre-tactic":
            name = obj.get("name", "")
            description = obj.get("description", "")
            external_refs = obj.get("external_references", [])

            tactic_id = ""
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    tactic_id = ref.get("external_id", "")
                    break

            if name:
                tactics.append({
                    "id": tactic_id,
                    "name": name,
                    "description": description[:1000],
                })

    # Write techniques to text files for ingestion
    techniques_file = OUTPUT_DIR / "techniques.txt"
    with open(techniques_file, "w", encoding="utf-8") as f:
        for tech in techniques:
            f.write(f"## {tech['id']}: {tech['name']}\n")
            f.write(f"Tactics: {', '.join(tech['tactics'])}\n")
            f.write(f"Platforms: {', '.join(tech['platforms'])}\n")
            f.write(f"{tech['description']}\n\n")

    # Write tactics
    tactics_file = OUTPUT_DIR / "tactics.txt"
    with open(tactics_file, "w", encoding="utf-8") as f:
        for tac in tactics:
            f.write(f"## {tac['id']}: {tac['name']}\n")
            f.write(f"{tac['description']}\n\n")

    print(f"Parsed {len(techniques)} techniques and {len(tactics)} tactics")
    print(f"Written to:\n  {techniques_file}\n  {tactics_file}")

    return len(techniques), len(tactics)


def main():
    print("=" * 60)
    print("MITRE ATT&CK Data Downloader")
    print("=" * 60)

    stix_path = download_mitre_data()
    parse_stix_to_knowledge(stix_path)

    print("\nDone! Run 'python scripts/ingest_knowledge.py' to index the data.")


if __name__ == "__main__":
    main()
