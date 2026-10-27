"""
TANA AI - Compliance Agent
Checks findings against Proclamation 1426/2026 requirements.
"""

import json
from datetime import datetime
from pathlib import Path
from backend.app.core.config import OUTPUT_DIR, BASE_DIR


class ComplianceAgent:
    """
    Compliance Agent
    Maps findings to Ethiopian critical sectors and legal requirements.
    """

    def __init__(self, target: str, scan_results: dict):
        self.target = target
        self.scan_results = scan_results
        self.sectors_file = BASE_DIR / "compliance" / "data" / "critical_sectors.json"
        self.results = {
            "agent": "ComplianceAgent",
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "is_critical_sector": False,
            "matched_sector": None,
            "legal_requirements": [],
            "cert_report_required": False,
            "reporting_deadline_hours": 48,
            "fine_range_etb": "1,500,000 - 2,000,000",
            "general_recommendations": []
        }

    def check_compliance(self) -> dict:
        """Check if findings trigger compliance requirements."""
        print(f"[TANA AI] Checking compliance for {self.target}...")

        self._check_sector()
        self._evaluate_requirements()
        self._add_general_recommendations()

        return self.results

    def _check_sector(self):
        """Check if target belongs to a critical sector."""
        target_lower = self.target.lower()

        sector_keywords = {
            "bank": 2, "finance": 2,
            "telecom": 12, "ethio": 12,
            "gov": 6, "ministry": 6,
            "health": 7, "hospital": 7,
            "edu": 8, "university": 8,
            "fayda": 11, "id": 11,
            "energy": 5, "water": 5,
            "transport": 4, "airline": 4,
        }

        with open(self.sectors_file) as f:
            data = json.load(f)

        for keyword, sector_id in sector_keywords.items():
            if keyword in target_lower:
                sector = next((s for s in data["sectors"] if s["id"] == sector_id), None)
                if sector:
                    self.results["is_critical_sector"] = True
                    self.results["matched_sector"] = sector
                    print(f"[TANA AI] CRITICAL SECTOR DETECTED: {sector['name']}")
                    return

        print(f"[TANA AI] Target is not in a designated critical sector.")

    def _evaluate_requirements(self):
        """Determine which legal requirements apply."""
        s = self.scan_results
        high_severity = s.get("critical", 0) > 0 or s.get("high", 0) > 0
        medium_severity = s.get("medium", 0) > 0

        if self.results["is_critical_sector"]:
            # Full critical infrastructure requirements
            self.results["legal_requirements"].append(
                "MANDATORY: Report to Ethio-CERT within 48 hours"
            )
            self.results["legal_requirements"].append(
                "MANDATORY: Conduct continuous security audits"
            )
            self.results["legal_requirements"].append(
                "MANDATORY: Maintain Security Operations Center (SOC)"
            )
            self.results["legal_requirements"].append(
                "MANDATORY: Comply with 18 cybersecurity regulations"
            )

            if high_severity:
                self.results["cert_report_required"] = True
        else:
            # General recommendations for non-critical targets
            self.results["legal_requirements"].append(
                "RECOMMENDED: Report high-severity findings to Ethio-CERT"
            )
            self.results["legal_requirements"].append(
                "RECOMMENDED: Conduct regular security audits"
            )
            self.results["legal_requirements"].append(
                "RECOMMENDED: Follow Data Protection Proclamation 1321/2024"
            )

            if high_severity or medium_severity:
                self.results["legal_requirements"].append(
                    "ADVISORY: Consider notifying relevant authorities if data is at risk"
                )

    def _add_general_recommendations(self):
        """Add general security recommendations for all targets."""
        self.results["general_recommendations"] = [
            "Update all software to the latest versions",
            "Enforce strong password policies",
            "Enable multi-factor authentication (MFA)",
            "Conduct regular vulnerability scans",
            "Train staff on cybersecurity awareness",
            "Maintain off-site backups of critical data",
        ]

    def summary(self) -> str:
        lines = [
            f"\n{'='*60}",
            f"  TANA AI - Compliance Report",
            f"{'='*60}",
            f"  Target: {self.target}",
            f"  Critical Sector: {'YES' if self.results['is_critical_sector'] else 'NO'}",
        ]

        if self.results["matched_sector"]:
            lines.append(f"  Sector: {self.results['matched_sector']['name']}")
            lines.append(f"  Sector (Amharic): {self.results['matched_sector']['name_am']}")

        lines.append(f"{'-'*60}")

        if self.results["is_critical_sector"]:
            lines.append(f"  Classification: CRITICAL INFRASTRUCTURE")
            lines.append(f"  CERT Report Required: {'YES' if self.results['cert_report_required'] else 'NO'}")
            lines.append(f"  Deadline: {self.results['reporting_deadline_hours']} hours")
            lines.append(f"  Fine if Neglected: ETB {self.results['fine_range_etb']}")
        else:
            lines.append(f"  Classification: Standard Target")
            lines.append(f"  Legal Framework: Data Protection Proclamation 1321/2024")

        lines.append(f"{'-'*60}")
        lines.append(f"  Legal Requirements & Recommendations:")
        for req in self.results["legal_requirements"]:
            lines.append(f"    - {req}")

        lines.append(f"{'='*60}\n")
        return "\n".join(lines)

    def save_results(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = self.target.replace(".", "_").replace("/", "_")
        filename = OUTPUT_DIR / f"compliance_{safe_target}_{timestamp}.json"

        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)

        print(f"[TANA AI] Compliance results saved to {filename}")
        return str(filename)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    mock_scan = {"critical": 0, "high": 2, "medium": 3, "low": 5}

    agent = ComplianceAgent(target, mock_scan)
    agent.check_compliance()
    print(agent.summary())
    agent.save_results()
