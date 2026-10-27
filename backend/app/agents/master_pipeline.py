"""
TANA AI - Master Pipeline
Runs the complete autonomous penetration test:
Recon -> Scan -> Compliance -> Report
"""

import json
from datetime import datetime
from pathlib import Path
from backend.app.core.config import OUTPUT_DIR
from backend.app.agents.recon_agent import ReconAgent
from backend.app.agents.scan_agent import ScanAgent
from backend.app.agents.compliance_agent import ComplianceAgent
from backend.app.agents.report_agent import ReportAgent


class MasterPipeline:
    """
    TANA AI Master Pipeline
    Complete autonomous security assessment.
    """

    def __init__(self, target: str):
        self.target = target
        self.started_at = datetime.now()
        self.results = {
            "tana_ai": "Master Pipeline",
            "version": "0.1.0",
            "target": target,
            "started_at": self.started_at.isoformat(),
            "completed_at": None,
            "phases": {}
        }

    def run(self):
        """Run all phases."""
        print(f"\n{'#'*70}")
        print(f"#  TANA AI - MASTER PIPELINE")
        print(f"#  Target: {self.target}")
        print(f"#  Started: {self.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'#'*70}\n")

        # Phase 1: Recon
        print(f"\n[PHASE 1/4] Reconnaissance")
        print(f"{'-'*70}")
        recon = ReconAgent(self.target)
        recon.run_nmap()
        recon.save_results()
        self.results["phases"]["recon"] = recon.results
        print(recon.summary())

        # Phase 2: Vulnerability Scan
        print(f"\n[PHASE 2/4] Vulnerability Scanning")
        print(f"{'-'*70}")
        scan = ScanAgent(self.target)
        scan.run_nuclei()
        scan.save_results()
        self.results["phases"]["scan"] = scan.results
        print(scan.summary())

        # Phase 3: Compliance
        print(f"\n[PHASE 3/4] Compliance Assessment")
        print(f"{'-'*70}")
        compliance = ComplianceAgent(self.target, scan.results)
        compliance.check_compliance()
        compliance.save_results()
        self.results["phases"]["compliance"] = compliance.results
        print(compliance.summary())

        # Phase 4: Report
        print(f"\n[PHASE 4/4] Report Generation")
        print(f"{'-'*70}")
        reporter = ReportAgent(
            self.target,
            recon.results,
            scan.results,
            compliance.results
        )
        pdf_path = reporter.generate()
        self.results["phases"]["report"] = {"pdf_path": pdf_path}

        # Save master report
        self.results["completed_at"] = datetime.now().isoformat()
        self._save_master_report()

        # Final summary
        self._final_summary()

        return self.results

    def _save_master_report(self):
        """Save master JSON report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = self.target.replace(".", "_").replace("/", "_")
        filename = OUTPUT_DIR / f"TANA_MASTER_{safe_target}_{timestamp}.json"

        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)

        print(f"\n[TANA AI] Master report saved: {filename}")

    def _final_summary(self):
        """Print final summary."""
        recon = self.results["phases"]["recon"]
        scan = self.results["phases"]["scan"]
        compliance = self.results["phases"]["compliance"]
        report = self.results["phases"]["report"]

        duration = (
            datetime.fromisoformat(self.results["completed_at"]) -
            datetime.fromisoformat(self.results["started_at"])
        ).total_seconds()

        print(f"\n{'#'*70}")
        print(f"#  TANA AI - SCAN COMPLETE")
        print(f"{'#'*70}")
        print(f"  Target:           {self.target}")
        print(f"  Duration:         {duration:.1f} seconds")
        print(f"  Open Ports:       {len(recon.get('ports', []))}")
        print(f"  Vulnerabilities:  {scan.get('total', 0)}")
        print(f"  Critical Sector:  {'YES' if compliance.get('is_critical_sector') else 'NO'}")

        if compliance.get("cert_report_required"):
            print(f"  ⚠ CERT Report:    REQUIRED (48 hours)")

        print(f"  PDF Report:       {report.get('pdf_path', 'N/A')}")
        print(f"{'#'*70}\n")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 -m backend.app.agents.master_pipeline <target>")
        sys.exit(1)

    target = sys.argv[1]
    pipeline = MasterPipeline(target)
    pipeline.run()
