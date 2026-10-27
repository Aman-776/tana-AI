"""
TANA AI - Orchestrator Agent
Coordinates Recon and Scan agents to perform a full penetration test.
"""

import json
from datetime import datetime
from pathlib import Path
from backend.app.core.config import OUTPUT_DIR
from backend.app.agents.recon_agent import ReconAgent
from backend.app.agents.scan_agent import ScanAgent


class Orchestrator:
    """
    TANA AI Orchestrator
    Runs the full pipeline: Recon -> Scan -> Report
    """

    def __init__(self, target: str):
        self.target = target
        self.results = {
            "orchestrator": "TANA AI",
            "version": "0.1.0",
            "target": target,
            "started_at": datetime.now().isoformat(),
            "completed_at": None,
            "phases": {
                "recon": None,
                "scan": None
            },
            "summary": {
                "total_ports": 0,
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }

    def run(self) -> dict:
        """Run the full TANA AI pipeline."""
        print(f"\n{'='*60}")
        print(f"  TANA AI - Autonomous Penetration Test")
        print(f"  Target: {self.target}")
        print(f"{'='*60}\n")

        # Phase 1: Reconnaissance
        print(f"[Orchestrator] Phase 1: Reconnaissance")
        print(f"{'-'*60}")
        recon = ReconAgent(self.target)
        recon.run_nmap()
        recon.save_results()
        self.results["phases"]["recon"] = recon.results
        self.results["summary"]["total_ports"] = len(recon.results["ports"])
        print(recon.summary())

        # Phase 2: Vulnerability Scan
        print(f"[Orchestrator] Phase 2: Vulnerability Scanning")
        print(f"{'-'*60}")
        scan = ScanAgent(self.target)
        scan.run_nuclei()
        scan.save_results()
        self.results["phases"]["scan"] = scan.results
        self.results["summary"]["total_findings"] = scan.results["total"]
        self.results["summary"]["critical"] = scan.results["critical"]
        self.results["summary"]["high"] = scan.results["high"]
        self.results["summary"]["medium"] = scan.results["medium"]
        self.results["summary"]["low"] = scan.results["low"]
        print(scan.summary())

        # Phase 3: Complete
        self.results["completed_at"] = datetime.now().isoformat()
        self._save_final_report()

        return self.results

    def _save_final_report(self) -> str:
        """Save the unified report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = self.target.replace(".", "_").replace("/", "_")
        filename = OUTPUT_DIR / f"TANA_REPORT_{safe_target}_{timestamp}.json"

        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)

        print(f"[TANA AI] Final report saved: {filename}")
        return str(filename)

    def final_summary(self) -> str:
        """Print the final summary."""
        s = self.results["summary"]
        lines = [
            f"\n{'='*60}",
            f"  TANA AI - FINAL REPORT",
            f"{'='*60}",
            f"  Target:           {self.target}",
            f"  Started:          {self.results['started_at']}",
            f"  Completed:        {self.results['completed_at']}",
            f"{'='*60}",
            f"  Open Ports:       {s['total_ports']}",
            f"  Total Findings:   {s['total_findings']}",
            f"{'-'*60}",
            f"  Critical:         {s['critical']}",
            f"  High:             {s['high']}",
            f"  Medium:           {s['medium']}",
            f"  Low:              {s['low']}",
            f"{'='*60}",
            f"  Status: TANA AI scan complete.",
            f"{'='*60}\n",
        ]
        return "\n".join(lines)


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"

    orchestrator = Orchestrator(target)
    orchestrator.run()
    print(orchestrator.final_summary())
