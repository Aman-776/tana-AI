"""
TANA AI - Scan Agent
Uses Nuclei to detect vulnerabilities on discovered services.
"""

import subprocess
import json
from datetime import datetime
from pathlib import Path
from backend.app.core.config import OUTPUT_DIR, SCAN_TIMEOUT


class ScanAgent:
    """
    Vulnerability Scan Agent
    Takes a target and runs Nuclei to detect known vulnerabilities.
    """

    def __init__(self, target: str):
        self.target = target
        self.results = {
            "agent": "ScanAgent",
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "findings": [],
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "success": False,
            "error": None
        }

    def run_nuclei(self) -> dict:
        """Run Nuclei vulnerability scan."""
        print(f"[TANA AI] Starting vulnerability scan on {self.target}...")

        try:
            command = [
                "nuclei",
                "-target", self.target,
                "-severity", "critical,high,medium,low",
                "-jsonl",              # JSON Lines output
                "-silent",
                "-no-color"
            ]

            print(f"[TANA AI] Running: {' '.join(command)}")

            output = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT
            )

            self.results["success"] = True
            self._parse_nuclei_output(output.stdout)

            return self.results

        except subprocess.TimeoutExpired:
            self.results["error"] = "Scan timed out"
            print("[TANA AI] Scan timed out")
            return self.results
        except FileNotFoundError:
            self.results["error"] = "Nuclei is not installed"
            print("[TANA AI] ERROR: Nuclei is not installed")
            return self.results
        except Exception as e:
            self.results["error"] = str(e)
            print(f"[TANA AI] ERROR: {e}")
            return self.results

    def _parse_nuclei_output(self, output: str):
        """Parse Nuclei JSONL output."""
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                finding = json.loads(line)
                severity = finding.get("info", {}).get("severity", "unknown").lower()

                self.results["findings"].append({
                    "template": finding.get("template-id", ""),
                    "name": finding.get("info", {}).get("name", ""),
                    "severity": severity,
                    "host": finding.get("host", ""),
                    "matched": finding.get("matched-at", ""),
                    "description": finding.get("info", {}).get("description", "")
                })

                if severity in self.results:
                    self.results[severity] += 1
                self.results["total"] += 1
            except json.JSONDecodeError:
                continue

    def save_results(self) -> str:
        """Save results to JSON file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = self.target.replace(".", "_").replace("/", "_")
        filename = OUTPUT_DIR / f"scan_{safe_target}_{timestamp}.json"

        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)

        print(f"[TANA AI] Results saved to {filename}")
        return str(filename)

    def summary(self) -> str:
        """Return a human-readable summary."""
        if self.results["error"]:
            return f"[TANA AI] Scan failed: {self.results['error']}"

        lines = [
            f"\n{'='*60}",
            f"  TANA AI - Vulnerability Scan Report",
            f"{'='*60}",
            f"  Target:   {self.target}",
            f"  Time:     {self.results['timestamp']}",
            f"  Findings: {self.results['total']}",
            f"{'-'*60}",
            f"  Critical: {self.results['critical']}",
            f"  High:     {self.results['high']}",
            f"  Medium:   {self.results['medium']}",
            f"  Low:      {self.results['low']}",
            f"{'='*60}",
        ]

        for f in self.results["findings"][:10]:
            lines.append(
                f"  [{f['severity'].upper():<8}] {f['name']}"
            )
            lines.append(f"           {f['matched']}")

        lines.append(f"{'='*60}\n")
        return "\n".join(lines)


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"

    agent = ScanAgent(target)
    agent.run_nuclei()

    print(agent.summary())
    agent.save_results()
