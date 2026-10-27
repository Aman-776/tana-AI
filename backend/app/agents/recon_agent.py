"""
TANA AI - Recon Agent
Discovers open ports and services on a target.
"""

import subprocess
import json
import re
from datetime import datetime
from pathlib import Path
from backend.app.core.config import OUTPUT_DIR, SCAN_TIMEOUT


class ReconAgent:
    """
    Reconnaissance Agent
    Uses Nmap to discover live hosts, open ports, and running services.
    """

    def __init__(self, target: str):
        self.target = target
        self.results = {
            "agent": "ReconAgent",
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "ports": [],
            "services": [],
            "raw_output": "",
            "success": False,
            "error": None
        }

    def run_nmap(self) -> dict:
        """Run Nmap service detection scan."""
        print(f"[TANA AI] Starting reconnaissance on {self.target}...")

        try:
            command = [
                "nmap",
                "-sV",           # Service/version detection
                "-T4",           # Aggressive timing
                "--open",        # Show only open ports
                self.target
            ]

            print(f"[TANA AI] Running: {' '.join(command)}")

            output = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT
            )

            self.results["raw_output"] = output.stdout
            self.results["success"] = output.returncode == 0

            # Parse the output
            self._parse_nmap_output(output.stdout)

            return self.results

        except subprocess.TimeoutExpired:
            self.results["error"] = "Scan timed out"
            print("[TANA AI] Scan timed out")
            return self.results
        except FileNotFoundError:
            self.results["error"] = "Nmap is not installed"
            print("[TANA AI] ERROR: Nmap is not installed")
            return self.results
        except Exception as e:
            self.results["error"] = str(e)
            print(f"[TANA AI] ERROR: {e}")
            return self.results

    def _parse_nmap_output(self, output: str):
        """Parse Nmap output to extract ports and services."""
        # Example line: 22/tcp   open  ssh     OpenSSH 8.2p1
        pattern = r"(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)"

        for line in output.split("\n"):
            match = re.search(pattern, line)
            if match:
                port = int(match.group(1))
                protocol = match.group(2)
                service = match.group(3)
                version = match.group(4).strip()

                self.results["ports"].append(port)
                self.results["services"].append({
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                    "version": version
                })

    def save_results(self) -> str:
        """Save results to JSON file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = self.target.replace(".", "_").replace("/", "_")
        filename = OUTPUT_DIR / f"recon_{safe_target}_{timestamp}.json"

        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)

        print(f"[TANA AI] Results saved to {filename}")
        return str(filename)

    def summary(self) -> str:
        """Return a human-readable summary."""
        if not self.results["success"]:
            return f"[TANA AI] Recon failed: {self.results['error']}"

        lines = [
            f"\n{'='*60}",
            f"  TANA AI - Reconnaissance Report",
            f"{'='*60}",
            f"  Target: {self.target}",
            f"  Time:   {self.results['timestamp']}",
            f"  Ports:  {len(self.results['ports'])} open",
            f"{'='*60}",
        ]

        for svc in self.results["services"]:
            lines.append(
                f"  {svc['port']:>5}/{svc['protocol']:<5} "
                f"{svc['service']:<15} {svc['version']}"
            )

        lines.append(f"{'='*60}\n")
        return "\n".join(lines)


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"

    agent = ReconAgent(target)
    agent.run_nmap()

    print(agent.summary())
    agent.save_results()
