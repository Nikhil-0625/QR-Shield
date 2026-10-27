"""Run production frontend privacy functions offline with synthetic dependencies."""
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    script = "\n".join("globalThis." + name + "=" + json.dumps((ROOT / path).read_text(encoding="utf-8")) + ";"
                       for name, path in [("SCAN_SOURCE", "frontend/scan.html"),
                                          ("DASHBOARD_SOURCE", "frontend/dashboard.html")])
    script += (ROOT / "frontend/tests/history-privacy.test.js").read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="qrshield-privacy-") as temporary:
        folder = Path(temporary)
        page = folder / "checks.html"
        page.write_text('<html><body><script>' + script.replace('</', '<\\/') + '</script></body></html>', encoding="utf-8")
        result = subprocess.run([
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "--headless=new", "--disable-gpu",
            "--no-first-run", "--disable-background-networking", "--disable-sync", "--disable-extensions",
            "--host-resolver-rules=MAP * ~NOTFOUND", "--proxy-server=http://127.0.0.1:9",
            "--user-data-dir=" + str(folder / "profile"), "--virtual-time-budget=3000", "--dump-dom", page.as_uri()
        ], capture_output=True, text=True, timeout=45)
        match = re.search(r'data-privacy-checks="(\d+)"', result.stdout)
        if result.returncode or not match:
            raise RuntimeError("Privacy checks failed: " + str(re.findall(r'data-privacy-(?:error|last-check)="([^"]*)"', result.stdout)))
        print(match[1] + " synthetic frontend privacy checks passed")


if __name__ == "__main__":
    main()
