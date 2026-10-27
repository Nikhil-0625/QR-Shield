"""Offline headless Edge tests of Phase B production functions; temporary files only."""
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    sources = {"LOGIN_SOURCE": ROOT / "frontend/login.html", "SCAN_SOURCE": ROOT / "frontend/scan.html",
               "PERF_SOURCE": ROOT / "tools/login-performance-diagnostics.js"}
    script = "\n".join("globalThis." + name + "=" + json.dumps(path.read_text(encoding="utf-8")) + ";" for name, path in sources.items())
    script += (ROOT / "frontend/tests/phase-b.test.js").read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="qrshield-phase-b-") as temporary:
        folder = Path(temporary)
        page = folder / "checks.html"
        page.write_text('<html><body><script>' + script.replace('</', '<\\/') + '</script></body></html>', encoding="utf-8")
        result = subprocess.run([
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            "--headless=new", "--disable-gpu", "--no-first-run", "--disable-background-networking",
            "--disable-sync", "--disable-extensions", "--disable-component-update",
            "--host-resolver-rules=MAP * ~NOTFOUND", "--proxy-server=http://127.0.0.1:9",
            "--user-data-dir=" + str(folder / "profile"), "--virtual-time-budget=3000", "--dump-dom", page.as_uri()
        ], capture_output=True, text=True, timeout=45)
        match = re.search(r'data-phase-b-checks="(\d+)"', result.stdout)
        if result.returncode or not match:
            stage = re.findall(r'data-phase-b-last-check="([^"]*)"', result.stdout)
            raise RuntimeError("Phase B browser checks failed at " + str(stage) + "; no submitted values logged")
        print(f"{match[1]} Phase B synthetic browser checks passed (no backend/clipboard/network access)")


if __name__ == "__main__":
    main()
