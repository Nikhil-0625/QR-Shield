"""Offline Edge runner for synthetic result explanations; no backend or database."""
import json
from pathlib import Path
import re
import subprocess
import tempfile
import ast
import sys
from decimal import Decimal, InvalidOperation
from urllib.parse import urlparse, parse_qsl

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / "backend"))
from upi_security import analyze_upi, upi_intent_banner
# Execute only the pure parser definition, never import FastAPI, models or databases.
tree = ast.parse((root / "backend/main.py").read_text(encoding="utf-8"))
parser = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "parse_upi_payment_uri")
namespace = dict(urlparse=urlparse, parse_qsl=parse_qsl, Decimal=Decimal, InvalidOperation=InvalidOperation, re=re)
exec(compile(ast.Module(body=[parser], type_ignores=[]), "<pure UPI parser>", "exec"), namespace)
fixtures = json.loads((root / "frontend/tests/upi-intent-fixtures.json").read_text(encoding="utf-8"))
for fixture in fixtures:
    fixture["details"] = namespace["parse_upi_payment_uri"](fixture["uri"])
    fixture["analysis"] = analyze_upi(fixture["uri"])
    fixture["backend"] = upi_intent_banner(fixture["details"], fixture["analysis"])
source = (root / "frontend/scan.html").read_text(encoding="utf-8")
tests = (root / "frontend/tests/result-explanations.test.js").read_text(encoding="utf-8")
script = "globalThis.UPI_INTENT_FIXTURES=" + json.dumps(fixtures).replace("</", "<\\/") + ";globalThis.SCAN_SOURCE=" + json.dumps(source).replace("</", "<\\/") + ";try {" + tests + "} catch (error) { document.documentElement.setAttribute('data-test-error', error.stack); }"
with tempfile.TemporaryDirectory(prefix="qrshield-result-tests-") as temporary:
    folder = Path(temporary)
    page = folder / "test.html"
    page.write_text('<html><body><script>' + script + '</script></body></html>', encoding="utf-8")
    result = subprocess.run([
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        "--headless=new", "--disable-gpu", "--no-first-run", "--disable-background-networking",
        "--disable-sync", "--disable-extensions", "--disable-component-update",
        "--host-resolver-rules=MAP * ~NOTFOUND", "--proxy-server=http://127.0.0.1:9",
        "--user-data-dir=" + str(folder / "profile"), "--dump-dom", page.as_uri()
    ], capture_output=True, text=True, timeout=45)
    match = re.search(r'data-result-checks="(\d+)"', result.stdout)
    if result.returncode or not match:
        raise RuntimeError("Result explanation browser checks failed: " + str(re.findall(r'data-test-error="([^\"]*)"', result.stdout)))
    print(f"{match[1]} synthetic DOM result explanation checks passed in Edge")
