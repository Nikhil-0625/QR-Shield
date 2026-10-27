"""Real rendered controls with local fixtures only; no accounts or physical clipboard."""
import ast
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
FRONT = ROOT / "frontend"
sys.path.insert(0, str(ROOT / "backend"))
from upi_security import analyze_upi  # Pure offline helper; no app/database import.


def main():
    # Reuse only the existing CDP transport class, not fixture-generating scripts.
    tree = ast.parse((ROOT / ".design-review/cdp_review.py").read_text(encoding="utf-8"))
    transport = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "CDP")
    namespace = dict(globals())
    exec(compile(ast.Module(body=[transport], type_ignores=[]), "<CDP transport>", "exec"), namespace)
    CDP = namespace["CDP"]
    assets = {"login.html", "scan.html", "theme.js", "theme.css", "navigation.js", "navigation.css", "link-warning.js"}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            name = self.path.split("?",1)[0].lstrip("/")
            if name not in assets:
                self.send_error(404)
                return
            body = (FRONT / name).read_bytes()
            if name == "scan.html":
                body = body.replace(b"<head>", b'<head><script>localStorage.setItem("access_token","synthetic-ui-only");window.fetch=async()=>({ok:true,status:200,json:async()=>({}),blob:async()=>new Blob(["synthetic"])});</script>', 1)
            content_type = "text/html" if name.endswith("html") else "text/css" if name.endswith("css") else "text/javascript"
            self.send_response(200)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory(prefix="qrshield-phase-b-rendered-") as temporary:
        process = subprocess.Popen([
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "--headless=new", "--disable-gpu",
            "--no-first-run", "--disable-background-networking", "--remote-debugging-port=0",
            "--user-data-dir=" + temporary, "about:blank"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            port_file = Path(temporary) / "DevToolsActivePort"
            for _ in range(80):
                if port_file.exists(): break
                time.sleep(.1)
            debug_port = port_file.read_text().splitlines()[0]
            tabs = json.load(urllib.request.urlopen("http://127.0.0.1:" + debug_port + "/json"))
            client = CDP(next(tab["webSocketDebuggerUrl"] for tab in tabs if tab["type"] == "page"))
            client.call("Page.enable")
            client.call("Network.enable")
            client.call("Network.setBlockedURLs", {"urls": ["https://*", "http://127.0.0.1:8000/*", "http://127.0.0.1:8766/*"]})
            base = "http://127.0.0.1:" + str(server.server_port)
            def navigate(page):
                client.call("Page.navigate", {"url": base + "/" + page})
                for _ in range(80):
                    if client.eval("document.readyState==='complete'"): break
                    time.sleep(.05)
                time.sleep(.15)
            report = {"rendered_cases":0, "upi_rendered_cases":0, "upi_screenshots":[], "themes":["light","dark"], "widths":[320,390,768,1280,1440]}
            data = {"decoded_content":"  https://example.test/path?x=1&y=2\nexact content  ",
                    "final_url":"https://example.test/path", "domain":"example.test", "registered_domain":"example.test",
                    "risk_label":"suspicious", "risk_score":56, "rule_score":55, "ml_phishing_probability":57.54,
                    "final_url_verified":False, "redirect_check_status":"not_performed", "redirect_chain":["https://example.test/path"],
                    "risk_breakdown":[], "tampering_reasons":[], "tampering_score":0, "scan_id":42}
            for theme in report["themes"]:
                for width in report["widths"]:
                    client.call("Emulation.setDeviceMetricsOverride", {"width":width,"height":1000,"deviceScaleFactor":1,"mobile":width<768})
                    navigate("login.html")
                    client.eval('localStorage.setItem("qr-shield-theme",'+json.dumps(theme)+')')
                    navigate("scan.html")
                    assert client.eval("typeof showResults==='function'"), "Scanner fixture did not load"
                    client.eval("showResults("+json.dumps(data)+")")
                    client.eval("setResultView('technical')")
                    assert client.eval("document.getElementById('result-rows').innerText.includes('Recorded destination (unverified)')&&document.getElementById('result-rows').innerText.includes('Not checked')&&document.documentElement.scrollWidth<=innerWidth"), "Unavailable-check presentation failed"
                    client.eval("setResultView('simple')")
                    state = client.eval("(()=>{const b=document.getElementById('copy-content-btn'),r=b.getBoundingClientRect();return {overflow:document.documentElement.scrollWidth>innerWidth,width:r.width,height:r.height,left:r.left,right:r.right,disabled:b.disabled,theme:document.documentElement.dataset.theme};})()")
                    assert state and not state["overflow"] and not state["disabled"] and state["height"]>=44 and state["left"]>=0 and state["right"]<=width and state["theme"]==theme, state
                    assert client.eval("(async()=>{Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>{window.__copied=text}}});document.getElementById('copy-content-btn').click();await Promise.resolve();return window.__copied==="+json.dumps(data["decoded_content"])+"&&document.getElementById('copy-content-status').textContent==='QR content copied.'})()"), "Rendered copy failed"
                    assert client.eval("document.getElementById('open-link-btn').click();document.getElementById('link-warning-dialog').open"), "Warning dialog lost"
                    client.eval("document.getElementById('link-warning-cancel').click()")
                    assert client.eval("(async()=>{navigator.clipboard.writeText=async()=>{throw new Error('synthetic denial')};await copyQrContent();const f=document.getElementById('copy-content-fallback');return !f.hidden&&f.readOnly&&f.value==="+json.dumps(data["decoded_content"])+"&&document.activeElement===f&&document.documentElement.scrollWidth<=innerWidth})()"), "Rendered fallback failed"
                    if width==390:
                        screenshot=client.call("Page.captureScreenshot",{"format":"png","captureBeyondViewport":False})["data"]
                        filename="phase-b-copy-"+theme+"-"+str(time.time_ns())+".png"
                        (ROOT/".design-review"/filename).write_bytes(base64.b64decode(screenshot))
                    client.eval("resetScan()")
                    assert client.eval("document.getElementById('copy-content-btn').disabled&&document.getElementById('copy-content-fallback').value===''")
                    report["rendered_cases"]+=1
                    for payload in [
                        "upi://pay?pa=merchant@upi&pn=Synthetic%20Store&am=250.00&cu=INR&tn=Lunch&tr=DEMO",
                        "upi://pay?pa=merchant@upi&pa=other@upi&am=10.001&cu=INR&tn=Pay%20to%20receive%20refund",
                        "upi://other?pa=%3Cimg%20src=x%20onerror=alert(1)%3E&tn=" + "long" * 300,
                    ]:
                        analysis = analyze_upi(payload)
                        fixture = {"decoded_content":payload, "upi_analysis":analysis,
                                   "tampering_score":0,"tampering_reasons":[],"scan_id":42}
                        client.eval("showResults("+json.dumps(fixture)+")")
                        assert client.eval("document.documentElement.scrollWidth<=innerWidth&&getComputedStyle(document.querySelector('.upi-security-summary')).display!=='none'"), "UPI simple view hidden or overflowing"
                        assert client.eval("document.querySelector('.upi-security-summary').innerText.includes('not independently verified')&&!document.querySelector('.upi-security-summary img')"), "UPI identity/escaping failed"
                        if "refund" in payload:
                            assert client.eval("document.querySelector('.upi-security-summary').innerText.includes('authorizing a payment is not required')&&document.querySelector('.upi-security-summary').innerText.includes('10.001')"), "Warnings or exact amount lost"
                            if width in (390,1280):
                                for part, selector in [("details", ".upi-security-summary"), ("notes", ".upi-security-notes")]:
                                    client.eval("document.querySelector("+json.dumps(selector)+").scrollIntoView({block:'start'})")
                                    filename="phase-d-upi-"+theme+"-"+str(width)+"-"+part+"-"+str(time.time_ns())+".png"
                                    shot=client.call("Page.captureScreenshot",{"format":"png","captureBeyondViewport":False})["data"]
                                    (ROOT/".design-review"/filename).write_bytes(base64.b64decode(shot))
                                    report["upi_screenshots"].append(filename)
                        client.eval("setResultView('technical')")
                        assert client.eval("document.documentElement.scrollWidth<=innerWidth&&getComputedStyle(document.querySelector('.upi-security-summary')).display!=='none'"), "Technical view lost UPI analysis"
                        assert client.eval("document.getElementById('open-link-btn').hidden||document.getElementById('open-link-btn').disabled"), "UPI must not launch a payment link"
                        client.eval("resetScan()")
                        report["upi_rendered_cases"]+=1
            navigate("login.html")
            diagnostic=(ROOT/"tools/login-performance-diagnostics.js").read_text(encoding="utf-8")
            metrics=client.eval(diagnostic)
            assert metrics and metrics["navigation"] and len(metrics["resources"])>=2
            report["local_fixture_diagnostic"]=metrics
            print(json.dumps(report))
        finally:
            process.terminate()
            process.wait(timeout=15)
            server.shutdown()
            server.server_close()


if __name__ == "__main__": main()
