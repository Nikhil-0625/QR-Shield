"""Rendered dashboard with real isolated ASGI endpoints, synthetic memory DB only."""
import ast
import base64
from datetime import datetime, timedelta, timezone
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
from urllib.parse import urlsplit
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"backend"))
import test_history_authorization as harness
import test_api_security as api_harness


def main():
    tree=ast.parse((ROOT/".design-review/cdp_review.py").read_text(encoding="utf-8"))
    node=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=="CDP")
    namespace=dict(globals());exec(compile(ast.Module(body=[node],type_ignores=[]),"<CDP>","exec"),namespace)
    CDP=namespace["CDP"]
    with patch("dotenv.load_dotenv",return_value=False):
        harness.HistoryAuthorizationTests.setUpClass()
    class Fixture(harness.HistoryAuthorizationTests):
        api=api_harness.ApiSecurityTests.api
    fixture=Fixture();fixture.setUp()
    token=fixture.token("a@example.test")
    with fixture.database.SessionLocal() as db:
        db.query(fixture.database.ScanRecord).filter_by(user_id=1).delete()
        db.add_all([fixture.database.ScanRecord(user_id=1,decoded_content="https://example.test/"+str(i) if i<100 else "upi://pay?pa=synthetic@upi",
            risk_label="safe" if i<40 else "suspicious" if i<80 else "unsafe",risk_score=i%100,
            risk_breakdown=json.dumps([{"name":"<img src=x onerror=alert(1)>"}]) if i==1 else "[]",
            scanned_at=datetime.now(timezone.utc).replace(tzinfo=None)-timedelta(minutes=i)) for i in range(120)])
        db.commit()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_): pass
        def do_GET(self):
            parsed=urlsplit(self.path)
            if parsed.path.startswith("/api/"):
                if self.server.fail_summary and parsed.path=="/api/history/summary":
                    status,body=413,b'{"detail":"Synthetic limit"}'
                elif self.server.fail_page and parsed.path=="/api/history/page":
                    status,body=503,b'{"detail":"Synthetic pending"}'
                else:
                    value=self.headers.get("Authorization","")
                    status,body,_=fixture.api(parsed.path[4:],token=value[7:] if value.startswith("Bearer ") else None,query=parsed.query)
                content_type="application/json"
            else:
                name=parsed.path.lstrip("/")
                if name not in {"dashboard.html","theme.css","theme.js","navigation.css","navigation.js"}:
                    self.send_error(404);return
                body=(ROOT/"frontend"/name).read_bytes()
                if name=="dashboard.html":
                    body=body.replace(b"<head>",('<head><script>localStorage.setItem("access_token",'+json.dumps(token)+');window.QR_SHIELD_API_BASE="/api";</script>').encode(),1)
                status=200
                content_type="text/html" if name.endswith("html") else "text/css" if name.endswith("css") else "text/javascript"
            self.send_response(status);self.send_header("Content-Type",content_type+"; charset=utf-8");self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)

    server=ThreadingHTTPServer(("127.0.0.1",0),Handler);server.fail_page=server.fail_summary=False
    threading.Thread(target=server.serve_forever,daemon=True).start()
    with tempfile.TemporaryDirectory(prefix="qrshield-phase-e-") as temporary:
        process=subprocess.Popen([r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe","--headless=new","--disable-gpu","--no-first-run","--disable-background-networking","--remote-debugging-port=0","--user-data-dir="+temporary,"about:blank"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            port_file=Path(temporary)/"DevToolsActivePort"
            for _ in range(80):
                if port_file.exists():break
                time.sleep(.1)
            tabs=json.load(urllib.request.urlopen("http://127.0.0.1:"+port_file.read_text().splitlines()[0]+"/json"))
            client=CDP(next(t["webSocketDebuggerUrl"] for t in tabs if t["type"]=="page"))
            client.call("Page.enable");client.call("Network.enable")
            client.call("Network.setBlockedURLs",{"urls":["https://*","http://127.0.0.1:8000/*","http://127.0.0.1:8766/*"]})
            def wait(expression):
                for _ in range(100):
                    if client.eval(expression):return
                    time.sleep(.05)
                raise AssertionError("Dashboard state did not settle: "+expression)
            def navigate():
                client.call("Page.navigate",{"url":"http://127.0.0.1:"+str(server.server_port)+"/dashboard.html"})
                wait("document.readyState==='complete'&&Boolean(document.getElementById('history-page-status'))")
            legacy_bytes=len(fixture.api('/history',token=token)[1])
            summary_bytes=len(fixture.api('/history/summary',token=token)[1])
            page_bytes=len(fixture.api('/history/page',token=token)[1])
            report={"rendered_cases":0,"screenshots":[],"timezones":["Asia/Kolkata","America/Los_Angeles"],
                    "synthetic_120_record_payload_bytes":{"legacy":legacy_bytes,"summary":summary_bytes,"first_page":page_bytes}}
            navigate();wait("!historyBusy&&document.getElementById('history-page-status').innerText.includes('Page 1')")
            for theme,zone in [("light","Asia/Kolkata"),("dark","America/Los_Angeles")]:
                client.call("Emulation.setTimezoneOverride",{"timezoneId":zone})
                for width in (320,390,768,1280,1440):
                    client.eval('localStorage.setItem("qr-shield-theme",'+json.dumps(theme)+')')
                    client.call("Emulation.setDeviceMetricsOverride",{"width":width,"height":1000,"deviceScaleFactor":1,"mobile":width<768})
                    navigate();wait("!historyBusy&&document.getElementById('history-page-status').innerText.includes('Page 1')")
                    assert client.eval("document.querySelectorAll('#history-body tr').length===50&&document.documentElement.scrollWidth<=innerWidth&&document.documentElement.dataset.theme==="+json.dumps(theme)),"Overflow or page size"
                    assert client.eval("document.querySelector('#summary-grid .stat-value').textContent==='120'&&!document.querySelector('#indicator-summary img')"),"Total or escaping"
                    assert client.eval("parseScanTime('2026-01-01 00:15:00').toISOString()==='2026-01-01T00:15:00.000Z'&&getDayLabel(new Date('2026-01-01T00:15:00Z'))==='Thu'"),"Browser timezone altered UTC dates"
                    client.eval("window.__firstPage=currentHistory.map(row=>row.id).join(',');nextPage.click()")
                    wait("!historyBusy&&document.getElementById('history-page-status').innerText.includes('Page 2')")
                    assert client.eval("currentHistory.length===50&&currentHistory.map(row=>row.id).join(',')!==window.__firstPage"),"Next page failed"
                    client.eval("previousPage.click()")
                    wait("!historyBusy&&document.getElementById('history-page-status').innerText.includes('Page 1')")
                    assert client.eval("currentHistory.map(row=>row.id).join(',')===window.__firstPage"),"Previous page failed"
                    client.eval("document.querySelector('[data-filter=safe]').click()")
                    wait("!historyBusy&&currentHistory.length===40")
                    assert client.eval("nextPage.disabled&&document.querySelector('#summary-grid .stat-value').textContent==='120'"),"Filter changed full totals"
                    if width in (390,1280):
                        filename="phase-e-dashboard-"+theme+"-"+str(width)+"-"+str(time.time_ns())+".png"
                        client.eval("window.scrollTo(0,0)")
                        shot=client.call("Page.captureScreenshot",{"format":"png","captureBeyondViewport":False})["data"]
                        (ROOT/".design-review"/filename).write_bytes(base64.b64decode(shot));report["screenshots"].append(filename)
                        client.eval("document.getElementById('history-next').scrollIntoView({block:'end'})")
                        filename="phase-e-dashboard-history-"+theme+"-"+str(width)+"-"+str(time.time_ns())+".png"
                        shot=client.call("Page.captureScreenshot",{"format":"png","captureBeyondViewport":False})["data"]
                        (ROOT/".design-review"/filename).write_bytes(base64.b64decode(shot));report["screenshots"].append(filename)
                    report["rendered_cases"]+=1
            server.fail_page=True;navigate();wait("document.getElementById('history-page-status').innerText.includes('Could not load')")
            assert client.eval("document.querySelector('#history-body').innerText.includes('unavailable')&&document.querySelector('#summary-grid .stat-value').textContent==='120'"),"Page error hides data or looks empty"
            server.fail_page=False;server.fail_summary=True;navigate();wait("document.getElementById('dashboard-status').innerText.includes('No partial totals')")
            server.fail_summary=False
            with fixture.database.SessionLocal() as db:
                db.query(fixture.database.ScanRecord).filter_by(user_id=1).delete();db.commit()
            navigate();wait("!historyBusy&&document.getElementById('history-page-status').innerText.includes('Page 1')")
            assert client.eval("document.querySelector('#summary-grid .stat-value').textContent==='0'&&document.querySelector('#history-body').innerText.includes('No scans yet')&&nextPage.disabled"),"Empty state incorrect"
            report["error_and_empty_checks"]=3
            print(json.dumps(report))
        finally:
            process.terminate();process.wait(timeout=15);server.shutdown();server.server_close();fixture.engine.dispose()


if __name__=="__main__":main()
