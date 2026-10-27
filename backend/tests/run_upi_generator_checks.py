"""Real generator DOM/PNG + isolated scanner; no production records or payments."""
import ast
import asyncio
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
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
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
FRONT = ROOT / "frontend"


def verify_png_and_scanner(image_url, uri):
    from PIL import Image
    from fastapi import UploadFile
    sys.path.insert(0, str(ROOT / "backend"))
    sys.path.insert(0, str(ROOT / "backend/tests"))
    import test_history_authorization as harness
    data = base64.b64decode(image_url.split(",", 1)[1], validate=True)
    image = Image.open(io.BytesIO(data)).convert("RGB")
    width, height = image.size
    assert width == height and width > 200
    assert {color for _, color in (image.getcolors(3) or [])} == {(0, 0, 0), (255, 255, 255)}, "QR contrast changed"
    for box in [(0,0,width,32),(0,height-32,width,height),(0,0,32,height),(width-32,0,width,height)]:
        assert image.crop(box).getextrema() == ((255,255),)*3, "Four-module quiet zone changed"
    with patch("dotenv.load_dotenv", return_value=False):
        harness.HistoryAuthorizationTests.setUpClass()
    fixture = harness.HistoryAuthorizationTests()
    try:
        fixture.setUp()
        with patch.object(fixture.main.requests, "get", side_effect=AssertionError("HTTP forbidden")), \
             patch.object(fixture.main.socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
             patch.object(fixture.main.whois, "whois", side_effect=AssertionError("WHOIS forbidden")):
            result = asyncio.run(fixture.main.scan_qr(
                file=UploadFile(filename="synthetic-generated.png", file=io.BytesIO(data)),
                current_user="a@example.test", expected_vpa=None))
        assert result["decoded_content"] == uri, "Real scanner decode differs from generated URI"
        analysis = result["upi_analysis"]
        assert analysis["payment_direction"] == "send_money"
        assert analysis["fields"]["payee_vpa"]["value"] == "refund-demo@upi"
        assert analysis["fields"]["amount"]["value"] == "99.00"
        assert analysis["fields"]["currency"]["value"] == "INR"
        assert analysis["fields"]["transaction_note"]["value"] == "Pay to receive refund"
        assert {"refund_language", "pay_to_receive"} <= {item["code"] for item in analysis["warnings"]}
        assert "risk_score" not in result
        return result
    finally:
        harness.HistoryAuthorizationTests.tearDownClass()


def verify_customized_exports(fixtures):
    """Execute only the real decoder function; never import the live app/database."""
    import cv2
    import numpy as np
    from pyzbar.pyzbar import decode
    tree = ast.parse((ROOT / "backend/main.py").read_text(encoding="utf-8-sig"))
    decoder = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "decode_qr")
    namespace = {"decode": decode, "cv2": cv2}
    exec(compile(ast.Module(body=[decoder], type_ignores=[]), "<isolated production QR decoder>", "exec"), namespace)
    count = 0
    assert len(fixtures) >= 20, "Customization fixtures unexpectedly missing"
    for fixture in fixtures:
        for key in ("png", "svg_png"):
            data = base64.b64decode(fixture[key].split(",", 1)[1], validate=True)
            image = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
            assert image is not None and image.shape[0] == image.shape[1] and image.shape[0] in (512, 1024), fixture["name"] + " export size"
            assert namespace["decode_qr"](image) == fixture["payload"], fixture["name"] + " " + key + " did not round-trip through the production decoder"
            count += 1
    return count


def main():
    tree = ast.parse((ROOT / ".design-review/cdp_review.py").read_text(encoding="utf-8"))
    transport = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "CDP")
    namespace = dict(globals())
    exec(compile(ast.Module(body=[transport], type_ignores=[]), "<CDP transport>", "exec"), namespace)
    CDP = namespace["CDP"]
    assets = {"generate.html","scan.html","theme.js","theme.css","navigation.js","navigation.css","qrcode-generator.js","link-warning.js",
              "generator.css","qr-renderer.js","jsqr.js","generator-handoff.js"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            name = self.path.split("?",1)[0].lstrip("/")
            if name not in assets:
                self.send_error(404)
                return
            body = (FRONT / name).read_bytes()
            if name.endswith("html"):
                body = body.replace(b"<head>", b'<head><script>localStorage.setItem("access_token","synthetic-only");window.__unexpectedRequests=[];window.__externalOpens=[];window.fetch=(...args)=>{window.__unexpectedRequests.push(args);throw new Error("No API requests in UI fixture")};window.open=(...args)=>{window.__externalOpens.push(args);throw new Error("No payment apps")};</script>',1)
            content_type = "text/html" if name.endswith("html") else "text/css" if name.endswith("css") else "text/javascript"
            self.send_response(200)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1",0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    with tempfile.TemporaryDirectory(prefix="qrshield-upi-generator-") as temporary:
        process = subprocess.Popen([
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "--headless=new", "--disable-gpu", "--no-first-run",
            "--disable-background-networking", "--remote-debugging-port=0", "--user-data-dir="+temporary,"about:blank"
        ],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            port_file = Path(temporary)/"DevToolsActivePort"
            for _ in range(80):
                if port_file.exists(): break
                time.sleep(.1)
            port = port_file.read_text().splitlines()[0]
            tabs = json.load(urllib.request.urlopen("http://127.0.0.1:"+port+"/json"))
            client = CDP(next(tab["webSocketDebuggerUrl"] for tab in tabs if tab["type"] == "page"))
            client.s.settimeout(120)
            client.call("Page.enable")
            client.call("Network.enable")
            client.call("Network.setBlockedURLs",{"urls":["https://*","http://127.0.0.1:8000/*","http://127.0.0.1:8766/*"]})
            def navigate(page):
                client.call("Page.navigate",{"url":"http://127.0.0.1:"+str(server.server_port)+"/"+page})
                for _ in range(80):
                    if client.eval("document.readyState==='complete'"): break
                    time.sleep(.05)
                time.sleep(.15)
            navigate("generate.html")
            script = (FRONT/"tests/upi-generator.test.js").read_text(encoding="utf-8")
            result = client.eval("(async()=>{try{return await ("+script+")}catch(e){return {error:e.stack}}})()")
            assert result and "error" not in result, result
            scan = verify_png_and_scanner(result["image"], result["uri"])
            customization_script = (FRONT/"tests/generator-customization.test.js").read_text(encoding="utf-8")
            customization = client.eval("(async()=>{try{return await ("+customization_script+")}catch(e){return {error:e.stack}}})()")
            assert customization and "error" not in customization, customization
            decoded_exports = verify_customized_exports(customization["fixtures"])
            handoff_source = (FRONT/"generator-handoff.js").read_text(encoding="utf-8")
            handoff_script = (FRONT/"tests/generator-handoff.test.js").read_text(encoding="utf-8")
            handoff_unit = client.eval("(async()=>{const HANDOFF_SOURCE="+json.dumps(handoff_source)+";try{return await ("+handoff_script+")}catch(e){return {error:e.stack}}})()")
            assert handoff_unit and "error" not in handoff_unit, handoff_unit
            assert handoff_unit["checks"] >= 196, "Handoff unit coverage unexpectedly missing"

            # Navigate for real with the finalized customized PNG; only the subsequent
            # authenticated /scan response is mocked. No live app or user data is used.
            navigate("generate.html")
            generated_handoff = client.eval("""(() => {
                selectType('upi');
                for (const [id,value] of Object.entries({'upi-id':'refund-demo@upi','payee-name':'Refund Support',
                    'upi-amount':'99.00','upi-note':'Pay to receive refund','qr-foreground':'#172033',
                    'qr-pattern':'rounded','qr-corners':'rounded','qr-frame':'label','qr-label':'Scan Me'})) {
                    document.getElementById(id).value=value;
                }
                generatePreview();
                return {png:currentRendered?.png,uri:currentPayload?.content,ready:!testQrButton.disabled,
                    requests:window.__unexpectedRequests.length,opens:window.__externalOpens.length};
            })()""")
            assert generated_handoff and generated_handoff["ready"] and generated_handoff["png"], "Customized handoff preview unavailable"
            assert generated_handoff["uri"] == result["uri"], "Handoff QR content changed"
            assert generated_handoff["requests"] == generated_handoff["opens"] == 0, "Generation contacted an API or opened content"
            client.eval("document.getElementById('test-qr-btn').click()")
            for _ in range(100):
                if client.eval("document.readyState==='complete'&&location.pathname==='/scan.html'&&typeof selectedFile!=='undefined'&&selectedFile instanceof File"):
                    break
                time.sleep(.05)
            handoff_ready = client.eval("""(async () => {
                if (typeof selectedFile==='undefined'||!(selectedFile instanceof File)) return {ready:false};
                const png=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result);reader.onerror=reject;reader.readAsDataURL(selectedFile);});
                return {ready:true,png,name:selectedFile.name,type:selectedFile.type,path:location.pathname,hash:location.hash,
                    stored:sessionStorage.getItem('qrshield.generated-image.v1'),privateScan:document.getElementById('private-scan').checked,
                    privacyEnabled:!document.getElementById('private-scan').disabled,scanEnabled:!scanBtn.disabled,
                    requests:window.__unexpectedRequests.length,opens:window.__externalOpens.length,status:statusMsg.textContent};
            })()""")
            assert handoff_ready and handoff_ready["ready"], "Test button did not prepare a scanner File"
            assert handoff_ready["path"] == "/scan.html" and handoff_ready["hash"] == "" and handoff_ready["stored"] is None, "Handoff navigation or one-use cleanup failed"
            assert handoff_ready["png"] == generated_handoff["png"], "Transferred PNG bytes changed"
            assert handoff_ready["name"] == "qr-shield-generated.png" and handoff_ready["type"] == "image/png", "Transferred file metadata changed"
            assert handoff_ready["requests"] == handoff_ready["opens"] == 0, "Handoff automatically scanned or opened content"
            assert handoff_ready["privateScan"] is False and handoff_ready["privacyEnabled"] and handoff_ready["scanEnabled"], "Handoff bypassed the existing privacy choice"
            assert "Choose Private scan if desired" in handoff_ready["status"], "Handoff privacy guidance missing"
            submission_checks = client.eval("""(async () => {
                let checks=0;
                const check=(condition,message)=>{if(!condition)throw new Error(message);checks++;};
                const fixture="""+json.dumps(scan)+""";
                const expectedPng="""+json.dumps(generated_handoff["png"])+""";
                window.__scanRequests=[];
                window.fetch=async (url,options)=>{
                    const file=options.body.get('file');
                    const png=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result);reader.onerror=reject;reader.readAsDataURL(file);});
                    window.__scanRequests.push({url,method:options.method,authorization:options.headers.Authorization,
                        privateScan:options.body.get('private_scan'),png,name:file.name,type:file.type});
                    return {ok:true,status:200,json:async()=>({...fixture,scan_id:options.body.get('private_scan')==='true'?null:fixture.scan_id})};
                };
                for (const privateScan of [true,false]) {
                    document.getElementById('private-scan').checked=privateScan;
                    updatePrivateScanNotice();
                    const before=window.__scanRequests.length;
                    const pending=scanImage();
                    await scanImage(); // Duplicate pending submission must remain guarded.
                    await pending;
                    check(window.__scanRequests.length===before+1,'One request per deliberate scan');
                    const request=window.__scanRequests.at(-1);
                    check(request.url===API_URL+SCAN_ENDPOINT&&request.method==='POST','Existing scan endpoint/method');
                    check(request.authorization==='Bearer synthetic-only','Existing JWT header preserved');
                    check(request.privateScan===String(privateScan),'Private scan flag preserved');
                    check(request.png===expectedPng&&request.name==='qr-shield-generated.png'&&request.type==='image/png','Actual generated PNG submitted unchanged');
                    check(document.getElementById('results-card').style.display==='block','Existing result renderer used');
                    check(!isAnalyzing&&!document.getElementById('private-scan').disabled,'Scan lifecycle restores controls');
                    check(document.getElementById('report-btn').disabled===privateScan,'Private scan PDF availability preserved');
                }
                check(window.__unexpectedRequests.length===0&&window.__externalOpens.length===0,'No external URLs or unexpected API requests');
                return {checks,requests:window.__scanRequests.length,privateFlags:window.__scanRequests.map(request=>request.privateScan)};
            })().catch(error=>({error:error.stack}))""")
            assert submission_checks and "error" not in submission_checks, submission_checks
            assert submission_checks["requests"] == 2 and submission_checks["privateFlags"] == ["true","false"], "Both privacy paths must be tested"
            report = {"browser_assertions":result["checks"],"real_png_scanner_roundtrip":True,
                      "customization_assertions":customization["checks"],"customized_exports_decoded":decoded_exports,
                      "mocked_download_requests":customization["downloadRequests"],
                      "handoff_unit_assertions":handoff_unit["checks"],"real_handoff_navigation":True,
                      "handoff_submission_assertions":submission_checks["checks"],"mocked_handoff_scan_requests":submission_checks["requests"],
                      "rendered_cases":0,"styled_preview_cases":0,"screenshots":[]}
            for theme in ("light","dark"):
                for width in (320,390,768,1280,1440):
                    client.call("Emulation.setDeviceMetricsOverride",{"width":width,"height":1000,"deviceScaleFactor":1,"mobile":width<768})
                    client.eval('localStorage.setItem("qr-shield-theme",'+json.dumps(theme)+')')
                    navigate("generate.html")
                    assert client.eval("qrResult.hidden&&downloadButton.disabled&&testQrButton.disabled&&getComputedStyle(document.querySelector('.tab svg')).padding==='0px'&&document.documentElement.scrollWidth<=innerWidth"), "Empty state or type icon sizing"
                    if width == 390:
                        client.eval("document.querySelector('.preview-card').scrollIntoView({block:'start'})")
                        filename="phase-d-generator-"+theme+"-390-empty-"+str(time.time_ns())+".png"
                        time.sleep(.3)  # Let the existing 240ms preview animation and compositor paint finish.
                        shot=client.call("Page.captureScreenshot",{"format":"png","captureBeyondViewport":False})["data"]
                        (ROOT/".design-review"/filename).write_bytes(base64.b64decode(shot))
                        report["screenshots"].append(filename)
                    client.eval("selectType('upi');document.getElementById('upi-id').value='refund-demo@upi';document.getElementById('payee-name').value='Refund Support';document.getElementById('upi-amount').value='99.00';document.getElementById('upi-note').value='Pay to receive refund';form.dispatchEvent(new Event('submit',{cancelable:true}))")
                    client.eval("qrImage.decode().then(()=>new Promise(resolve=>requestAnimationFrame(()=>resolve(true))))")
                    assert client.eval("!qrResult.hidden&&document.documentElement.scrollWidth<=innerWidth&&document.documentElement.dataset.theme==="+json.dumps(theme)), "Generator overflow/theme"
                    assert client.eval("!document.querySelector('.encoded-details').open"), "Encoded metadata must be collapsed initially"
                    client.eval("document.querySelector('.encoded-details').open=true")
                    assert client.eval("getComputedStyle(document.querySelector('.qr-image-frame')).backgroundColor==='rgb(255, 255, 255)'&&upiPreview.innerText.includes('99.00')"), "QR surface/details"
                    assert client.eval("document.documentElement.scrollWidth<=innerWidth"), "Expanded metadata overflow"
                    client.eval("document.querySelector('.encoded-details').open=false")
                    if width in (320,390,768,1280):
                        for part, selector in [("form","#panel-upi"),("preview","#qr-result")]:
                            client.eval("document.querySelector("+json.dumps(selector)+").scrollIntoView({block:'start'})")
                            filename="phase-d-generator-"+theme+"-"+str(width)+"-"+part+"-"+str(time.time_ns())+".png"
                            time.sleep(.3)  # Let the existing 240ms preview animation and compositor paint finish.
                            shot=client.call("Page.captureScreenshot",{"format":"png","captureBeyondViewport":False})["data"]
                            (ROOT/".design-review"/filename).write_bytes(base64.b64decode(shot))
                            report["screenshots"].append(filename)
                        if width == 390:
                            client.eval("document.querySelector('.encoded-details').open=true;document.querySelector('.encoded-details').scrollIntoView({block:'center'})")
                            filename="phase-d-generator-"+theme+"-390-metadata-"+str(time.time_ns())+".png"
                            time.sleep(.3)  # Let the existing 240ms preview animation and compositor paint finish.
                            shot=client.call("Page.captureScreenshot",{"format":"png","captureBeyondViewport":False})["data"]
                            (ROOT/".design-review"/filename).write_bytes(base64.b64decode(shot))
                            report["screenshots"].append(filename)
                            client.eval("document.querySelector('.encoded-details').open=false")
                    navigate("scan.html")
                    client.eval("showResults("+json.dumps(scan)+")")
                    assert client.eval("document.querySelector('.upi-security-summary').innerText.includes('Payment Request')&&document.querySelector('.upi-security-summary').innerText.includes('authorizing a payment is not required')&&document.documentElement.scrollWidth<=innerWidth"), "Generated QR scanner UI"
                    report["rendered_cases"]+=1
                    if width in (390,1280):
                        navigate("generate.html")
                        client.eval("""selectType('url');
                            for (const [id,value] of Object.entries({'website-url':'https://example.test/menu',
                                'qr-foreground':'#172033','qr-pattern':'dots','qr-corners':'rounded',
                                'qr-size':'1024','qr-frame':'label','qr-label':'custom','qr-custom-label':'Visit our menu'})) {
                                document.getElementById(id).value=value;
                            }
                            updateCustomizationState(); generatePreview();""")
                        client.eval("qrImage.decode().then(()=>new Promise(resolve=>requestAnimationFrame(()=>resolve(true))))")
                        assert client.eval("!qrResult.hidden&&!downloadButton.disabled&&currentRendered.width===1024&&currentRendered.svg.includes('Visit our menu')&&document.documentElement.scrollWidth<=innerWidth"), "Styled URL preview regression"
                        client.eval("document.querySelector('.preview-card').scrollIntoView({block:'start'})")
                        filename="phase-d-generator-"+theme+"-"+str(width)+"-styled-url-"+str(time.time_ns())+".png"
                        time.sleep(.3)  # Let the existing 240ms preview animation and compositor paint finish.
                        shot=client.call("Page.captureScreenshot",{"format":"png","captureBeyondViewport":False})["data"]
                        (ROOT/".design-review"/filename).write_bytes(base64.b64decode(shot))
                        report["screenshots"].append(filename)
                        report["styled_preview_cases"]+=1
            print(json.dumps(report))
        finally:
            process.terminate()
            process.wait(timeout=15)
            server.shutdown()
            server.server_close()


if __name__ == "__main__": main()
