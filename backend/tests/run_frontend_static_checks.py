"""Existing JS syntax, local navigation, and QR generation checks; no servers."""
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import subprocess
import tempfile


class ScriptsAndLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inline, self.links, self.current = [], [], None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script" and "src" not in attrs:
            self.current = []
        if tag == "a" and "href" in attrs:
            self.links.append(attrs["href"])

    def handle_data(self, data):
        if self.current is not None:
            self.current.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self.current is not None:
            self.inline.append("".join(self.current))
            self.current = None


def main():
    frontend = Path(__file__).resolve().parents[2] / "frontend"
    scripts, links = [], 0
    for page in frontend.glob("*.html"):
        parser = ScriptsAndLinks()
        parser.feed(page.read_text(encoding="utf-8-sig"))
        scripts.extend(parser.inline)
        for href in parser.links:
            if not href or href.startswith(("#", "http:", "https:", "mailto:")):
                continue
            target = frontend / href.split("?")[0].split("#")[0]
            if not target.is_file():
                raise RuntimeError("Missing local navigation target")
            links += 1
    scripts.extend(path.read_text(encoding="utf-8-sig") for path in frontend.glob("*.js"))
    checks = '''
let count=0; const check=value=>{if(!value)throw new Error('Synthetic frontend failure');count++;};
for(const source of SOURCES){new Function(source);count++;}
const toggle=document.querySelector('.qs-menu-toggle');const header=document.querySelector('.qs-header');
toggle.click(); check(toggle.getAttribute('aria-expanded')==='true');
document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape'}));check(toggle.getAttribute('aria-expanded')==='false');check(document.activeElement===toggle);
toggle.click();document.getElementById('outside').click();check(!header.classList.contains('is-open'));
toggle.click();document.querySelector('.qs-nav-links button').click();check(toggle.getAttribute('aria-expanded')==='false');
qrcode.stringToBytes=qrcode.stringToBytesFuncs['UTF-8'];
for(const text of ['Synthetic text','https://example.invalid/synthetic','upi://pay?pa=synthetic@upi&pn=Demo']){
 const qr=qrcode(0,'M');qr.addData(text);qr.make();check(qr.getModuleCount()>0);check(qr.createDataURL(3,4).startsWith('data:image/gif;base64,'));
}
document.documentElement.dataset.frontendChecks=String(count);
'''
    script = "const SOURCES=" + json.dumps(scripts).replace("</", "<\\/") + ";\n" + checks
    html = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline' 'unsafe-eval'; connect-src 'none'"></head><body><header class="qs-header"><button class="qs-menu-toggle" aria-expanded="false">Menu</button><nav class="qs-nav-links"><button>Navigation</button></nav></header><button id="outside">Outside</button>"""
    for filename in ("navigation.js", "qrcode-generator.js"):
        html += "<script>" + (frontend / filename).read_text(encoding="utf-8") + "</script>"
    html += "<script>" + script + "</script></body></html>"
    with tempfile.TemporaryDirectory(prefix="qrshield-static-ui-") as temporary:
        folder = Path(temporary)
        page = folder / "synthetic.html"
        page.write_text(html, encoding="utf-8")
        result = subprocess.run([
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            "--headless=new", "--disable-gpu", "--no-first-run", "--disable-background-networking",
            "--disable-sync", "--disable-extensions", "--disable-component-update",
            "--host-resolver-rules=MAP * ~NOTFOUND", "--proxy-server=http://127.0.0.1:9",
            "--user-data-dir=" + str(folder / "profile"), "--dump-dom", page.as_uri()
        ], capture_output=True, text=True, timeout=45)
        match = re.search(r'data-frontend-checks="(\d+)"', result.stdout)
        if result.returncode or not match:
            raise RuntimeError("Synthetic frontend checks failed")
        print(json.dumps({"javascript_scripts_compiled": len(scripts),
                          "local_navigation_links_checked": links,
                          "syntax_and_navigation_and_qr_checks": int(match[1])}))


if __name__ == "__main__":
    main()
