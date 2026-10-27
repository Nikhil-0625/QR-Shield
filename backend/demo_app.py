"""Production entry point for the restricted, offline college demonstration."""
import os
import re
from pathlib import Path
from starlette.applications import Starlette
from starlette.responses import FileResponse, RedirectResponse, JSONResponse, HTMLResponse
from starlette.routing import Mount, Route
from demo_runtime import restricted_demo
from demo_security import DemoBoundary, settings

FRONTEND = Path(__file__).resolve().parents[1] / "frontend"
ASSETS = {"login.html", "scan.html", "dashboard.html", "generate.html", "navigation.css", "navigation.js",
          "theme.css", "theme.js", "link-warning.js", "qrcode-generator.js",
          "generator.css", "qr-renderer.js", "jsqr.js", "generator-handoff.js",
          "website-checker.html", "website-checker.css", "website-checker.js"}


def create_app():
    if not restricted_demo():
        raise RuntimeError("demo_app requires QR_SHIELD_MODE=restricted-demo")
    origin, _, _, _, _ = settings()
    if len(os.environ.get("JWT_SECRET_KEY", "").encode()) < 32:
        raise RuntimeError("Configure a strong JWT_SECRET_KEY before starting the demo")
    if os.environ.get("CORS_ALLOWED_ORIGINS", origin) != origin:
        raise RuntimeError("Restricted demo CORS must match PUBLIC_ORIGIN")
    os.environ["CORS_ALLOWED_ORIGINS"] = origin
    from main import app as api

    async def root(request):
        return RedirectResponse("/login.html", status_code=303)

    async def asset(request):
        name = request.path_params["asset"]
        path = FRONTEND / name
        if name not in ASSETS or path.is_symlink() or not path.is_file():
            return JSONResponse({"detail":"Not found"},status_code=404)
        if name.endswith(".html"):
            source = path.read_text(encoding="utf-8")
            if name in {"login.html", "scan.html", "dashboard.html", "website-checker.html"}:
                source = source.replace("<head>", '<head><script>window.QR_SHIELD_API_BASE="/api";</script>', 1)
            if name == "scan.html":
                notice = '<aside class="upi-identity-notice" role="note"><strong>Restricted offline college demo</strong><span>Live DNS, redirects, TLS and WHOIS checks are disabled. QR decoding, offline URL indicators and the existing uncalibrated ML estimate remain active. This is not a live destination-safety verification.</span></aside>'
                source = re.sub(r"(<main[^>]*>)", lambda match: match[0] + notice, source, count=1)
            return HTMLResponse(source)
        return FileResponse(path)

    app = Starlette(routes=[Mount("/api",app=api),Route("/",root),Route("/{asset:path}",asset)])
    return DemoBoundary(app)
