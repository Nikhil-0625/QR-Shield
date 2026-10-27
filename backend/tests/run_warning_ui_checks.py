"""Offline headless Edge checks using mocked fetch; never starts either server."""
import json
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parents[2]
    page = (root / "frontend/experimental-warning.html").read_text(encoding="utf-8")
    harness = (root / "frontend/tests/experimental-warning.test.js").read_text(encoding="utf-8")
    assert "localStorage" not in page and "sessionStorage" not in page
    assert "innerHTML" not in page and "window.open" not in page
    edge = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
    if not edge.is_file():
        raise RuntimeError("Existing Edge installation required; no packages installed")
    with tempfile.TemporaryDirectory(prefix="qrshield-mocked-ui-") as temporary:
        folder = Path(temporary)
        for width, height in ((1280, 1000), (390, 844), (320, 800)):
            test_page = folder / f"test-{width}.html"
            test_page.write_text(page.replace(
                "</body>", "<script>" + harness + "</script></body>"), encoding="utf-8")
            command = [str(edge), "--headless=new", "--disable-gpu", "--no-first-run",
                       "--disable-background-networking", "--disable-component-update",
                       "--disable-sync", "--disable-extensions", "--host-resolver-rules=MAP * ~NOTFOUND",
                       "--proxy-server=http://127.0.0.1:9", "--force-device-scale-factor=1",
                       "--user-data-dir=" + str(folder / f"profile-{width}"),
                       f"--window-size={width},{height}", "--virtual-time-budget=2000",
                       "--dump-dom", test_page.as_uri()]
            result = subprocess.run(command, capture_output=True, text=True, timeout=45)
            synthetic = re.search(r'data-checks="(\d+)"', result.stdout)
            prediction = re.search(r'data-prediction-tests="(\d+)"', result.stdout)
            if result.returncode or not synthetic or not prediction:
                print(json.dumps({"exit":result.returncode,"synthetic_markers":re.findall(r'data-(?:checks|prediction-tests|prediction-failure)="[^\"]*"',result.stdout)}))
                raise RuntimeError("Synthetic browser checks failed; no submitted values logged")
            print(json.dumps({"requested_width": width, "synthetic_checks": int(synthetic[1]),
                              "mocked_prediction_checks": int(prediction[1])}))


if __name__ == "__main__":
    main()
