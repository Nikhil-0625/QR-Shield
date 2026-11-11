"""Static contract checks for the repository Docker startup dispatch."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


def case_body(script, label):
    match = re.search(
        rf"(?ms)^    {re.escape(label)}\)\s*\n(.*?)^        ;;\s*$",
        script,
    )
    if not match:
        raise AssertionError(f"Missing {label} case in demo entrypoint")
    return match.group(1)


class ContainerStartupContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        cls.entrypoint = (ROOT / "tools" / "demo-entrypoint.sh").read_text(encoding="utf-8")
        cls.dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")

    def test_dockerfile_uses_repository_entrypoint_and_context_contains_it(self):
        self.assertIn("COPY tools/demo-entrypoint.sh /app/demo-entrypoint.sh", self.dockerfile)
        self.assertIn('ENTRYPOINT ["/app/demo-entrypoint.sh"]', self.dockerfile)
        self.assertIn("!tools/demo-entrypoint.sh", self.dockerignore)

    def test_production_dispatches_to_normal_fastapi_app(self):
        branch = case_body(self.entrypoint, "production")
        self.assertIn('APP_MODULE="main:app"', branch)
        self.assertIn("DATABASE_URL", branch)
        self.assertIn("FACTORY=0", branch)

    def test_restricted_demo_keeps_demo_factory_and_data_directory(self):
        branch = case_body(self.entrypoint, "restricted-demo")
        self.assertIn('APP_MODULE="demo_app:create_app"', branch)
        self.assertIn("FACTORY=1", branch)
        self.assertIn("mkdir -p /data", branch)
        self.assertIn("chown 10001:10001 /data", branch)

    def test_invalid_container_mode_fails_clearly(self):
        invalid_branch = re.search(r"(?ms)^    \*\)\s*\n(.*?)^        ;;\s*$", self.entrypoint)
        self.assertIsNotNone(invalid_branch)
        self.assertIn("QR_SHIELD_MODE must be restricted-demo or production", invalid_branch.group(1))

    def test_both_modes_use_render_port_and_all_interface_binding(self):
        self.assertIn("EXPOSE 10000", self.dockerfile)
        self.assertIn('--host 0.0.0.0 --port "${PORT:-8000}"', self.entrypoint)
        self.assertIn('exec gosu 10001:10001 python -m uvicorn "$@"', self.entrypoint)


if __name__ == "__main__":
    unittest.main()
