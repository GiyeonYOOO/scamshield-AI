"""Deployment-specific configuration regressions (no live API calls)."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.scamshield_api import create_app
from app.scamshield.llm import OpenAICompatibleDecider


class DeploymentTests(unittest.TestCase):
    def test_environment_secrets_take_priority_without_local_env(self):
        with patch.dict(os.environ, {
            "OPENAI_API_KEY": "deployment-test-key",
            "OPENAI_MODEL": "deployment-test-model",
            "OPENAI_BASE_URL": "https://example.com/v1",
        }), patch("app.scamshield.llm.ENV_PATH", Path("/does-not-exist/.env")):
            decider = OpenAICompatibleDecider.from_env()
            self.assertIsNotNone(decider)
            self.assertEqual(decider.key, "deployment-test-key")
            self.assertEqual(decider.model, "deployment-test-model")

    def test_cloud_db_path_and_healthcheck(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "scamshield-test.sqlite3")
            with patch.dict(os.environ, {"SCAMSHIELD_DB_PATH": path}):
                with TestClient(create_app(secure_cookies=True)) as client:
                    self.assertEqual(client.get("/healthz").json(), {"status": "ok"})
                    self.assertEqual(client.get("/").status_code, 200)
                    self.assertTrue(Path(path).exists())


if __name__ == "__main__":
    unittest.main()
