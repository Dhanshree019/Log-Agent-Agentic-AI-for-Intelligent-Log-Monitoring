import unittest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from app.main import app


class TestLogAnalysisAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health(self):
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"status": "healthy", "service": "log-agent-backend"})

    def test_analyze_file_not_found(self):
        res = self.client.post("/analyze", json={"log_path": "non_existent_file.log"})
        self.assertEqual(res.status_code, 400)
        self.assertIn("Log file not found", res.json()["detail"])

    @patch("app.api.logs.analyze_logs", new_callable=AsyncMock)
    def test_analyze_post_success(self, mock_analyze):
        mock_analyze.return_value = {
            "status": "success",
            "incident_count": 1,
            "analysis": {
                "incident_id": "INC-001",
                "service_name": "payment-service",
                "severity": "CRITICAL",
                "incident_summary": "Database connection pool exhausted",
                "root_cause": "Pool size reduced",
                "cause_status": "CONFIRMED",
                "evidence": ["Connection pool timeout"],
                "historical_matches": [],
                "recommended_fixes": ["Restore pool size"],
                "verification_steps": ["Check active connections"],
                "confidence_score": 0.92,
                "notification_required": True,
            },
            "notification": {"status": "sent", "to": ["devops@example.com"]},
        }

        res = self.client.post("/analyze", json={"trigger_email": True})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["analysis"]["severity"], "CRITICAL")
        self.assertEqual(data["notification"]["status"], "sent")

    @patch("app.api.logs.analyze_logs", new_callable=AsyncMock)
    def test_analyze_get_success(self, mock_analyze):
        mock_analyze.return_value = {
            "status": "success",
            "incident_count": 0,
            "message": "No ERROR, CRITICAL, or FATAL log incidents detected.",
            "analysis": None,
            "notification": None,
        }

        res = self.client.get("/analyze")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")

    @patch("app.api.logs.analyze_logs", new_callable=AsyncMock)
    def test_upload_and_analyze(self, mock_analyze):
        mock_analyze.return_value = {
            "status": "success",
            "incident_count": 1,
            "analysis": {
                "incident_id": "INC-002",
                "service_name": "api-gateway",
                "severity": "HIGH",
                "incident_summary": "Gateway 504 timeout",
                "root_cause": "Upstream service unresponsive",
                "cause_status": "PROBABLE",
                "evidence": ["504 Gateway Timeout"],
                "historical_matches": [],
                "recommended_fixes": ["Restart upstream service"],
                "verification_steps": ["Verify latency metrics"],
                "confidence_score": 0.85,
                "notification_required": False,
            },
            "notification": None,
        }

        files = {"file": ("test.log", b"2026-11-23 14:03:58,100 ERROR [api-gateway] 504 Gateway Timeout\n", "text/plain")}
        res = self.client.post("/upload-and-analyze", files=files)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["analysis"]["service_name"], "api-gateway")


if __name__ == "__main__":
    unittest.main()
