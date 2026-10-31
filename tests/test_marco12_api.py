from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from src.dashboard_api import create_app
from src.monitoring_repository import (
    InMemoryPredictionRepository,
    RepositoryUnavailable,
)
from src.runtime_config import RuntimeSettings
from tests.marco12_helpers import model_identity, monitoring_document


class UnavailableRepository:
    def initialize(self):
        raise RepositoryUnavailable("offline")

    def ping(self):
        raise RepositoryUnavailable("offline")

    def upsert_many(self, documents):
        raise RepositoryUnavailable("offline")

    def query(self, filters):
        raise RepositoryUnavailable("offline")

    def status(self, model):
        raise RepositoryUnavailable("offline")


class FalsePingRepository(UnavailableRepository):
    def ping(self):
        return False


class Marco12ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = model_identity()
        self.start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.end = self.start + timedelta(minutes=10)
        self.repository = InMemoryPredictionRepository()
        self.repository.upsert_many(
            [
                monitoring_document("event-1", self.start, self.model, score=0.7),
                monitoring_document(
                    "event-2", self.start + timedelta(minutes=5), self.model, score=0.5
                ),
            ]
        )
        self.settings = RuntimeSettings(
            dashboard_window_hours=24,
            dashboard_max_records=100,
            dashboard_max_window_days=31,
        )
        self.app = create_app(
            repository=self.repository,
            settings=self.settings,
            model=self.model,
        )
        self.client = TestClient(self.app)
        self.params = {
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "bucket_minutes": 5,
        }

    def test_all_dashboard_endpoints_reconcile(self) -> None:
        overview = self.client.get("/api/v1/dashboard/overview", params=self.params)
        timeseries = self.client.get("/api/v1/dashboard/timeseries", params=self.params)
        breakdowns = self.client.get("/api/v1/dashboard/breakdowns", params=self.params)
        recent = self.client.get("/api/v1/anomalies/recent", params=self.params)
        status = self.client.get("/api/v1/model/status")

        for response in (overview, timeseries, breakdowns, recent, status):
            self.assertEqual(response.status_code, 200, response.text)
        overview_body = overview.json()
        totals = overview_body["totals"]
        self.assertEqual(totals["flows"], 2)
        self.assertEqual(totals["normal"] + totals["anomalies"], totals["flows"])
        self.assertEqual(totals["anomaly_rate"], 0.5)
        timeline = timeseries.json()["items"]
        self.assertEqual(sum(row["flows_total"] for row in timeline), totals["flows"])
        self.assertEqual(sum(row["anomalies_total"] for row in timeline), totals["anomalies"])
        self.assertEqual(recent.json()["items"][0]["event_id"], "event-1")
        self.assertFalse(breakdowns.json()["dimension_availability"]["protocol"])
        self.assertEqual(breakdowns.json()["protocols"], [])
        self.assertEqual(status.json()["model"]["model_sha256"], self.model.sha256)
        self.assertEqual(status.json()["model"]["threshold"], self.model.threshold)

    def test_window_always_means_requested_window_and_extent_is_separate(self) -> None:
        body = self.client.get("/api/v1/dashboard/overview", params=self.params).json()

        self.assertEqual(body["window"]["start"], self.start.isoformat())
        self.assertEqual(body["window"]["end"], self.end.isoformat())
        self.assertEqual(body["data_extent"]["start"], self.start.isoformat())
        self.assertEqual(
            body["data_extent"]["end"],
            (self.start + timedelta(minutes=5)).isoformat(),
        )
        self.assertEqual(body["query"]["interval_semantics"], "start_inclusive_end_exclusive")

    def test_empty_window_is_valid_and_contains_no_nan(self) -> None:
        params = {
            "start": (self.end + timedelta(hours=1)).isoformat(),
            "end": (self.end + timedelta(hours=2)).isoformat(),
        }
        overview = self.client.get("/api/v1/dashboard/overview", params=params)
        timeseries = self.client.get("/api/v1/dashboard/timeseries", params=params)
        breakdowns = self.client.get("/api/v1/dashboard/breakdowns", params=params)
        recent = self.client.get("/api/v1/anomalies/recent", params=params)

        for response in (overview, timeseries, breakdowns, recent):
            self.assertEqual(response.status_code, 200, response.text)
            self.assertNotIn("NaN", response.text)
        body = overview.json()
        self.assertEqual(body["totals"]["flows"], 0)
        self.assertIsNone(body["scores"]["p95"])
        self.assertEqual(body["data_extent"], {"start": None, "end": None})
        self.assertEqual(timeseries.json()["items"], [])
        self.assertEqual(recent.json()["items"], [])

    def test_invalid_queries_return_422(self) -> None:
        cases = [
            {"start": "not-a-date", "end": self.end.isoformat()},
            {"start": "2026-01-01T00:00:00", "end": self.end.isoformat()},
            {"start": self.start.isoformat(), "end": self.start.isoformat()},
            {"start": self.end.isoformat(), "end": self.start.isoformat()},
            {"start": self.start.isoformat(), "end": (self.start + timedelta(days=32)).isoformat()},
            {**self.params, "bucket_minutes": 0},
            {**self.params, "bucket_minutes": 1441},
            {**self.params, "top_n": 0},
            {**self.params, "top_n": 101},
            {**self.params, "limit": 0},
            {**self.params, "limit": 1001},
            {**self.params, "source": "   "},
        ]

        for params in cases:
            with self.subTest(params=params):
                response = self.client.get("/api/v1/dashboard/overview", params=params)
                self.assertEqual(response.status_code, 422, response.text)

    def test_timezone_offsets_are_normalized_to_utc(self) -> None:
        params = {
            "start": "2025-12-31T21:00:00-03:00",
            "end": "2025-12-31T21:01:00-03:00",
        }
        body = self.client.get("/api/v1/dashboard/overview", params=params).json()

        self.assertEqual(body["totals"]["flows"], 1)
        self.assertEqual(body["query"]["start"], self.start.isoformat())

    def test_truncated_snapshot_is_rejected_instead_of_publishing_partial_totals(self) -> None:
        app = create_app(
            repository=self.repository,
            settings=RuntimeSettings(dashboard_max_records=1),
            model=self.model,
        )
        response = TestClient(app).get("/api/v1/dashboard/overview", params=self.params)

        self.assertEqual(response.status_code, 422)
        self.assertIn("métricas parciais não são publicadas", response.text)

    def test_repository_failures_and_false_ping_return_503(self) -> None:
        client = TestClient(
            create_app(
                repository=UnavailableRepository(),
                settings=self.settings,
                model=self.model,
            )
        )
        paths = [
            "/health/ready",
            "/api/v1/dashboard/overview",
            "/api/v1/dashboard/timeseries",
            "/api/v1/dashboard/breakdowns",
            "/api/v1/anomalies/recent",
            "/api/v1/model/status",
        ]
        for path in paths:
            with self.subTest(path=path):
                response = client.get(path, params=self.params)
                self.assertEqual(response.status_code, 503, response.text)

        false_ping = TestClient(
            create_app(
                repository=FalsePingRepository(),
                settings=self.settings,
                model=self.model,
            )
        )
        self.assertEqual(false_ping.get("/health/ready").status_code, 503)
        self.assertEqual(self.client.get("/health/live").json(), {"status": "alive"})
        self.assertEqual(self.client.get("/health/ready").status_code, 200)


if __name__ == "__main__":
    unittest.main()
