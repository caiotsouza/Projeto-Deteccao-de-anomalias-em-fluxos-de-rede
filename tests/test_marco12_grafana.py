from __future__ import annotations

import json
import unittest
from pathlib import Path
from urllib.parse import urlparse

import yaml

from generate_grafana_dashboard import OUTPUT_PATH, build_dashboard
from src.dashboard_api import create_app
from src.monitoring_repository import InMemoryPredictionRepository
from src.runtime_config import RuntimeSettings
from tests.marco12_helpers import model_identity


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class Marco12GrafanaContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dashboard = json.loads(OUTPUT_PATH.read_text(encoding="utf-8"))

    def test_generated_file_matches_reproducible_builder(self) -> None:
        self.assertEqual(self.dashboard, build_dashboard())

    def test_dashboard_has_eleven_unique_panels_and_fixed_datasource(self) -> None:
        panels = self.dashboard["panels"]
        self.assertEqual(len(panels), 11)
        self.assertEqual({panel["id"] for panel in panels}, set(range(1, 12)))
        self.assertEqual(self.dashboard["timezone"], "utc")
        self.assertEqual(self.dashboard["refresh"], "30s")
        self.assertEqual(self.dashboard["time"]["from"], "2026-01-01T00:00:00Z")
        self.assertEqual(self.dashboard["time"]["to"], "2026-01-02T04:00:00Z")
        for panel in panels:
            self.assertEqual(panel["datasource"]["uid"], "tcc-fastapi")
            self.assertEqual(
                panel["datasource"]["type"],
                "yesoreyeram-infinity-datasource",
            )

    def test_every_target_points_to_an_implemented_api_route(self) -> None:
        app = create_app(
            repository=InMemoryPredictionRepository(),
            settings=RuntimeSettings(),
            model=model_identity(),
        )
        routes = set(app.openapi()["paths"])
        expected = {
            "/api/v1/dashboard/overview",
            "/api/v1/dashboard/timeseries",
            "/api/v1/dashboard/breakdowns",
            "/api/v1/anomalies/recent",
            "/api/v1/model/status",
        }
        used = set()
        for panel in self.dashboard["panels"]:
            self.assertEqual(len(panel["targets"]), 1)
            target = panel["targets"][0]
            parsed = urlparse(target["url"])
            used.add(parsed.path)
            self.assertIn(parsed.path, routes)
            self.assertEqual(target["source"], "url")
            self.assertEqual(target["type"], "json")
            self.assertEqual(target["parser"], "backend")
            if panel["id"] <= 10:
                self.assertIn("start=${__from:date:iso}", target["url"])
                self.assertIn("end=${__to:date:iso}", target["url"])
            else:
                self.assertNotIn("${__from", target["url"])
        self.assertEqual(used, expected)

    def test_methodological_warnings_and_available_dimensions_are_explicit(self) -> None:
        serialized = json.dumps(self.dashboard, ensure_ascii=False).lower()
        for required in (
            "replay offline",
            "balanceado",
            "timestamps simulados",
            "não é probabilidade",
            "generatedlabelledflows",
            "destination_port",
            "model_sha256",
            "operating_point",
            "threshold",
        ):
            self.assertIn(required, serialized)
        for forbidden in (
            "binary_label",
            "attack_category",
            "ground_truth",
            "false_positive_rate",
            "dataset_source_file",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_provisioning_compose_and_mongodb_contract_are_coherent(self) -> None:
        compose = (PROJECT_ROOT / "infra" / "compose.yaml").read_text(encoding="utf-8")
        parsed_compose = yaml.safe_load(compose)
        datasource = (
            PROJECT_ROOT
            / "infra"
            / "grafana"
            / "provisioning"
            / "datasources"
            / "tcc-fastapi.yaml"
        ).read_text(encoding="utf-8")
        dockerfile = (PROJECT_ROOT / "infra" / "api" / "Dockerfile").read_text(encoding="utf-8")
        schema = json.loads(
            (PROJECT_ROOT / "reports" / "integration" / "mongodb_prediction.schema.json").read_text(
                encoding="utf-8"
            )
        )

        for service in ("mongodb:", "mongo-init:", "api:", "grafana:"):
            self.assertIn(service, compose)
        self.assertEqual(
            set(parsed_compose["services"]),
            {"mongodb", "mongo-init", "api", "grafana"},
        )
        self.assertEqual(
            parsed_compose["services"]["api"]["depends_on"]["mongo-init"]["condition"],
            "service_completed_successfully",
        )
        self.assertIn("yesoreyeram-infinity-datasource@4.0.0", compose)
        self.assertIn("TCC_GRAFANA_ADMIN_PASSWORD:?", compose)
        self.assertIn("uid: tcc-fastapi", datasource)
        self.assertIn("allowedHosts:", datasource)
        self.assertIn("USER app", dockerfile)
        self.assertIn("initialize_mongodb.py", dockerfile)
        properties = schema["validator"]["$jsonSchema"]["properties"]
        self.assertEqual(properties["observed_at"]["bsonType"], "date")
        self.assertEqual(properties["processed_at_utc"]["bsonType"], "date")
        self.assertFalse(schema["retention"]["ttl_enabled_by_default"])
        self.assertIn("infra/.env", (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
