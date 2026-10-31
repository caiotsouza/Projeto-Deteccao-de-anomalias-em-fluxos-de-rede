from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from src.config import DEFAULT_REPLAY_NAMESPACE, DEFAULT_REPLAY_START_ISO, PROJECT_ROOT
from src.generated_flow_context import FlowNetworkContext
from src.monitoring_repository import InMemoryPredictionRepository
from src.replay import (
    PREDICTION_COLUMNS,
    PROVENANCE_COLUMNS,
    ReplayArtifacts,
    ReplayConfig,
    _load_replay_frames,
    build_replay_documents,
    run_replay,
)
from tests.marco12_helpers import model_identity, replay_frames


def _replace_hashes(features, predictions, provenance) -> None:
    hashes = pd.Series(
        (
            f"{int(value):016x}"
            for value in pd.util.hash_pandas_object(features, index=False).to_numpy(
                dtype=np.uint64
            )
        ),
        dtype="string",
    )
    predictions["record_hash"] = hashes
    provenance["record_hash"] = hashes


class WriteSpyRepository(InMemoryPredictionRepository):
    def __init__(self) -> None:
        super().__init__()
        self.initialize_calls = 0
        self.upsert_calls = 0

    def initialize(self):
        self.initialize_calls += 1
        return super().initialize()

    def upsert_many(self, documents):
        self.upsert_calls += 1
        return super().upsert_many(documents)


class Marco12ReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = model_identity()
        self.features, self.predictions, self.provenance = replay_frames()

    def test_default_configuration_is_stable_and_millisecond_normalized(self) -> None:
        default_one = ReplayConfig(limit=1).normalized(10)
        default_two = ReplayConfig(limit=1).normalized(10)
        explicit = ReplayConfig(
            limit=1,
            start_time=datetime(2026, 1, 1, 0, 0, 0, 123456, tzinfo=timezone.utc),
        ).normalized(10)

        self.assertEqual(default_one, default_two)
        self.assertEqual(default_one.start_time.isoformat(), DEFAULT_REPLAY_START_ISO)
        self.assertEqual(default_one.namespace, DEFAULT_REPLAY_NAMESPACE)
        self.assertEqual(explicit.start_time.microsecond, 123000)

    def test_same_configuration_and_different_batch_size_produce_same_documents(self) -> None:
        first = build_replay_documents(
            self.features,
            self.predictions,
            self.provenance,
            self.model,
            ReplayConfig(limit=4, batch_size=1),
        )
        second = build_replay_documents(
            self.features,
            self.predictions,
            self.provenance,
            self.model,
            ReplayConfig(limit=4, batch_size=4),
        )

        self.assertEqual(first, second)
        self.assertEqual(len({item["event_id"] for item in first}), 4)

    def test_offset_chunks_are_identical_to_full_replay(self) -> None:
        full = build_replay_documents(
            self.features,
            self.predictions,
            self.provenance,
            self.model,
            ReplayConfig(limit=4),
        )
        first = build_replay_documents(
            self.features,
            self.predictions,
            self.provenance,
            self.model,
            ReplayConfig(limit=2, offset=0),
        )
        second = build_replay_documents(
            self.features,
            self.predictions,
            self.provenance,
            self.model,
            ReplayConfig(limit=2, offset=2),
        )

        self.assertEqual(first + second, full)

    def test_operational_threshold_is_inclusive(self) -> None:
        documents = build_replay_documents(
            self.features,
            self.predictions,
            self.provenance,
            self.model,
            ReplayConfig(limit=2),
        )

        self.assertEqual(documents[0]["classification"]["anomaly_score"], 0.6)
        self.assertEqual(documents[0]["classification"]["predicted_anomaly"], 1)
        self.assertEqual(documents[1]["classification"]["predicted_anomaly"], 0)

    def test_documents_accept_only_explicitly_validated_network_context(self) -> None:
        contexts = {
            0: FlowNetworkContext("192.168.10.5", "192.168.10.50", "TCP"),
            1: FlowNetworkContext("192.168.10.6", "192.168.10.60", "UDP"),
        }
        documents = build_replay_documents(
            self.features,
            self.predictions,
            self.provenance,
            self.model,
            ReplayConfig(limit=2),
            contexts,
        )

        self.assertEqual(documents[0]["context"]["src_ip"], "192.168.10.5")
        self.assertEqual(documents[0]["context"]["dst_ip"], "192.168.10.50")
        self.assertEqual(documents[1]["context"]["protocol"], "UDP")
        self.assertEqual(
            documents[0]["context"]["context_origin"],
            "processed_cicids_features+generated_labelled_flows_validated",
        )

        with self.assertRaisesRegex(ValueError, "Contexto de rede ausente"):
            build_replay_documents(
                self.features,
                self.predictions,
                self.provenance,
                self.model,
                ReplayConfig(limit=2),
                {0: contexts[0]},
            )

    def test_reordered_or_tampered_features_are_detected(self) -> None:
        reordered = self.features.iloc[::-1].reset_index(drop=True)
        tampered = self.features.copy()
        tampered.loc[0, "flow_duration"] += 1

        for frame in (reordered, tampered):
            with self.subTest(frame=frame):
                with self.assertRaisesRegex(ValueError, "record_hash"):
                    build_replay_documents(
                        frame,
                        self.predictions,
                        self.provenance,
                        self.model,
                        ReplayConfig(limit=4),
                    )

    def test_invalid_native_prediction_and_fractional_port_are_rejected(self) -> None:
        bad_prediction = self.predictions.copy()
        bad_prediction.loc[0, "sklearn_prediction"] = 0
        with self.assertRaisesRegex(ValueError, "sklearn_prediction"):
            build_replay_documents(
                self.features,
                bad_prediction,
                self.provenance,
                self.model,
                ReplayConfig(limit=4),
            )

        fractional_features = self.features.copy()
        fractional_predictions = self.predictions.copy()
        fractional_provenance = self.provenance.copy()
        fractional_features.loc[0, "destination_port"] = 80.5
        _replace_hashes(
            fractional_features, fractional_predictions, fractional_provenance
        )
        with self.assertRaisesRegex(ValueError, "destination_port deve ser inteira"):
            build_replay_documents(
                fractional_features,
                fractional_predictions,
                fractional_provenance,
                self.model,
                ReplayConfig(limit=4),
            )

    def test_documents_do_not_persist_truth_or_raw_scenario_filename(self) -> None:
        documents = build_replay_documents(
            self.features,
            self.predictions,
            self.provenance,
            self.model,
            ReplayConfig(limit=4),
        )
        serialized = json.dumps(documents).lower()

        for forbidden in (
            '"label"',
            "binary_label",
            "attack_category",
            "ground_truth",
            "true_class",
            "secret-scenario",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertIn("dataset_provenance_ref", serialized)
        self.assertIn("dst_port", serialized)

    def test_report_preflight_occurs_before_any_repository_write(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as temporary:
            root = Path(temporary)
            report_path = root / "existing.json"
            report_path.write_text("{}", encoding="utf-8")
            repository = WriteSpyRepository()
            model = model_identity(root=root)

            with self.assertRaises(FileExistsError):
                run_replay(
                    repository,
                    project_root=root,
                    model=model,
                    config=ReplayConfig(limit=1),
                    report_path=report_path,
                )

            self.assertEqual(repository.initialize_calls, 0)
            self.assertEqual(repository.upsert_calls, 0)

    def _temporary_artifacts(self, root: Path) -> tuple[ReplayArtifacts, object]:
        root.mkdir(parents=True, exist_ok=True)
        features_path = root / "features.parquet"
        predictions_path = root / "predictions.parquet"
        provenance_path = root / "provenance.parquet"
        self.features.to_parquet(features_path, index=False)
        self.predictions.to_parquet(predictions_path, index=False)
        provenance_with_truth = self.provenance.assign(
            label="SHOULD_NOT_BE_LOADED", binary_label=1
        )
        provenance_with_truth.to_parquet(provenance_path, index=False)
        model = model_identity(root=root)
        model.registry_path.write_text("registry", encoding="utf-8")
        model.model_path.write_bytes(b"model-not-deserialized")
        return ReplayArtifacts(features_path, predictions_path, provenance_path), model

    def test_loader_projects_away_labels_and_run_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as temporary:
            root = Path(temporary)
            artifacts, model = self._temporary_artifacts(root)
            _, loaded_predictions, loaded_provenance = _load_replay_frames(artifacts)
            self.assertEqual(tuple(loaded_predictions.columns), PREDICTION_COLUMNS)
            self.assertEqual(tuple(loaded_provenance.columns), PROVENANCE_COLUMNS)

            repository = InMemoryPredictionRepository()
            config = ReplayConfig(limit=4, batch_size=2)
            first = run_replay(
                repository,
                project_root=root,
                model=model,
                config=config,
                artifacts=artifacts,
            )
            second = run_replay(
                repository,
                project_root=root,
                model=model,
                config=config,
                artifacts=artifacts,
            )

            self.assertEqual(first["counts"]["inserted"], 4)
            self.assertEqual(second["counts"]["inserted"], 0)
            self.assertEqual(second["counts"]["duplicates"], 4)
            self.assertTrue(first["source_integrity_unchanged"])
            self.assertTrue(first["methodology"]["labels_loaded"] is False)

    def test_dry_run_does_not_initialize_or_write(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as temporary:
            root = Path(temporary)
            artifacts, model = self._temporary_artifacts(root)
            repository = WriteSpyRepository()
            report = run_replay(
                repository,
                project_root=root,
                model=model,
                config=ReplayConfig(limit=4, dry_run=True),
                artifacts=artifacts,
            )

            self.assertEqual(repository.initialize_calls, 0)
            self.assertEqual(repository.upsert_calls, 0)
            self.assertEqual(report["counts"]["would_insert_in_dry_run"], 4)


if __name__ == "__main__":
    unittest.main()
