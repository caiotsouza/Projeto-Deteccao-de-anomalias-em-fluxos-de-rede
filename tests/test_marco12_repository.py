from __future__ import annotations

import copy
import unittest
from datetime import datetime, timedelta, timezone

from src.monitoring_repository import (
    DocumentConflict,
    InMemoryPredictionRepository,
    MongoPredictionRepository,
    QueryFilters,
    from_storage_document,
    to_storage_document,
    validate_monitoring_document,
)
from src.runtime_config import RuntimeSettings
from tests.marco12_helpers import model_identity, monitoring_document


class Marco12RepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = model_identity()
        self.start = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def test_bson_boundary_uses_aware_dates_and_round_trips_to_iso(self) -> None:
        document = monitoring_document("event-1", self.start, self.model)
        stored = to_storage_document(document)

        self.assertIsInstance(stored["observed_at"], datetime)
        self.assertEqual(stored["observed_at"].tzinfo, timezone.utc)
        self.assertIsInstance(stored["processed_at_utc"], datetime)
        restored = from_storage_document({"_id": "ignored", **stored})
        self.assertEqual(restored, document)
        self.assertNotIn("_id", restored)

    def test_upsert_is_idempotent_and_returns_defensive_copies(self) -> None:
        repository = InMemoryPredictionRepository()
        original = monitoring_document("event-1", self.start, self.model)

        first = repository.upsert_many([original, original])
        second = repository.upsert_many([original])
        original["context"]["dst_port"] = 1
        queried = repository.query(
            QueryFilters(
                self.start,
                self.start + timedelta(seconds=1),
                self.model,
            )
        )

        self.assertEqual(first.as_dict(), {"attempted": 2, "inserted": 1, "duplicates": 1, "conflicts": 0})
        self.assertEqual(second.as_dict(), {"attempted": 1, "inserted": 0, "duplicates": 1, "conflicts": 0})
        self.assertEqual(queried.documents[0]["context"]["dst_port"], 443)

    def test_conflicting_batch_is_rejected_without_partial_mutation(self) -> None:
        repository = InMemoryPredictionRepository()
        existing = monitoring_document("event-1", self.start, self.model, score=0.7)
        repository.upsert_many([existing])
        new = monitoring_document("event-2", self.start, self.model, score=0.8)
        conflict = monitoring_document("event-1", self.start, self.model, score=0.9)

        with self.assertRaises(DocumentConflict):
            repository.upsert_many([new, conflict])

        result = repository.query(
            QueryFilters(self.start, self.start + timedelta(seconds=1), self.model)
        )
        self.assertEqual(result.matched_count, 1)
        self.assertEqual(result.documents[0]["event_id"], "event-1")

    def test_time_filter_is_start_inclusive_and_end_exclusive(self) -> None:
        repository = InMemoryPredictionRepository()
        end = self.start + timedelta(seconds=1)
        documents = [
            monitoring_document("event-1", self.start, self.model),
            monitoring_document("event-2", end - timedelta(microseconds=1), self.model),
            monitoring_document("event-3", end, self.model),
        ]
        repository.upsert_many(documents)

        first = repository.query(QueryFilters(self.start, end, self.model))
        adjacent = repository.query(
            QueryFilters(end, end + timedelta(seconds=1), self.model)
        )

        self.assertEqual([item["event_id"] for item in first.documents], ["event-1", "event-2"])
        self.assertEqual([item["event_id"] for item in adjacent.documents], ["event-3"])

    def test_filters_fix_complete_model_identity_source_protocol_and_anomaly(self) -> None:
        repository = InMemoryPredictionRepository()
        repository.upsert_many(
            [
                monitoring_document("event-1", self.start, self.model, score=0.7, protocol="TCP"),
                monitoring_document("event-2", self.start + timedelta(seconds=1), self.model, score=0.5, protocol="UDP"),
            ]
        )
        result = repository.query(
            QueryFilters(
                self.start,
                self.start + timedelta(seconds=2),
                self.model,
                source="offline_replay",
                protocol="TCP",
                anomalies_only=True,
            )
        )
        wrong_model = repository.query(
            QueryFilters(
                self.start,
                self.start + timedelta(seconds=2),
                model_identity(threshold=0.61),
            )
        )

        self.assertEqual([item["event_id"] for item in result.documents], ["event-1"])
        self.assertEqual(wrong_model.matched_count, 0)

    def test_validation_rejects_truth_recursively_unsafe_keys_and_wrong_types(self) -> None:
        base = monitoring_document("event-1", self.start, self.model)
        cases = []
        nested_truth = copy.deepcopy(base)
        nested_truth["context"]["metadata"] = {"binary_label": 1}
        cases.append(nested_truth)
        root_truth = copy.deepcopy(base)
        root_truth["label"] = "BENIGN"
        cases.append(root_truth)
        unsafe = copy.deepcopy(base)
        unsafe["context"]["$where"] = "x"
        cases.append(unsafe)
        wrong_schema = copy.deepcopy(base)
        wrong_schema["schema_version"] = "1"
        cases.append(wrong_schema)
        wrong_prediction = copy.deepcopy(base)
        wrong_prediction["classification"]["predicted_anomaly"] = True
        cases.append(wrong_prediction)
        uppercase_hash = copy.deepcopy(base)
        uppercase_hash["model"]["sha256"] = "A" * 64
        cases.append(uppercase_hash)

        for document in cases:
            with self.subTest(document=document):
                with self.assertRaises((TypeError, ValueError)):
                    validate_monitoring_document(document)

    def test_mongo_filter_uses_bson_dates_and_full_identity(self) -> None:
        settings = RuntimeSettings(project_root=self.model.registry_path.parent)
        repository = MongoPredictionRepository(settings)
        try:
            filters = QueryFilters(
                self.start,
                self.start + timedelta(hours=1),
                self.model,
                source="offline_replay",
                protocol="TCP",
                anomalies_only=True,
            )
            query = repository._mongo_filter(filters)
        finally:
            repository.client.close()

        self.assertEqual(query["observed_at"], {"$gte": filters.start, "$lt": filters.end})
        for key, value in self.model.as_filter().items():
            self.assertEqual(query[f"model.{key}"], value)
        self.assertTrue(query["classification.is_anomaly"])
        self.assertEqual(len(MongoPredictionRepository.INDEX_NAMES), 5)


if __name__ == "__main__":
    unittest.main()
