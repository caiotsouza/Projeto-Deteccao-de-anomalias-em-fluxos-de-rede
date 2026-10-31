"""Contrato do adaptador exploratorio; nenhuma dependencia de Docker ou PCAP privado."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from predict_lab_v4 import run_experiment
from src.lab_flow_audit import COMMITS, sha256
from src.lab_v4_adapter import parse_v4_timestamp, prepare_v4_records, summarize_predictions


ROOT = Path(__file__).resolve().parents[1]


class LabV4AdapterTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "tmp").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "tmp")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.extracted = self.directory / "extracted"
        self.extracted.mkdir()
        self.pcap = self.directory / "test.pcap"
        self.pcap.write_bytes(b"controlled provenance fixture, not parsed as real PCAP")
        self.selection = json.loads((ROOT / "data/processed/monday_feature_manifest.json").read_text())
        self.split = json.loads((ROOT / "experiments/scale_100k/data/splits/split_manifest.json").read_text())
        self.row = dict.fromkeys(self.selection["selected_features"], 0)
        self.row.update({
            "destination_port": 8000, "flow_duration": 1335,
            "total_fwd_packets": 3, "total_backward_packets": 4,
            "total_length_of_fwd_packets": 80, "total_length_of_bwd_packets": 343,
            "syn_flag_count": 2, "ack_flag_count": 6,
            "init_win_bytes_forward": 64240, "init_win_bytes_backward": 126,
            "packet_length_mean": 52.875, "average_packet_size": 423 / 7,
            "src_ip": "172.31.50.161", "dst_ip": "172.31.60.10",
            "src_port": 60029, "protocol": 6, "timestamp": "25/10/2026 07:22:16 PM",
            "flow_id": "test-flow", "Label": "NeedManualLabel",
        })
        self.write_rows([self.row])

    def write_rows(self, rows):
        self.csv = self.extracted / "flows.csv"
        pd.DataFrame(rows).to_csv(self.csv, index=False)
        self.run = {
            "status": "extraction_completed", "timezone": "UTC",
            "source_repository": "https://github.com/ahlashkari/CICFlowMeter",
            "source_commit": COMMITS["v4"], "image_id": "test-image",
            "pcap_sha256_before": sha256(self.pcap), "pcap_sha256_after": sha256(self.pcap),
            "csv_files": [{"name": self.csv.name, "sha256": sha256(self.csv)}],
        }
        self.write_manifest()

    def write_manifest(self):
        (self.extracted / "extraction_run.json").write_text(json.dumps(self.run), encoding="utf-8")

    def prepare(self, **overrides):
        options = dict(pcap=self.pcap, extraction_dir=self.extracted, selection=self.selection,
                       split=self.split, accept_experimental_v4=True, scenario="http_lab")
        options.update(overrides)
        return prepare_v4_records(**options)

    def test_requires_explicit_experimental_acknowledgment(self):
        with self.assertRaisesRegex(ValueError, "exploratorio"):
            self.prepare(accept_experimental_v4=False)

    def test_features_are_exact_ordered_separate_and_not_repaired(self):
        before = sha256(self.csv)
        records, method = self.prepare()
        record = records[0]
        self.assertEqual(list(record["features"]), self.split["feature_columns"])
        self.assertEqual(len(record["features"]), 60)
        for forbidden in ("label", "Label", "src_ip", "timestamp", "predicted_anomaly"):
            self.assertNotIn(forbidden, record["features"])
        self.assertEqual(record["features"]["syn_flag_count"], 2)
        self.assertEqual(record["features"]["ack_flag_count"], 6)
        self.assertEqual(record["features"]["init_win_bytes_backward"], 126)
        self.assertEqual(record["features"]["packet_length_mean"], 52.875)
        self.assertIsInstance(record["features"]["destination_port"], int)
        self.assertFalse(record["context"]["production_approved"])
        self.assertFalse(record["context"]["ground_truth_available"])
        self.assertEqual(record["observed_at"], "2026-10-25T19:22:16+00:00")
        self.assertEqual(method["rows_dropped"], 0)
        self.assertEqual(sha256(self.csv), before)

    def test_duplicate_segments_get_unique_and_repeatable_ids(self):
        self.write_rows([self.row, self.row])
        a, _ = self.prepare()
        b, _ = self.prepare()
        self.assertNotEqual(a[0]["event_id"], a[1]["event_id"])
        self.assertEqual([r["event_id"] for r in a], [r["event_id"] for r in b])
        self.assertEqual(a[0]["context"]["endpoint_group_id"], a[1]["context"]["endpoint_group_id"])

    def test_tail_is_preserved_and_context_not_inferred_from_label(self):
        tail = copy.deepcopy(self.row)
        tail.update(total_length_of_fwd_packets=0, total_length_of_bwd_packets=0,
                    total_fwd_packets=2, total_backward_packets=1, Label="ATTACK")
        self.write_rows([self.row, tail])
        records, _ = self.prepare()
        self.assertEqual(len(records), 2)
        self.assertEqual(records[1]["context"]["payload_group"], "zero_payload")
        self.assertFalse(records[1]["context"]["ground_truth_available"])
        self.assertNotIn("ATTACK", json.dumps(records))

    def test_rejects_wrong_provenance_and_timezone(self):
        for key, value in (("source_commit", COMMITS["legacy_pre2019"]), ("timezone", "local"),
                           ("source_repository", "unknown"), ("status", "failed")):
            with self.subTest(field=key):
                self.write_rows([self.row])
                self.run[key] = value
                self.write_manifest()
                with self.assertRaises(ValueError):
                    self.prepare()

    def test_rejects_invalid_ip_port_protocol_and_timestamp(self):
        for key, value in (("src_ip", "999.1.1.1"), ("src_port", 1.5),
                           ("src_port", 65536), ("protocol", 17), ("timestamp", "2026-10-25")):
            with self.subTest(field=key, value=value):
                row = {**self.row, key: value}
                self.write_rows([row])
                with self.assertRaises(ValueError):
                    self.prepare()

    def test_rejects_nan_infinite_missing_fractional_and_boolean_features(self):
        for row in ({**self.row, "flow_bytes_s": float("nan")},
                    {**self.row, "flow_bytes_s": float("inf")},
                    {**self.row, "flow_duration": 1.5},
                    {**self.row, "syn_flag_count": True},
                    {k: v for k, v in self.row.items() if k != "flow_duration"}):
            with self.subTest(row=row):
                self.write_rows([row])
                with self.assertRaises((ValueError, TypeError, OverflowError)):
                    self.prepare()

    def test_timestamp_midnight_noon_and_invalid_clock(self):
        self.assertEqual(parse_v4_timestamp("25/10/2026 12:00:00 AM"), "2026-10-25T00:00:00+00:00")
        self.assertEqual(parse_v4_timestamp("25/10/2026 12:00:00 PM"), "2026-10-25T12:00:00+00:00")
        for text in ("25/10/2026 00:00:00 AM", "31/02/2026 01:00:00 PM", "25/10/2026 13:00:00 PM"):
            with self.assertRaises(ValueError):
                parse_v4_timestamp(text)

    def test_runner_guards_fail_before_model_loading_or_output_write(self):
        with patch("predict_lab_v4.AnomalyInferenceService.from_registry") as loader:
            with self.assertRaises(ValueError):
                run_experiment(pcap=self.pcap, extraction_dir=self.extracted,
                               output_dir=self.directory / "new")
            with self.assertRaises(FileExistsError):
                run_experiment(pcap=self.pcap, extraction_dir=self.extracted,
                               output_dir=self.extracted, accept_experimental_v4=True)
            # CSV/PCAP provenance failure must occur before deserialization.
            self.run["pcap_sha256_before"] = "tampered"
            self.write_manifest()
            with self.assertRaises(ValueError):
                run_experiment(pcap=self.pcap, extraction_dir=self.extracted,
                               output_dir=self.directory / "new", accept_experimental_v4=True)
            loader.assert_not_called()
            self.assertFalse((self.directory / "new").exists())

    def fake_project(self):
        root = self.directory / "project"
        registry = {"experiments": {"expanded_100k": {"models": {}}}}
        for name in ("isolation_forest", "lof"):
            model = root / "models" / f"{name}.joblib"
            model.parent.mkdir(parents=True, exist_ok=True)
            model.write_bytes(b"test stub: never deserialized")
            metadata = model.with_suffix(".json")
            metadata.write_text("{}")
            registry["experiments"]["expanded_100k"]["models"][name] = {
                "model_artifact": {"relative_path": str(model.relative_to(root)), "sha256": sha256(model)},
                "metadata_artifact": {"relative_path": str(metadata.relative_to(root)),
                                      "sha256": "historical auxiliary mismatch"},
            }
        for name, data in (
            ("reports/operational/model_registry_operational.json", registry),
            ("data/processed/monday_feature_manifest.json", self.selection),
            ("experiments/scale_100k/data/splits/split_manifest.json", self.split),
        ):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data))
        return root

    def test_runner_preserves_metadata_warning_but_blocks_changed_model(self):
        root = self.fake_project()
        model = root / "models/isolation_forest.joblib"
        model.write_bytes(b"tampered model")
        with patch("predict_lab_v4.AnomalyInferenceService.from_registry") as loader:
            with self.assertRaisesRegex(ValueError, "model_artifact"):
                run_experiment(pcap=self.pcap, extraction_dir=self.extracted,
                               output_dir=self.directory / "new", accept_experimental_v4=True,
                               project_root=root)
            loader.assert_not_called()

    def test_runner_full_pipeline_uses_same_rows_batches_and_keeps_auxiliary_warning(self):
        from types import SimpleNamespace

        root = self.fake_project()
        self.write_rows([self.row] * 3)
        output = self.directory / "result"
        calls = []

        def factory(**options):
            selection = options["selection"]
            def predict_many(records):
                calls.append((selection.model, len(records)))
                return [{"event_id": r["event_id"], "context": r["context"],
                         "prediction": {"anomaly_score": .4, "predicted_anomaly": 0,
                                        "native_predicted_anomaly": 0}} for r in records]
            return SimpleNamespace(feature_columns=self.split["feature_columns"], selection=selection,
                                   model_sha256="synthetic", threshold=.6, predict_many=predict_many)

        with patch("predict_lab_v4.AnomalyInferenceService.from_registry", side_effect=factory):
            report = run_experiment(pcap=self.pcap, extraction_dir=self.extracted, output_dir=output,
                                    accept_experimental_v4=True, project_root=root, batch_size=2)
        self.assertEqual(calls, [("isolation_forest", 2), ("isolation_forest", 1), ("lof", 2), ("lof", 1)])
        self.assertEqual(report["decision_agreement"]["agree"], 3)
        self.assertFalse(report["database_written"])
        self.assertFalse(report["models_retrained"])
        self.assertTrue(report["integrity"]["protected_files_unchanged"])
        self.assertEqual(len(report["integrity"]["warnings"]), 2)
        self.assertFalse(report["integrity"]["auxiliary_metadata_used_for_inference"])
        self.assertTrue((output / "run_manifest.json").is_file())
        for name, expected in report["output_sha256"].items():
            self.assertEqual(sha256(output / name), expected)

    def test_summary_reports_signal_not_supervised_metrics(self):
        records, _ = self.prepare()
        context = records[0]["context"]
        predictions = [
            {"context": context, "prediction": {"anomaly_score": .7, "predicted_anomaly": 1,
                                                 "native_predicted_anomaly": 1}},
            {"context": {**context, "payload_group": "zero_payload"},
             "prediction": {"anomaly_score": .4, "predicted_anomaly": 0, "native_predicted_anomaly": 1}},
        ]
        result = summarize_predictions(predictions)
        self.assertEqual(result["all_segments"]["signal_rate"], .5)
        self.assertEqual(result["with_payload"]["signaled_segments"], 1)
        self.assertEqual(result["zero_payload"]["signaled_segments"], 0)
        self.assertEqual(result["endpoint_groups"]["total"], 1)
        self.assertFalse(result["supervised_metrics_computed"])
        for key in ("precision", "recall", "fpr", "accuracy"):
            self.assertNotIn(key, result)


if __name__ == "__main__":
    unittest.main()
