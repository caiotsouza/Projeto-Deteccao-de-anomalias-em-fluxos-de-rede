"""Comparacoes descritivas: nao ajusta scaler, modelo ou limiar."""

from __future__ import annotations

import numpy as np
import pandas as pd


def validate_frame(frame: pd.DataFrame, columns: list[str]) -> None:
    if frame.empty or list(frame.columns) != columns:
        raise ValueError("Frame vazio ou contrato/ordem de features divergente.")
    if any(not pd.api.types.is_numeric_dtype(frame[c]) or pd.api.types.is_bool_dtype(frame[c]) for c in columns):
        raise ValueError("As features precisam ser numericas, nao booleanas.")
    if not np.isfinite(frame.to_numpy(dtype=np.float64)).all():
        raise ValueError("NaN ou infinito nas features.")


def reference_profile(train: pd.DataFrame) -> tuple[dict, dict]:
    columns = list(train.columns)
    validate_frame(train, columns)
    profile, ordered = {}, {}
    for name in columns:
        values = train[name].to_numpy(dtype=np.float64)
        quantiles = np.quantile(values, [0, .01, .25, .50, .75, .99, 1])
        profile[name] = {key: float(value) for key, value in zip(
            ("minimum", "p01", "p25", "median", "p75", "p99", "maximum"), quantiles)}
        profile[name].update(mean=float(np.mean(values)), std_population=float(np.std(values, ddof=0)),
                             unique_values=int(train[name].nunique()),
                             negative_values=int((values < 0).sum()))
        ordered[name] = np.sort(values)
    return profile, ordered


def compare_features(sample: pd.DataFrame, profile: dict, ordered: dict) -> list[dict]:
    validate_frame(sample, list(profile))
    comparisons = []
    for name in sample:
        values = sample[name].to_numpy(dtype=np.float64)
        reference = profile[name]
        median = float(np.median(values))
        unique, counts = np.unique(values, return_counts=True)
        mode = float(unique[np.argmax(counts)])
        sorted_train = ordered[name]
        outside = (values < reference["minimum"]) | (values > reference["maximum"])
        outside_central = (values < reference["p01"]) | (values > reference["p99"])
        left = int(np.searchsorted(sorted_train, median, side="left"))
        right = int(np.searchsorted(sorted_train, median, side="right"))
        mode_count = int(np.searchsorted(sorted_train, mode, side="right") -
                         np.searchsorted(sorted_train, mode, side="left"))
        comparisons.append({
            "feature": name, "training": reference,
            "sample": {"records": len(values), "minimum": float(np.min(values)), "median": median,
                       "maximum": float(np.max(values)), "mode": mode,
                       "observed_values_if_at_most_16": unique.tolist() if len(unique) <= 16 else None},
            "outside_training_min_max_count": int(outside.sum()),
            "outside_training_min_max_rate": float(outside.mean()),
            "outside_training_p01_p99_count": int(outside_central.sum()),
            "outside_training_p01_p99_rate": float(outside_central.mean()),
            "training_fraction_below_sample_median": left / len(sorted_train),
            "training_fraction_below_or_equal_sample_median": right / len(sorted_train),
            "training_count_equal_sample_mode": mode_count,
            "training_fraction_equal_sample_mode": mode_count / len(sorted_train),
        })
    return comparisons


def squared_distance_diagnostics(query, fitted_reference, distances, indices, columns) -> dict:
    """Decompoe distancias euclidianas, NAO o score de densidade do LOF.

    A participacao agrupada e ponderada pela distancia: um registro distante
    pode pesar mais. A mediana das participacoes por registro tambem e entregue.
    """
    q, ref, d, ix = map(np.asarray, (query, fitted_reference, distances, indices))
    if q.ndim != 2 or ref.ndim != 2 or q.shape[1] != ref.shape[1] or q.shape[1] != len(columns):
        raise ValueError("Dimensoes invalidas para a decomposicao.")
    if not len(q) or d.ndim != 2 or ix.shape != d.shape or len(d) != len(q) or not d.shape[1]:
        raise ValueError("Lote/vizinhos vazio ou shapes divergentes.")
    if not np.issubdtype(ix.dtype, np.integer) or (ix < 0).any() or (ix >= len(ref)).any():
        raise ValueError("Indices de vizinhos invalidos.")
    if not all(np.isfinite(a).all() for a in (q, ref, d)) or (d < 0).any():
        raise ValueError("Distancias ou coordenadas invalidas.")
    differences = q[:, None, :] - ref[ix]
    squared = differences ** 2
    reconstructed = squared.sum(axis=2)
    if not np.allclose(reconstructed, d ** 2, rtol=1e-8, atol=1e-8):
        raise ValueError("As distancias nao correspondem a geometria Euclidiana informada.")
    per_record = squared.mean(axis=1)
    totals = per_record.sum(axis=1)
    shares = np.divide(per_record, totals[:, None], out=np.zeros_like(per_record), where=totals[:, None] > 0)
    pooled = per_record.sum(axis=0)
    pooled = pooled / pooled.sum() if pooled.sum() else np.zeros_like(pooled)
    below = np.maximum(ref.min(axis=0) - q, 0)
    above = np.maximum(q - ref.max(axis=0), 0)
    floor = np.sqrt(((below + above) ** 2).sum(axis=1))
    if (floor > d.min(axis=1) + 1e-6).any():
        raise ValueError("Limite inferior de suporte excede a distancia observada.")
    features = [{"feature": name, "pooled_squared_distance_share": float(pooled[i]),
                 "median_record_squared_distance_share": float(np.median(shares[:, i]))}
                for i, name in enumerate(columns)]
    features.sort(key=lambda item: (-item["pooled_squared_distance_share"], item["feature"]))
    records = []
    for row in range(len(q)):
        order = np.argsort(shares[row])[::-1][:5]
        records.append({"nearest_distance": float(d[row].min()),
                        "mean_neighbor_distance": float(d[row].mean()),
                        "support_range_distance_lower_bound": float(floor[row]),
                        "top_distance_components": [{"feature": columns[i], "share": float(shares[row, i])}
                                                    for i in order]})
    return {"metric": "squared Euclidean distance after the frozen LOF scaler", "neighbors": d.shape[1],
            "nearest_distance_median": float(np.median(d.min(axis=1))),
            "support_range_distance_lower_bound_median": float(np.median(floor)),
            "features": features, "records": records,
            "is_lof_score_attribution": False, "applies_to_isolation_forest": False}
