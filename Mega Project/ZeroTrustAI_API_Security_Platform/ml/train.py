"""Train a reproducible baseline; synthetic results are NOT real-world security results."""

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from gateway.features import FEATURE_NAMES, SCHEMA_VERSION, extract_features
from gateway.state import Window


def synthetic_benign(count: int = 3000, seed: int = 42) -> np.ndarray:
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(count):
        path = str(rng.choice(["/products", "/orders", "/orders/1", "/orders/3", "/health"]))
        method = "GET"
        query = str(rng.choice(["", "page=1", "page=2&limit=10", "search=sensor"]))
        requests = int(rng.integers(1, 35))
        headers = {"user-agent": "zerotrustai-local-simulator", "accept": "*/*"}
        headers.update({"x-client-version": str(rng.integers(1, 4))})
        features = extract_features(
            method,
            path,
            query,
            b"",
            headers,
            Window(
                requests,
                int(rng.integers(1, min(5, requests) + 1)),
                float(rng.uniform(500, 10000)),
                0,
                0,
            ),
            None,
        )
        features[15] = float(rng.uniform(0, 850))
        rows.append(features)
    return np.asarray(rows, dtype=float)


def train(input_path: str | None, output: str, report_path: str):
    if input_path:
        records = [json.loads(line) for line in Path(input_path).read_text().splitlines() if line]
        if not records or any(r.get("label") != "benign" for r in records):
            raise ValueError(
                "Input must contain curated benign-only JSONL records with label=benign"
            )
        # Preserve temporal order. Keep entire sessions out of multiple splits when collecting data.
        values = np.asarray([r["features"] for r in records], dtype=float)
        source = "curated-benign-jsonl"
    else:
        values = synthetic_benign()
        source = "synthetic-local-demo-only"
    if values.ndim != 2 or values.shape[1] != len(FEATURE_NAMES) or len(values) < 300:
        raise ValueError("At least 300 benign rows of 18 features required")
    if not np.isfinite(values).all():
        raise ValueError("Features must be finite")
    a, b = int(len(values) * 0.7), int(len(values) * 0.85)
    training, validation, test = values[:a], values[a:b], values[b:]
    model = IsolationForest(n_estimators=100, max_samples="auto", random_state=42, n_jobs=1)
    model.fit(training)
    calibration_scores = -model.score_samples(validation)
    threshold = float(np.quantile(calibration_scores, 0.99))
    median = float(np.median(calibration_scores))
    benign_scores = -model.score_samples(test)
    version = datetime.now(UTC).strftime("iforest-%Y%m%dT%H%M%SZ")
    artifact = {
        "model": model,
        "threshold": threshold,
        "median": median,
        "features": FEATURE_NAMES,
        "schema": SCHEMA_VERSION,
        "version": version,
        "source": source,
    }
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, output)

    # Sanity check only: extreme modified vectors are not an OWASP attack benchmark.
    modified = test.copy()
    modified[:, 10] = 200  # request burst
    modified[:, 11] = 50  # resource enumeration
    modified[:, 12] = 1  # millisecond cadence
    modified_scores = -model.score_samples(modified)
    truth = np.concatenate([np.zeros(len(test)), np.ones(len(test))])
    prediction = np.concatenate([benign_scores > threshold, modified_scores > threshold])
    precision, recall, f1, _ = precision_recall_fscore_support(
        truth, prediction, average="binary", zero_division=0
    )
    report = {
        "version": version,
        "source": source,
        "warning": "Demo sanity check, NOT evidence of OWASP coverage or zero-day detection. "
        "Synthetic outliers may not be detected; measure on independently labeled traffic.",
        "split_sizes": {"train": len(training), "validation": len(validation), "test": len(test)},
        "threshold": threshold,
        "held_out_benign_false_positive_rate": float(np.mean(benign_scores > threshold)),
        "synthetic_modified_vectors_only": {
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "confusion_matrix_tn_fp_fn_tp": confusion_matrix(truth, prediction).ravel().tolist(),
        },
    }
    Path(report_path).parent.mkdir(parents=True, exist_ok=True)
    Path(report_path).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input", help="Curated benign JSONL: {label: benign, features: [18 values]}"
    )
    parser.add_argument("--output", default="ml/artifacts/isolation_forest.joblib")
    parser.add_argument("--report", default="reports/model_evaluation.json")
    args = parser.parse_args()
    train(args.input, args.output, args.report)
