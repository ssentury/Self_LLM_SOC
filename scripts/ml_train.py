from __future__ import annotations

import argparse
import json
import math
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
LOCAL_DEPS = ROOT / ".ml_deps"
LOCAL_DEPS_SENTINEL = LOCAL_DEPS / "six.py"
try:
    if LOCAL_DEPS_SENTINEL.is_file():
        with LOCAL_DEPS_SENTINEL.open("rb"):
            pass
        if str(LOCAL_DEPS) not in sys.path:
            sys.path.insert(0, str(LOCAL_DEPS))
except OSError:
    pass
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from soc.ml.features import (  # noqa: E402
    BINARY_FEATURE_ORDER,
    CATEGORICAL_FEATURES,
    RANDOM_SEED,
    binary_feature_contract,
)


LABEL_COLUMN = "Label"
ATTACK_COLUMN = "Attack"
TIME_COLUMN = "FLOW_START_MILLISECONDS"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Train the CICIDS2018 binary XGBoost router. "
            "This script is intended for the GPU workstation, not this laptop."
        )
    )
    parser.add_argument("--input", default="Dataset/NF-CICIDS2018-v3.csv")
    parser.add_argument("--output-dir", default="output/models")
    parser.add_argument("--model-name", default="xgb_binary_v1")
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    parser.add_argument("--val-size", type=float, default=0.15)
    parser.add_argument("--test-size", type=float, default=0.15)
    parser.add_argument("--max-dismiss-attack-rate", type=float, default=0.01)
    parser.add_argument("--ideal-dismiss-attack-rate", type=float, default=0.005)
    parser.add_argument("--min-alert-precision", type=float, default=0.95)
    parser.add_argument("--n-estimators", type=int, default=700)
    parser.add_argument("--max-depth", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=0.08)
    parser.add_argument("--subsample", type=float, default=0.85)
    parser.add_argument("--colsample-bytree", type=float, default=0.85)
    parser.add_argument("--early-stopping-rounds", type=int, default=40)
    parser.add_argument(
        "--xgb-verbose",
        type=int,
        default=25,
        help="Print XGBoost training progress every N boosting rounds.",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Load and validate the dataset, print distribution, then stop before training.",
    )
    parser.add_argument(
        "--device",
        default="cuda",
        choices=["cuda", "cpu"],
        help="Use cuda on the GPU workstation. Use cpu only for tiny dry runs.",
    )
    parser.add_argument(
        "--allow-downsample",
        action="store_true",
        help=(
            "Fallback only. Downsampling changes probability calibration; "
            "validation/test remain natural distribution."
        ),
    )
    parser.add_argument(
        "--benign-to-attack-ratio",
        type=float,
        default=3.0,
        help="Only used with --allow-downsample.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _require_training_dependencies(preflight_only=args.preflight_only)

    import pandas as pd
    if not args.preflight_only:
        import xgboost as xgb
        from sklearn.metrics import (
            average_precision_score,
            confusion_matrix,
            precision_recall_fscore_support,
            roc_auc_score,
        )

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    usecols = [TIME_COLUMN, *BINARY_FEATURE_ORDER, LABEL_COLUMN, ATTACK_COLUMN]
    _log(f"reading dataset: {input_path}")
    df = pd.read_csv(input_path, usecols=usecols)
    _log(f"loaded rows={len(df):,} cols={len(df.columns):,}")
    _log("validating required columns, labels, and finite feature values")
    _validate_frame(df)

    _log("converting feature columns to numeric dtypes")
    for feature in BINARY_FEATURE_ORDER:
        df[feature] = pd.to_numeric(df[feature], errors="raise")
    df[LABEL_COLUMN] = pd.to_numeric(df[LABEL_COLUMN], errors="raise").astype("int8")

    distribution = _distribution_report(df)
    _log(f"label_counts={distribution['label_counts']}")
    _log(f"attack_categories={len(distribution['attack_counts']):,}")
    if args.preflight_only:
        _log("preflight complete; stopping before split/training")
        return 0

    _log("creating stratified train/validation/test split")
    train_df, val_df, test_df = _stratified_split(
        df=df,
        val_size=args.val_size,
        test_size=args.test_size,
        seed=args.seed,
    )
    _log(
        "stratified split rows="
        f"train:{len(train_df):,} validation:{len(val_df):,} test:{len(test_df):,}"
    )
    _log("building time-ordered split diagnostics")
    time_diagnostics = _time_split_diagnostics(df, args.val_size, args.test_size)

    if args.allow_downsample:
        _log("downsampling training split because --allow-downsample was set")
        train_df = _downsample_train(
            train_df,
            benign_to_attack_ratio=args.benign_to_attack_ratio,
            seed=args.seed,
        )

    _log("fitting categorical encoders on training split")
    categorical_mappings = _fit_categorical_mappings(train_df)
    _log("materializing X/y matrices")
    x_train = _make_x(train_df, categorical_mappings)
    y_train = train_df[LABEL_COLUMN].to_numpy()
    x_val = _make_x(val_df, categorical_mappings)
    y_val = val_df[LABEL_COLUMN].to_numpy()
    x_test = _make_x(test_df, categorical_mappings)
    y_test = test_df[LABEL_COLUMN].to_numpy()

    neg = int((y_train == 0).sum())
    pos = int((y_train == 1).sum())
    if pos == 0:
        raise ValueError("training split has zero attack rows")
    scale_pos_weight = neg / pos
    _log(f"scale_pos_weight={scale_pos_weight:.6f} neg={neg:,} pos={pos:,}")

    _log(
        "starting XGBoost training "
        f"device={args.device} n_estimators={args.n_estimators} max_depth={args.max_depth}"
    )
    model = xgb.XGBClassifier(
        objective="binary:logistic",
        eval_metric=["aucpr", "auc", "logloss"],
        tree_method="hist",
        device=args.device,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        learning_rate=args.learning_rate,
        subsample=args.subsample,
        colsample_bytree=args.colsample_bytree,
        scale_pos_weight=scale_pos_weight,
        random_state=args.seed,
        n_jobs=-1,
        early_stopping_rounds=args.early_stopping_rounds,
    )
    model.fit(x_train, y_train, eval_set=[(x_val, y_val)], verbose=args.xgb_verbose)
    _log("training complete")

    _log("predicting validation and test probabilities")
    val_prob = model.predict_proba(x_val)[:, 1]
    test_prob = model.predict_proba(x_test)[:, 1]
    _log("selecting routing thresholds from validation split")
    thresholds = _select_thresholds(
        y_true=y_val,
        prob=val_prob,
        max_dismiss_attack_rate=args.max_dismiss_attack_rate,
        ideal_dismiss_attack_rate=args.ideal_dismiss_attack_rate,
        min_alert_precision=args.min_alert_precision,
    )

    metrics = {
        "distribution": distribution,
        "stratified_split": {
            "train": _split_report(train_df),
            "validation": _split_report(val_df),
            "test": _split_report(test_df),
        },
        "time_split_diagnostics": time_diagnostics,
        "training": {
            "downsampled": bool(args.allow_downsample),
            "scale_pos_weight": scale_pos_weight,
            "seed": args.seed,
            "device": args.device,
            "n_estimators": args.n_estimators,
            "best_iteration": getattr(model, "best_iteration", None),
            "best_score": getattr(model, "best_score", None),
        },
        "validation": _binary_metrics(
            y_val,
            val_prob,
            thresholds,
            roc_auc_score,
            average_precision_score,
            precision_recall_fscore_support,
            confusion_matrix,
        ),
        "test": _binary_metrics(
            y_test,
            test_prob,
            thresholds,
            roc_auc_score,
            average_precision_score,
            precision_recall_fscore_support,
            confusion_matrix,
        ),
    }

    _log("writing model, metadata, metrics, and thresholds")
    model_path = output_dir / f"{args.model_name}.json"
    metadata_path = output_dir / f"{args.model_name}_metadata.json"
    metrics_path = output_dir / f"{args.model_name}_metrics.json"
    thresholds_path = output_dir / f"{args.model_name}_thresholds.json"

    model.save_model(model_path)
    _write_json(
        metadata_path,
        {
            **binary_feature_contract().to_dict(),
            "categorical_encoders": categorical_mappings,
            "categorical_mappings": categorical_mappings,
            "training_dataset": str(input_path),
            "model_file": model_path.name,
        },
    )
    _write_json(metrics_path, metrics)
    _write_json(thresholds_path, thresholds)

    print(f"saved_model={model_path}")
    print(f"saved_metadata={metadata_path}")
    print(f"saved_metrics={metrics_path}")
    print(f"saved_thresholds={thresholds_path}")
    _log("done")
    return 0


def _log(message: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}", flush=True)


def _require_training_dependencies(preflight_only: bool) -> None:
    missing: list[str] = []
    modules = (
        ("numpy", "pandas")
        if preflight_only
        else ("numpy", "pandas", "sklearn", "xgboost")
    )
    for module in modules:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    if missing:
        raise SystemExit(
            "Missing ML dependencies: "
            + ", ".join(missing)
            + ". Install them on the GPU machine with: "
            + "python -m pip install -r requirements-ml.txt"
        )


def _validate_frame(df: Any) -> None:
    expected = {TIME_COLUMN, *BINARY_FEATURE_ORDER, LABEL_COLUMN, ATTACK_COLUMN}
    missing = sorted(expected - set(df.columns))
    if missing:
        raise ValueError(f"dataset is missing required columns: {missing}")
    if df.empty:
        raise ValueError("dataset is empty")

    labels = set(df[LABEL_COLUMN].dropna().astype(str).unique())
    if labels != {"0", "1"}:
        raise ValueError(f"expected Label values {{0, 1}}, got {sorted(labels)}")

    nonfinite_columns = []
    for feature in BINARY_FEATURE_ORDER:
        values = df[feature]
        if values.isna().any():
            nonfinite_columns.append(feature)
            continue
        numeric = values.astype("float64")
        if not numeric.map(math.isfinite).all():
            nonfinite_columns.append(feature)
    if nonfinite_columns:
        raise ValueError(
            "non-finite feature values found; do not train silently: "
            + ", ".join(nonfinite_columns)
        )


def _distribution_report(df: Any) -> dict[str, Any]:
    return {
        "rows": int(len(df)),
        "label_counts": _value_counts(df[LABEL_COLUMN]),
        "attack_counts": _value_counts(df[ATTACK_COLUMN]),
    }


def _stratified_split(df: Any, val_size: float, test_size: float, seed: int) -> tuple[Any, Any, Any]:
    from sklearn.model_selection import train_test_split

    train_val_df, test_df = train_test_split(
        df,
        test_size=test_size,
        random_state=seed,
        stratify=df[ATTACK_COLUMN],
    )
    relative_val_size = val_size / (1.0 - test_size)
    train_df, val_df = train_test_split(
        train_val_df,
        test_size=relative_val_size,
        random_state=seed,
        stratify=train_val_df[ATTACK_COLUMN],
    )
    return train_df, val_df, test_df


def _time_split_diagnostics(df: Any, val_size: float, test_size: float) -> dict[str, Any]:
    sorted_df = df.sort_values(TIME_COLUMN)
    total = len(sorted_df)
    train_end = int(total * (1.0 - val_size - test_size))
    val_end = int(total * (1.0 - test_size))
    splits = {
        "train": sorted_df.iloc[:train_end],
        "validation": sorted_df.iloc[train_end:val_end],
        "test": sorted_df.iloc[val_end:],
    }
    reports = {name: _split_report(split) for name, split in splits.items()}
    all_attacks = set(df[ATTACK_COLUMN].unique())
    for name, split in splits.items():
        missing_attacks = sorted(all_attacks - set(split[ATTACK_COLUMN].unique()))
        reports[name]["missing_attack_categories"] = missing_attacks

    train_categories = set(splits["train"][ATTACK_COLUMN].unique())
    validation_categories = set(splits["validation"][ATTACK_COLUMN].unique())
    test_categories = set(splits["test"][ATTACK_COLUMN].unique())
    train_only = sorted(train_categories - validation_categories - test_categories)
    test_only = sorted(test_categories - train_categories - validation_categories)
    warnings = []
    for split_name, report in reports.items():
        missing_non_benign = [
            attack for attack in report["missing_attack_categories"] if attack != "Benign"
        ]
        if missing_non_benign:
            warnings.append(
                f"{split_name} is missing {len(missing_non_benign)} attack categories"
            )
    if train_only or test_only:
        warnings.append(
            "time split category distribution differs from stratified split; "
            "use time split as distribution-shift diagnostics only"
        )
    return {
        **reports,
        "categories_in_train_only": train_only,
        "categories_in_test_only": test_only,
        "warning": "; ".join(warnings) if warnings else "",
    }


def _downsample_train(df: Any, benign_to_attack_ratio: float, seed: int) -> Any:
    import pandas as pd

    attack_df = df[df[LABEL_COLUMN] == 1]
    benign_df = df[df[LABEL_COLUMN] == 0]
    target_benign = min(len(benign_df), int(len(attack_df) * benign_to_attack_ratio))
    sampled_benign = benign_df.sample(n=target_benign, random_state=seed)
    return pd.concat(
        [attack_df.sample(frac=1.0, random_state=seed), sampled_benign],
        ignore_index=True,
    ).sample(frac=1.0, random_state=seed)


def _fit_categorical_mappings(df: Any) -> dict[str, dict[str, int]]:
    mappings: dict[str, dict[str, int]] = {}
    for feature in CATEGORICAL_FEATURES:
        values = sorted(str(value) for value in df[feature].unique())
        mappings[feature] = {value: index for index, value in enumerate(values)}
    return mappings


def _make_x(df: Any, categorical_mappings: dict[str, dict[str, int]]) -> Any:
    import numpy as np

    x = df[BINARY_FEATURE_ORDER].copy()
    for feature, mapping in categorical_mappings.items():
        x[feature] = x[feature].astype(str).map(mapping).fillna(-1).astype("int32")
    x = x.astype("float32")
    if not np.isfinite(x.to_numpy()).all():
        raise ValueError("non-finite values appeared after feature encoding")
    return x


def _select_thresholds(
    y_true: Any,
    prob: Any,
    max_dismiss_attack_rate: float,
    ideal_dismiss_attack_rate: float,
    min_alert_precision: float,
) -> dict[str, Any]:
    import numpy as np

    y_true = np.asarray(y_true)
    prob = np.asarray(prob)
    total_attacks = max(1, int((y_true == 1).sum()))

    low_candidates = np.linspace(0.01, 0.50, 100)
    selected_low = 0.0
    low_detail = {}
    for threshold in low_candidates:
        dismissed = prob < threshold
        dismissed_attacks = int(((y_true == 1) & dismissed).sum())
        attack_leak_rate = dismissed_attacks / total_attacks
        if attack_leak_rate <= max_dismiss_attack_rate:
            selected_low = float(threshold)
            low_detail = {
                "dismissed": int(dismissed.sum()),
                "dismissed_attacks": dismissed_attacks,
                "attack_leak_rate": attack_leak_rate,
            }

    high_candidates = np.linspace(0.70, 0.999, 120)
    selected_high = 1.0
    high_detail = {}
    for threshold in high_candidates:
        alerted = prob > threshold
        alert_count = int(alerted.sum())
        if alert_count == 0:
            continue
        true_alerts = int(((y_true == 1) & alerted).sum())
        precision = true_alerts / alert_count
        if precision >= min_alert_precision:
            selected_high = float(threshold)
            high_detail = {
                "alerted": alert_count,
                "true_alerts": true_alerts,
                "false_alerts": alert_count - true_alerts,
                "alert_precision": precision,
            }
            break

    return {
        "low_threshold": selected_low,
        "high_threshold": selected_high,
        "max_dismiss_attack_rate": max_dismiss_attack_rate,
        "ideal_dismiss_attack_rate": ideal_dismiss_attack_rate,
        "min_alert_precision": min_alert_precision,
        "target_policy": {
            "primary": (
                "Select the highest low_threshold that keeps validation "
                "auto_dismiss attack leak rate <= max_dismiss_attack_rate."
            ),
            "ideal": (
                "Report whether validation auto_dismiss attack leak rate also "
                "meets ideal_dismiss_attack_rate; do not fail training solely "
                "because the ideal target is missed."
            ),
        },
        "selection_details": {
            "low": low_detail,
            "high": high_detail,
        },
    }


def _binary_metrics(
    y_true: Any,
    prob: Any,
    thresholds: dict[str, Any],
    roc_auc_score: Any,
    average_precision_score: Any,
    precision_recall_fscore_support: Any,
    confusion_matrix: Any,
) -> dict[str, Any]:
    y_pred = (prob >= 0.5).astype("int8")
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true,
        y_pred,
        average="binary",
        zero_division=0,
    )
    return {
        "roc_auc": float(roc_auc_score(y_true, prob)),
        "pr_auc": float(average_precision_score(y_true, prob)),
        "precision_at_0_5": float(precision),
        "recall_at_0_5": float(recall),
        "f1_at_0_5": float(f1),
        "confusion_matrix_at_0_5": confusion_matrix(y_true, y_pred).tolist(),
        "routing": _routing_metrics(y_true, prob, thresholds),
    }


def _routing_metrics(y_true: Any, prob: Any, thresholds: dict[str, Any]) -> dict[str, Any]:
    import numpy as np

    y_true = np.asarray(y_true)
    prob = np.asarray(prob)
    low = float(thresholds["low_threshold"])
    high = float(thresholds["high_threshold"])
    dismiss = prob < low
    alert = prob > high
    tier1 = ~(dismiss | alert)
    total = len(y_true)
    total_attacks = max(1, int((y_true == 1).sum()))
    alert_count = int(alert.sum())
    true_alerts = int(((y_true == 1) & alert).sum())
    dismissed_attacks = int(((y_true == 1) & dismiss).sum())
    return {
        "auto_dismiss_count": int(dismiss.sum()),
        "auto_dismiss_rate": int(dismiss.sum()) / total,
        "auto_dismiss_attack_count": dismissed_attacks,
        "auto_dismiss_attack_leak_rate": dismissed_attacks / total_attacks,
        "auto_alert_count": alert_count,
        "auto_alert_rate": alert_count / total,
        "auto_alert_true_positive_count": true_alerts,
        "auto_alert_false_positive_count": alert_count - true_alerts,
        "auto_alert_precision": true_alerts / alert_count if alert_count else 0.0,
        "tier1_llm_count": int(tier1.sum()),
        "tier1_llm_rate": int(tier1.sum()) / total,
    }


def _split_report(df: Any) -> dict[str, Any]:
    return {
        "rows": int(len(df)),
        "label_counts": _value_counts(df[LABEL_COLUMN]),
        "attack_counts": _value_counts(df[ATTACK_COLUMN]),
        "time_min": int(df[TIME_COLUMN].min()) if len(df) else None,
        "time_max": int(df[TIME_COLUMN].max()) if len(df) else None,
    }


def _value_counts(series: Any) -> dict[str, int]:
    return {str(key): int(value) for key, value in series.value_counts().sort_index().items()}


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
