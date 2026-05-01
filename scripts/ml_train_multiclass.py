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


def _local_deps_are_usable() -> bool:
    if sys.platform == "win32":
        return True
    pandas_init = LOCAL_DEPS / "pandas" / "__init__.py"
    if pandas_init.exists() and "os.add_dll_directory" in pandas_init.read_text(
        encoding="utf-8",
        errors="ignore",
    ):
        return False
    return True


try:
    if LOCAL_DEPS_SENTINEL.is_file() and _local_deps_are_usable():
        with LOCAL_DEPS_SENTINEL.open("rb"):
            pass
        if str(LOCAL_DEPS) not in sys.path:
            sys.path.insert(0, str(LOCAL_DEPS))
except OSError:
    pass
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from soc.ml.features import (  # noqa: E402
    ATTACK_HINT_CLASS_LABELS,
    ATTACK_HINT_LABEL_MAP,
    BINARY_FEATURE_ORDER,
    CATEGORICAL_FEATURES,
    RANDOM_SEED,
    attack_hint_label,
    binary_feature_contract,
)


LABEL_COLUMN = "Label"
ATTACK_COLUMN = "Attack"
TIME_COLUMN = "FLOW_START_MILLISECONDS"
HINT_COLUMN = "attack_hint"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train the CICIDS2018 multiclass XGBoost attack-family hint model."
    )
    parser.add_argument("--input", default="Dataset/NF-CICIDS2018-v3.csv")
    parser.add_argument("--output-dir", default="output/models")
    parser.add_argument("--model-name", default="xgb_attack_hint_v1")
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    parser.add_argument("--val-size", type=float, default=0.15)
    parser.add_argument("--test-size", type=float, default=0.15)
    parser.add_argument("--n-estimators", type=int, default=700)
    parser.add_argument("--max-depth", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=0.08)
    parser.add_argument("--subsample", type=float, default=0.85)
    parser.add_argument("--colsample-bytree", type=float, default=0.85)
    parser.add_argument("--early-stopping-rounds", type=int, default=40)
    parser.add_argument("--xgb-verbose", type=int, default=25)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--device", default="cuda", choices=["cuda", "cpu"])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _require_training_dependencies(preflight_only=args.preflight_only)

    import pandas as pd
    if not args.preflight_only:
        import xgboost as xgb
        from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    usecols = [TIME_COLUMN, *BINARY_FEATURE_ORDER, LABEL_COLUMN, ATTACK_COLUMN]
    _log(f"reading dataset: {input_path}")
    df = pd.read_csv(input_path, usecols=usecols)
    _log(f"loaded rows={len(df):,} cols={len(df.columns):,}")
    _validate_frame(df)
    for feature in BINARY_FEATURE_ORDER:
        df[feature] = pd.to_numeric(df[feature], errors="raise")
    df[LABEL_COLUMN] = pd.to_numeric(df[LABEL_COLUMN], errors="raise").astype("int8")

    attack_df = prepare_attack_hint_frame(df)
    distribution = _distribution_report(attack_df)
    _log(f"attack hint rows={len(attack_df):,}")
    _log(f"hint_counts={distribution['hint_counts']}")
    if args.preflight_only:
        _log("preflight complete; stopping before split/training")
        return 0

    train_df, val_df, test_df = _stratified_split(
        attack_df,
        val_size=args.val_size,
        test_size=args.test_size,
        seed=args.seed,
    )
    categorical_mappings = _fit_categorical_mappings(train_df)
    x_train = _make_x(train_df, categorical_mappings)
    y_train = _encode_labels(train_df[HINT_COLUMN])
    x_val = _make_x(val_df, categorical_mappings)
    y_val = _encode_labels(val_df[HINT_COLUMN])
    x_test = _make_x(test_df, categorical_mappings)
    y_test = _encode_labels(test_df[HINT_COLUMN])

    _log(
        "starting XGBoost multiclass training "
        f"device={args.device} classes={len(ATTACK_HINT_CLASS_LABELS)}"
    )
    model = xgb.XGBClassifier(
        objective="multi:softprob",
        num_class=len(ATTACK_HINT_CLASS_LABELS),
        eval_metric=["mlogloss", "merror"],
        tree_method="hist",
        device=args.device,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        learning_rate=args.learning_rate,
        subsample=args.subsample,
        colsample_bytree=args.colsample_bytree,
        random_state=args.seed,
        n_jobs=-1,
        early_stopping_rounds=args.early_stopping_rounds,
    )
    model.fit(x_train, y_train, eval_set=[(x_val, y_val)], verbose=args.xgb_verbose)
    _log("training complete")

    val_pred = model.predict(x_val)
    test_pred = model.predict(x_test)
    metrics = {
        "distribution": distribution,
        "class_labels": ATTACK_HINT_CLASS_LABELS,
        "stratified_split": {
            "train": _split_report(train_df),
            "validation": _split_report(val_df),
            "test": _split_report(test_df),
        },
        "training": {
            "seed": args.seed,
            "device": args.device,
            "n_estimators": args.n_estimators,
            "best_iteration": getattr(model, "best_iteration", None),
            "best_score": getattr(model, "best_score", None),
        },
        "validation": _multiclass_metrics(
            y_val,
            val_pred,
            accuracy_score,
            classification_report,
            confusion_matrix,
        ),
        "test": _multiclass_metrics(
            y_test,
            test_pred,
            accuracy_score,
            classification_report,
            confusion_matrix,
        ),
    }

    model_path = output_dir / f"{args.model_name}.json"
    metadata_path = output_dir / f"{args.model_name}_metadata.json"
    metrics_path = output_dir / f"{args.model_name}_metrics.json"

    model.save_model(model_path)
    _write_json(
        metadata_path,
        {
            **binary_feature_contract().to_dict(),
            "categorical_encoders": categorical_mappings,
            "categorical_mappings": categorical_mappings,
            "class_labels": ATTACK_HINT_CLASS_LABELS,
            "label_to_index": {
                label: index for index, label in enumerate(ATTACK_HINT_CLASS_LABELS)
            },
            "attack_hint_label_map": dict(ATTACK_HINT_LABEL_MAP),
            "training_dataset": str(input_path),
            "model_file": model_path.name,
        },
    )
    _write_json(metrics_path, metrics)

    print(f"saved_model={model_path}")
    print(f"saved_metadata={metadata_path}")
    print(f"saved_metrics={metrics_path}")
    _log("done")
    return 0


def prepare_attack_hint_frame(df: Any) -> Any:
    attack_df = df[df[LABEL_COLUMN].astype(int) == 1].copy()
    if attack_df.empty:
        raise ValueError("dataset has no attack rows for multiclass hint training")
    attack_df[HINT_COLUMN] = attack_df[ATTACK_COLUMN].map(attack_hint_label)
    unknown = sorted(str(value) for value in attack_df.loc[attack_df[HINT_COLUMN].isna(), ATTACK_COLUMN].unique())
    if unknown:
        raise ValueError(f"unmapped attack labels for attack hint training: {unknown}")
    return attack_df


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
    if not labels.issubset({"0", "1"}):
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
        raise ValueError("non-finite feature values found: " + ", ".join(nonfinite_columns))


def _distribution_report(df: Any) -> dict[str, Any]:
    return {
        "rows": int(len(df)),
        "hint_counts": _value_counts(df[HINT_COLUMN]),
        "attack_counts": _value_counts(df[ATTACK_COLUMN]),
    }


def _stratified_split(df: Any, val_size: float, test_size: float, seed: int) -> tuple[Any, Any, Any]:
    from sklearn.model_selection import train_test_split

    train_val_df, test_df = train_test_split(
        df,
        test_size=test_size,
        random_state=seed,
        stratify=df[HINT_COLUMN],
    )
    relative_val_size = val_size / (1.0 - test_size)
    train_df, val_df = train_test_split(
        train_val_df,
        test_size=relative_val_size,
        random_state=seed,
        stratify=train_val_df[HINT_COLUMN],
    )
    return train_df, val_df, test_df


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


def _encode_labels(series: Any) -> Any:
    import numpy as np

    label_to_index = {label: index for index, label in enumerate(ATTACK_HINT_CLASS_LABELS)}
    return np.asarray([label_to_index[str(value)] for value in series], dtype="int32")


def _multiclass_metrics(
    y_true: Any,
    y_pred: Any,
    accuracy_score: Any,
    classification_report: Any,
    confusion_matrix: Any,
) -> dict[str, Any]:
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "classification_report": classification_report(
            y_true,
            y_pred,
            labels=list(range(len(ATTACK_HINT_CLASS_LABELS))),
            target_names=ATTACK_HINT_CLASS_LABELS,
            output_dict=True,
            zero_division=0,
        ),
        "confusion_matrix": confusion_matrix(
            y_true,
            y_pred,
            labels=list(range(len(ATTACK_HINT_CLASS_LABELS))),
        ).tolist(),
    }


def _split_report(df: Any) -> dict[str, Any]:
    return {
        "rows": int(len(df)),
        "hint_counts": _value_counts(df[HINT_COLUMN]),
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
