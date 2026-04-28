# GPU Training Handoff

This file is the instruction packet for the Codex session on the GPU workstation.
Do not improvise the feature list, excluded columns, split policy, or threshold policy
unless a local validation failure forces a change.

## Goal

Train the CICIDS2018 NetFlow v3 binary XGBoost router before wiring the trained
model back into the laptop project.

The binary model is the real-time cheap router:

```text
low attack probability  -> auto_dismiss
high attack probability -> auto_alert
middle band             -> tier1_llm
```

The model is not the final SOC verdict engine. Tier 2 context and Tier 1 LLM
remain responsible for context-aware judgment.

## Input Dataset

Expected file:

```text
Dataset/NF-CICIDS2018-v3.csv
```

If the dataset was unpacked as a BagIt directory, the local path may instead be:

```text
Dataset/NF-CICIDS2018-v3/data/NF-CICIDS2018-v3.csv
```

Expected rough shape:

```text
rows: 20,115,529
benign: 17,514,626
attack: 2,600,903
```

If these counts are very different, stop and report the mismatch before training.

## Fixed Feature Contract

Use the feature contract in:

```text
src/soc/ml/features.py
```

Do not add these excluded fields back into training:

```text
IPV4_SRC_ADDR
IPV4_DST_ADDR
FLOW_START_MILLISECONDS
FLOW_END_MILLISECONDS
Label
Attack
DNS_QUERY_ID
L4_SRC_PORT
```

Why:

- Raw IPs make the model memorize the CICIDS test network.
- Absolute timestamps leak the attack schedule.
- Label and Attack are ground truth.
- DNS_QUERY_ID is a random transaction identifier.
- L4_SRC_PORT is an ephemeral/tool artifact risk.

## Split Policy

Primary evaluation:

```text
stratified train / validation / test
```

Use this as the main model-quality and threshold-selection result.

Secondary diagnostics:

```text
time-ordered split
```

Use this only to expose CICIDS date/attack-schedule distribution shift. Do not
use time split as the main score because prior experiments showed attack
categories can disappear from one side of the split.

## Sampling Policy

Default:

```text
no downsampling
scale_pos_weight = negative_count / positive_count
```

Reason: prior experiments showed the full data can train on the GPU workstation,
and downsampling can distort probability calibration.

Only use `--allow-downsample` if the GPU workstation cannot train the full data.
If downsampling is used, validation and test must still keep natural distribution.

## Threshold Policy

Thresholds must be selected on the validation set, then frozen for test.

Primary target:

```text
auto_dismiss attack leak rate <= 1.0%
auto_alert precision >= 95%
```

Ideal best-effort target:

```text
auto_dismiss attack leak rate <= 0.5%
```

Prior experiments saw roughly `0.71%` attack leak in the `prob < 0.30`
region, so `0.1%` is too strict as a default pass/fail target. If the ideal
target is missed but the primary target is met, report it clearly instead of
declaring training failed.

The training script records:

```text
auto_dismiss_attack_leak_rate
auto_alert_precision
tier1_llm_rate
```

These routing metrics matter more than raw accuracy.

## SHAP Policy

Do not compute SHAP for every flow during real-time routing.

Runtime policy after model integration:

```text
auto_dismiss -> skip SHAP
auto_alert   -> skip SHAP by default; optional batch/report mode only
tier1_llm    -> compute SHAP top5 and pass to Tier 1
```

## Multiclass Hint Policy

Do not block binary training on multiclass. The multiclass attack-hint model is
needed for the final system, but it is a second model layered after the binary
router is stable.

Use this mapping later:

```text
DDoS:
  DDOS_attack-HOIC
  DDoS_attacks-LOIC-HTTP
  DDOS_attack-LOIC-UDP

DoS:
  DoS_attacks-Hulk
  DoS_attacks-SlowHTTPTest
  DoS_attacks-GoldenEye
  DoS_attacks-Slowloris

BruteForce:
  FTP-BruteForce
  SSH-Bruteforce

WebAttack:
  Brute_Force_-Web
  Brute_Force_-XSS
  SQL_Injection

Bot:
  Bot

Infiltration:
  Infilteration
```

## Environment Setup

On the GPU workstation:

```powershell
python -m pip install -r requirements-ml.txt
```

If the workstation uses a repo-local dependency folder instead of a virtualenv,
install with:

```powershell
python -m pip install -r requirements-ml.txt --target .ml_deps
```

`scripts/ml_train.py` automatically adds `.ml_deps` to `sys.path` when the
folder exists and is readable by the current process.

If using Docker on the GPU workstation, make sure the image installs
`requirements-ml.txt` and has NVIDIA container runtime available.

## Training Command

Run from the repository root:

```powershell
python scripts/ml_train.py `
  --input Dataset/NF-CICIDS2018-v3.csv `
  --output-dir output/models `
  --model-name xgb_binary_v1 `
  --device cuda
```

Run this first when preparing a new machine. It validates the dataset contract
and prints label/category counts, then stops before split/training:

```powershell
python scripts/ml_train.py `
  --input Dataset/NF-CICIDS2018-v3/data/NF-CICIDS2018-v3.csv `
  --output-dir output/models `
  --model-name xgb_binary_v1 `
  --device cuda `
  --preflight-only
```

During the full run, `scripts/ml_train.py` prints timestamped progress for CSV
loading, validation, splitting, encoding, training start/end, prediction,
threshold selection, and artifact writing. XGBoost evaluation progress is
printed every 25 boosting rounds by default. Change it with:

```powershell
--xgb-verbose 10
```

Fallback CPU dry run is allowed only for debugging with tiny samples:

```powershell
python scripts/ml_train.py --input <tiny_sample.csv> --device cpu
```

Do not train the production model on a tiny sample.

## Expected Outputs

Copy these files back to the laptop repository:

```text
output/models/xgb_binary_v1.json
output/models/xgb_binary_v1_metadata.json
output/models/xgb_binary_v1_metrics.json
output/models/xgb_binary_v1_thresholds.json
```

These are plain files and can be moved by USB, cloud drive, or git-lfs/artifact
download. The model file alone is not enough; metadata and thresholds are
required for safe inference.

If the GPU workstation repository does not already contain the latest prep
files, copy these files to the same paths before training:

```text
src/soc/ml/features.py
scripts/ml_train.py
requirements-ml.txt
Knowledge/GPU_TRAINING_HANDOFF.md
```

Copying only this handoff document is not enough unless the GPU repo already has
the matching `features.py` and `ml_train.py`.

## Must-Check Before Returning

Open `output/models/xgb_binary_v1_metrics.json` and verify:

```text
stratified split exists
time split diagnostics exists
time split diagnostics includes categories_in_train_only / categories_in_test_only
auto_dismiss_attack_leak_rate <= 1.0%, or clearly report failure
auto_dismiss_attack_leak_rate <= 0.5%, or clearly report that only the ideal target failed
auto_alert_precision >= target, or clearly report failure
feature_order in metadata matches src/soc/ml/features.py
feature_types in metadata matches src/soc/ml/features.py
categorical_encoders exists in metadata
```

If any of these fail, do not claim the model is ready.
