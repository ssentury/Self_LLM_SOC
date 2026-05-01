from __future__ import annotations

import pytest

from scripts.ml_train_multiclass import prepare_attack_hint_frame


pd = pytest.importorskip("pandas")


def test_prepare_attack_hint_frame_uses_attack_rows_only() -> None:
    frame = pd.DataFrame(
        {
            "Label": [0, 1, 1],
            "Attack": ["Benign", "Bot", "SQL_Injection"],
            "FLOW_START_MILLISECONDS": [1, 2, 3],
        }
    )

    attack_frame = prepare_attack_hint_frame(frame)

    assert attack_frame["Attack"].tolist() == ["Bot", "SQL_Injection"]
    assert attack_frame["attack_hint"].tolist() == ["Bot", "WebAttack"]


def test_prepare_attack_hint_frame_rejects_unmapped_attack_labels() -> None:
    frame = pd.DataFrame(
        {
            "Label": [1],
            "Attack": ["NewAttack"],
            "FLOW_START_MILLISECONDS": [1],
        }
    )

    with pytest.raises(ValueError, match="unmapped attack labels"):
        prepare_attack_hint_frame(frame)
