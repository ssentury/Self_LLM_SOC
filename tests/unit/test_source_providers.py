from pathlib import Path

from soc.tier2.source_providers import YamlAssetInfoProvider, YamlPolicyInfoProvider


def test_yaml_provider_valid_dict(tmp_path: Path) -> None:
    yaml_file = tmp_path / "valid.yaml"
    yaml_file.write_text("assets:\n  - ip: 10.0.0.1\n", encoding="utf-8")
    
    provider = YamlAssetInfoProvider({"enabled": True, "path": str(yaml_file)})
    snapshot = provider.get_snapshot()
    
    assert snapshot.status == "used"
    assert snapshot.item_count == 1
    assert snapshot.error is None


def test_yaml_provider_invalid_list_root(tmp_path: Path) -> None:
    yaml_file = tmp_path / "invalid_list.yaml"
    yaml_file.write_text("- ip: 10.0.0.1\n- ip: 10.0.0.2\n", encoding="utf-8")
    
    provider = YamlAssetInfoProvider({"enabled": True, "path": str(yaml_file)})
    snapshot = provider.get_snapshot()
    
    assert snapshot.status == "error"
    assert snapshot.item_count == 0
    assert "YAML root must be a dictionary" in snapshot.error


def test_yaml_provider_invalid_scalar_root(tmp_path: Path) -> None:
    yaml_file = tmp_path / "invalid_scalar.yaml"
    yaml_file.write_text("just a string\n", encoding="utf-8")
    
    provider = YamlAssetInfoProvider({"enabled": True, "path": str(yaml_file)})
    snapshot = provider.get_snapshot()
    
    assert snapshot.status == "error"
    assert snapshot.item_count == 0
    assert "YAML root must be a dictionary" in snapshot.error


def test_yaml_provider_rejects_invalid_source_list_field(tmp_path: Path) -> None:
    yaml_file = tmp_path / "invalid_assets.yaml"
    yaml_file.write_text("assets: not-a-list\n", encoding="utf-8")

    provider = YamlAssetInfoProvider({"enabled": True, "path": str(yaml_file)})
    snapshot = provider.get_snapshot()

    assert snapshot.status == "error"
    assert snapshot.item_count == 0
    assert snapshot.error == "assets must be a list."


def test_yaml_provider_rejects_invalid_source_list_item(tmp_path: Path) -> None:
    yaml_file = tmp_path / "invalid_policy.yaml"
    yaml_file.write_text("elevated_risk_rules:\n  - string-rule\n", encoding="utf-8")

    provider = YamlPolicyInfoProvider({"enabled": True, "path": str(yaml_file)})
    snapshot = provider.get_snapshot()

    assert snapshot.status == "error"
    assert snapshot.item_count == 0
    assert snapshot.error == "elevated_risk_rules[0] must be a dictionary."


def test_yaml_provider_missing_file(tmp_path: Path) -> None:
    provider = YamlAssetInfoProvider({"enabled": True, "path": str(tmp_path / "missing.yaml")})
    snapshot = provider.get_snapshot()
    
    assert snapshot.status == "missing"
    assert snapshot.item_count == 0


def test_yaml_provider_disabled(tmp_path: Path) -> None:
    provider = YamlAssetInfoProvider({"enabled": False, "path": str(tmp_path / "missing.yaml")})
    snapshot = provider.get_snapshot()
    
    assert snapshot.status == "disabled"
    assert snapshot.item_count == 0
