import copy

import pytest
import yaml

from config import load_config


def test_valid_configuration_loads(tmp_path, settings):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(settings), encoding="utf-8")
    loaded = load_config(str(path))
    assert loaded["scoring"]["strategy"] == "category_topk_mean"


@pytest.mark.parametrize("section,key,value", [
    ("service", "port", 70000),
    ("model", "batch_size", -5),
    ("scoring", "top_k", 0),
    ("scoring", "benign_comparison", "unknown"),
    ("logging", "level", "VERBOSE"),
])
def test_invalid_values_are_rejected(tmp_path, settings, section, key, value):
    modified = copy.deepcopy(settings)
    modified[section][key] = value
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(modified), encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid configuration"):
        load_config(str(path))


def test_missing_required_section_is_rejected(tmp_path, settings):
    del settings["references"]
    path = tmp_path / "missing.yaml"
    path.write_text(yaml.safe_dump(settings), encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid configuration"):
        load_config(str(path))


def test_missing_yaml_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(str(tmp_path / "not-there.yaml"))
