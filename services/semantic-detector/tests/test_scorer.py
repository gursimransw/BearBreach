import numpy as np
import pytest
from scorer import SemanticScorer
from conftest import PREFIX


def test_correct_top_three_mean_and_evidence(scorer, fake_model):
    result = scorer.analyze("Please analyze this")
    assert fake_model.calls == 1
    assert fake_model.last_text == PREFIX + "Please analyze this"
    assert result["category_candidate"] == "prompt_injection"
    assert result["predicted_category"] == "prompt_injection"
    assert result["detected"] is True
    assert result["malicious_similarity"] == pytest.approx(0.8)
    assert result["benign_similarity"] == pytest.approx(0.6)
    assert result["semantic_margin"] == pytest.approx(0.2)
    assert result["matched_reference_ids"] == ["M-0-0", "M-0-1", "M-0-2"]


def test_benign_scores_win(scorer, fake_model):
    fake_model.embedding = np.array([0.6, 0., 0., 0., 0.8], dtype=np.float32)
    result = scorer.analyze("benign")
    assert result["detected"] is False
    assert result["predicted_category"] is None
    assert result["category_candidate"] == "prompt_injection"
    assert result["semantic_margin"] == pytest.approx(-0.2)


def test_similarity_threshold_boundary(scorer, fake_model):
    fake_model.embedding = np.array([0.56, 0., 0., 0., 0.1], dtype=np.float32)
    assert scorer.analyze("borderline")["detected"] is False
    fake_model.embedding = np.array([0.58, 0., 0., 0., 0.1], dtype=np.float32)
    assert scorer.analyze("borderline")["detected"] is True


def test_empty_text_rejected_without_running_model(scorer, fake_model):
    with pytest.raises(ValueError, match="empty"):
        scorer.analyze("   ")
    assert fake_model.calls == 0


def test_bytes_limit_uses_utf8(scorer, fake_model):
    scorer.max_character_bytes = 3
    with pytest.raises(ValueError, match="max_character_bytes"):
        scorer.analyze("éé")
    assert fake_model.calls == 0


def test_long_input_rejected_before_encoding(scorer, fake_model):
    fake_model.max_seq_length = 5
    with pytest.raises(ValueError, match="not scanned"):
        scorer.analyze("word word word word")
    assert fake_model.calls == 0


def test_bad_scoring_strategy_rejected(store, fake_model, settings):
    settings["scoring"]["strategy"] = "global_max"
    with pytest.raises(ValueError, match="category_topk_mean"):
        SemanticScorer(fake_model, store, settings["model"], settings["scoring"])


def test_reference_and_model_dimensions_must_match(store, fake_model, settings):
    fake_model.get_sentence_embedding_dimension = lambda: 384
    with pytest.raises(ValueError, match="dimensions"):
        SemanticScorer(fake_model, store, settings["model"], settings["scoring"])
