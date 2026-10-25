import numpy as np
import pytest
from reference_store import ReferenceStore


def test_builds_indexes_and_preserves_record_alignment(store):
    assert store.reference_embeddings.shape == (15, 5)
    assert store.get_category_indexes("prompt_injection") == [0, 1, 2]
    assert store.get_benign_indexes() == [12, 13, 14]
    assert store.get_reference_by_id("M-2-1") is store.get_reference(7)


def test_rejects_wrong_embedding_count(records_and_embeddings, settings):
    records, embeddings = records_and_embeddings
    with pytest.raises(ValueError, match="Reference count"):
        ReferenceStore(records, embeddings[:-1], settings["scoring"])


def test_rejects_duplicate_ids(records_and_embeddings, settings):
    records, embeddings = records_and_embeddings
    records[1]["reference_id"] = records[0]["reference_id"]
    with pytest.raises(ValueError, match="Duplicate"):
        ReferenceStore(records, embeddings, settings["scoring"])


def test_rejects_non_finite_embeddings(records_and_embeddings, settings):
    records, embeddings = records_and_embeddings
    embeddings[0, 0] = np.nan
    with pytest.raises(ValueError, match="NaN"):
        ReferenceStore(records, embeddings, settings["scoring"])


def test_rejects_invalid_label_category(records_and_embeddings, settings):
    records, embeddings = records_and_embeddings
    records[0]["category"] = "unsupported_category"
    with pytest.raises(ValueError, match="Unsupported"):
        ReferenceStore(records, embeddings, settings["scoring"])


def test_rejects_insufficient_references(records_and_embeddings, settings):
    records, embeddings = records_and_embeddings
    settings["scoring"]["top_k"] = 4
    with pytest.raises(ValueError, match="at least"):
        ReferenceStore(records, embeddings, settings["scoring"])
