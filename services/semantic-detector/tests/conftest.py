import sys
from pathlib import Path
from types import ModuleType

import numpy as np
import pytest

APP_DIR = Path(__file__).resolve().parents[2] / "app"
if not APP_DIR.exists():
    APP_DIR = Path(__file__).resolve().parents[2] / "services" / "semantic-detector" / "app"
if not APP_DIR.exists():
    # The installed test directory is services/semantic-detector/tests.
    APP_DIR = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_DIR))

# Tests inject their own model. Importing the service must not download BGE.
try:
    import sentence_transformers
except ImportError:
    stub = ModuleType("sentence_transformers")
    stub.SentenceTransformer = type("SentenceTransformer", (), {})
    sys.modules["sentence_transformers"] = stub

CATEGORIES = [
    "prompt_injection",
    "jailbreak",
    "role_manipulation",
    "system_prompt_extraction",
]
PREFIX = "Represent this sentence for searching relevant passages: "

@pytest.fixture
def settings():
    return {
        "service": {"name": "semantic-detector", "version": "0.1.0", "host": "127.0.0.1", "port": 8001},
        "model": {"provider": "sentence-transformers", "name": "BAAI/bge-base-en-v1.5", "device": "cpu", "batch_size": 32, "normalize_embeddings": True, "reference_prefix": "", "query_prefix": PREFIX},
        "references": {"source_path": "unused", "embeddings_path": "unused", "manifest_path": "unused", "preload_on_startup": True, "use_cached_embeddings": False, "verify_integrity": True, "expected_sha256": "0" * 64},
        "scoring": {"strategy": "category_topk_mean", "top_k": 3, "supported_categories": CATEGORIES, "benign_comparison": "global_topk_mean", "thresholds": {"similarity": 0.5673961877822876, "margin": -0.0007279515266418457, "support": None}},
        "input": {"supported_artifacts": ["user_input", "model_output"], "max_character_bytes": 16384, "reject_empty_text": True},
        "response": {"include_category_scores": True, "include_reference_ids": True, "max_evidence_references": 5, "include_reference_text": False},
        "logging": {"level": "INFO", "structured": False, "log_artifact_text": False, "log_request_id": True, "log_processing_time": True},
    }

@pytest.fixture
def records_and_embeddings():
    # 3 references per attack category, plus 3 benign references.
    records = []
    vectors = []
    for index, category in enumerate(CATEGORIES):
        for n in range(3):
            records.append({"reference_id": f"M-{index}-{n}", "label": "malicious", "category": category, "text": f"sample {index}-{n}"})
            vector = np.zeros(5, dtype=np.float32)
            vector[index] = 1.0
            vectors.append(vector)
    for n in range(3):
        records.append({"reference_id": f"B-{n}", "label": "benign", "category": "benign", "text": "benign sample"})
        vectors.append(np.array([0., 0., 0., 0., 1.], dtype=np.float32))
    return records, np.array(vectors, dtype=np.float32)

class FakeTokenizer:
    def encode(self, text, add_special_tokens=True, truncation=False):
        return list(range(len(text.split()) + (2 if add_special_tokens else 0)))

class FakeModel:
    def __init__(self, embedding=None):
        self.embedding = np.array(embedding if embedding is not None else [0.8, 0, 0, 0, 0.6], dtype=np.float32)
        self.tokenizer = FakeTokenizer()
        self.max_seq_length = 512
        self.calls = 0
        self.last_text = None

    def get_sentence_embedding_dimension(self):
        return 5

    def encode(self, text, **kwargs):
        self.calls += 1
        self.last_text = text
        return self.embedding.copy()

@pytest.fixture
def fake_model():
    return FakeModel()

@pytest.fixture
def store(records_and_embeddings, settings):
    from reference_store import ReferenceStore
    records, embeddings = records_and_embeddings
    return ReferenceStore(records, embeddings, settings["scoring"])

@pytest.fixture
def scorer(store, fake_model, settings):
    from scorer import SemanticScorer
    return SemanticScorer(fake_model, store, settings["model"], settings["scoring"], settings["input"], settings["response"])
