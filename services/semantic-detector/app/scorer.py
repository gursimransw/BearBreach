import logging
from time import perf_counter

import numpy as np

logger = logging.getLogger(__name__)


class SemanticScorer:
    def __init__(self, model, reference_store, model_config: dict, scoring_config: dict, input_config: dict | None = None, response_config: dict | None = None):
        self.model = model
        self.reference_store = reference_store
        self.query_prefix = model_config["query_prefix"]
        self.normalize_embeddings = model_config["normalize_embeddings"]
        self.top_k = scoring_config["top_k"]
        self.similarity_threshold = scoring_config["thresholds"]["similarity"]
        self.margin_threshold = scoring_config["thresholds"]["margin"]
        self.max_character_bytes = (input_config or {}).get("max_character_bytes", 16384)
        self.reject_empty_text = (input_config or {}).get("reject_empty_text", True)
        self.include_category_scores = (response_config or {}).get("include_category_scores", True)
        self.include_reference_ids = (response_config or {}).get("include_reference_ids", True)
        self.max_evidence_references = (response_config or {}).get("max_evidence_references", 5)

        if scoring_config["strategy"] != "category_topk_mean":
            raise ValueError("SemanticScorer currently supports only category_topk_mean")
        if scoring_config["benign_comparison"] != "global_topk_mean":
            raise ValueError("SemanticScorer requires global_topk_mean benign comparison")
        if not self.normalize_embeddings:
            raise ValueError("The frozen BGE scorer requires normalized embeddings")
        if self.top_k != reference_store.top_k:
            raise ValueError("Scorer top_k does not match the reference store")
        if self.query_prefix != "Represent this sentence for searching relevant passages: ":
            raise ValueError("BGE query prefix differs from the evaluated configuration")
        if reference_store.reference_embeddings.shape[1] != model.get_sentence_embedding_dimension():
            raise ValueError("Model and reference embedding dimensions do not match")

    def _top_k_score(self, similarities: np.ndarray, indexes: list[int]) -> tuple[float, list[int]]:
        ranked_indexes = sorted(indexes, key=lambda index: float(similarities[index]), reverse=True)
        selected_indexes = ranked_indexes[:self.top_k]
        score = float(np.mean(similarities[selected_indexes]))
        return score, selected_indexes

    def analyze(self, text: str) -> dict:
        if not isinstance(text, str):
            raise TypeError("Artifact text must be a string")
        if self.reject_empty_text and not text.strip():
            raise ValueError("Artifact text cannot be empty")
        if len(text.encode("utf-8")) > self.max_character_bytes:
            raise ValueError("Artifact exceeds max_character_bytes")

        query_text = self.query_prefix + text

        # Reject silent truncation: we have not evaluated chunking or truncation yet.
        tokenizer = self.model.tokenizer
        token_ids = tokenizer.encode(query_text, add_special_tokens=True, truncation=False)
        if len(token_ids) > self.model.max_seq_length:
            raise ValueError(
                f"Artifact has {len(token_ids)} tokens including prefix; "
                f"model limit is {self.model.max_seq_length}. Input was not scanned."
            )

        start = perf_counter()
        query_embedding = self.model.encode(
            query_text,
            normalize_embeddings=self.normalize_embeddings,
            convert_to_numpy=True,
            show_progress_bar=False,
        )
        if query_embedding.ndim != 1:
            raise ValueError("Expected one query embedding vector")

        similarities = self.reference_store.reference_embeddings @ query_embedding
        if not np.isfinite(similarities).all():
            raise ValueError("Similarity calculations produced invalid values")

        category_scores = {}
        category_indexes = {}
        for category in self.reference_store.supported_categories:
            score, indexes = self._top_k_score(
                similarities, self.reference_store.get_category_indexes(category)
            )
            category_scores[category] = score
            category_indexes[category] = indexes

        # Preserve configured category order to break equal-score ties consistently.
        candidate_category = max(self.reference_store.supported_categories, key=lambda category: category_scores[category])
        malicious_similarity = category_scores[candidate_category]
        benign_similarity, _ = self._top_k_score(
            similarities, self.reference_store.get_benign_indexes()
        )
        semantic_margin = malicious_similarity - benign_similarity
        detected = (
            malicious_similarity >= self.similarity_threshold
            and semantic_margin >= self.margin_threshold
        )

        result = {
            "detected": bool(detected),
            "predicted_category": candidate_category if detected else None,
            "category_candidate": candidate_category,
            "malicious_similarity": malicious_similarity,
            "benign_similarity": benign_similarity,
            "semantic_margin": semantic_margin,
            "scoring_strategy": "category_topk_mean",
            "processing_time_ms": round((perf_counter() - start) * 1000, 3),
        }
        if self.include_category_scores:
            result["category_scores"] = category_scores
        if self.include_reference_ids:
            result["matched_reference_ids"] = [
                self.reference_store.get_reference(index)["reference_id"]
                for index in category_indexes[candidate_category][:self.max_evidence_references]
            ]
        return result
