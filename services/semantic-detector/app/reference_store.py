import logging

import numpy as np

logger = logging.getLogger(__name__)


class ReferenceStore:
    def __init__(self, reference_records: list[dict], reference_embeddings: np.ndarray, scoring_config: dict):
        self.reference_records = reference_records
        self.reference_embeddings = reference_embeddings
        self.top_k = scoring_config["top_k"]
        self.supported_categories = scoring_config["supported_categories"]

        self.category_indexes = {category: [] for category in self.supported_categories}
        self.benign_indexes = []
        self.reference_id_indexes = {}

        self._validate_and_index()

    def _validate_and_index(self):
        if not self.reference_records:
            raise ValueError("Reference corpus is empty")

        if not isinstance(self.reference_embeddings, np.ndarray):
            raise TypeError("Reference embeddings must be a NumPy array")

        if self.reference_embeddings.ndim != 2:
            raise ValueError("Reference embeddings must be a 2D matrix")

        if len(self.reference_records) != self.reference_embeddings.shape[0]:
            raise ValueError("Reference count does not match embedding rows")

        if not np.issubdtype(self.reference_embeddings.dtype, np.number):
            raise ValueError("Reference embeddings must contain numeric values")

        if not np.isfinite(self.reference_embeddings).all():
            raise ValueError("Reference embeddings contain NaN or infinite values")

        for index, record in enumerate(self.reference_records):
            if not isinstance(record, dict):
                raise ValueError(f"Invalid reference record at index {index}")

            reference_id = record.get("reference_id")
            label = record.get("label")
            category = record.get("category")

            if not isinstance(reference_id, str) or not reference_id.strip():
                raise ValueError(f"Invalid reference_id at index {index}")

            if reference_id in self.reference_id_indexes:
                raise ValueError(f"Duplicate reference_id: {reference_id}")

            self.reference_id_indexes[reference_id] = index

            if label == "malicious":
                if category not in self.category_indexes:
                    raise ValueError(f"Unsupported malicious category for {reference_id}: {category}")
                self.category_indexes[category].append(index)
            elif label == "benign":
                if category != "benign":
                    raise ValueError(f"Benign reference {reference_id} must have category 'benign'")
                self.benign_indexes.append(index)
            else:
                raise ValueError(f"Invalid reference label for {reference_id}: {label}")

        if len(self.benign_indexes) < self.top_k:
            raise ValueError(f"Need at least {self.top_k} benign references")

        for category, indexes in self.category_indexes.items():
            if len(indexes) < self.top_k:
                raise ValueError(f"Need at least {self.top_k} malicious references for {category}")

        logger.info(
            "Reference store ready: %d references, %d benign, %d malicious categories, embeddings shape %s",
            len(self.reference_records),
            len(self.benign_indexes),
            len(self.category_indexes),
            self.reference_embeddings.shape,
        )

    def get_reference(self, index: int) -> dict:
        return self.reference_records[index]

    def get_reference_by_id(self, reference_id: str) -> dict:
        return self.get_reference(self.reference_id_indexes[reference_id])

    def get_category_indexes(self, category: str) -> list[int]:
        return self.category_indexes[category]

    def get_benign_indexes(self) -> list[int]:
        return self.benign_indexes
