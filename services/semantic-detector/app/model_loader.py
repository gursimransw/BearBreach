
from config import load_config
from sentence_transformers import SentenceTransformer
import logging
import json
import hashlib
from pathlib import Path

logger = logging.getLogger(__name__)


def load_model(config_path: str, reference_corpus_path: str):

    config = load_config(config_path)

    model_name = config["model"]["name"]
    device = config["model"]["device"]
    embedding_normalization = config["model"]["normalize_embeddings"]
    batch_size = config["model"]["batch_size"]
    reference_prefix = config["model"]["reference_prefix"]

    expected_hash = config["references"]["expected_sha256"]
    verify_integrity = config["references"]["verify_integrity"]

    corpus_path = Path(reference_corpus_path)

    if not corpus_path.is_file():
        raise FileNotFoundError(
            f"Reference corpus not found: {corpus_path}"
        )
    # Verify the reference corpus has not changed

    if verify_integrity:

        with open(corpus_path, "rb") as file:
            actual_hash = hashlib.file_digest(
                file, "sha256"
            ).hexdigest()

        if actual_hash.lower() != expected_hash.lower():

            logger.error(
                "Reference corpus hash mismatch. Expected: %s, Actual: %s",
                expected_hash,
                actual_hash
            )

            raise ValueError(
                "Reference corpus integrity verification failed"
            )

        logger.info("Reference corpus hash verified successfully")

    # Load the reference corpus

    reference_records = []

    try:
        with open(reference_corpus_path, "r", encoding="utf-8") as file:

            for line_number, line in enumerate(file, start=1):

                line = line.strip()

                if not line:
                    continue

                try:
                    record = json.loads(line)

                except json.JSONDecodeError as error:
                    raise ValueError(
                        f"Invalid JSON on line {line_number}: {error}"
                    ) from error

                if not isinstance(record, dict):
                    raise ValueError(
                        f"Invalid reference record on line {line_number}"
                    )

                required_fields = [
                    "reference_id",
                    "text",
                    "label",
                    "category"
                ]

                for field in required_fields:
                    if field not in record:
                        raise ValueError(
                            f"Missing '{field}' on line {line_number}"
                        )

                if not isinstance(record["text"], str) or not record["text"].strip():
                    raise ValueError(
                        f"Invalid reference text on line {line_number}"
                    )

                if record["label"] not in ["malicious", "benign"]:
                    raise ValueError(
                        f"Invalid reference label on line {line_number}"
                    )

                reference_records.append(record)

    except Exception:
        logger.exception("Failed to load reference corpus")
        raise

    if not reference_records:
        raise ValueError("Reference corpus is empty")

    logger.info(
        "Loaded %d reference records",
        len(reference_records)
    )

    reference_texts = [
        reference_prefix + record["text"]
        for record in reference_records
    ]

    # Load the embedding model

    try:
        model = SentenceTransformer(
            model_name,
            device=device
        )

        logger.info(
            "Model %s initialized successfully",
            model_name
        )

    except Exception:
        logger.exception("Failed to initialize embedding model")
        raise

    # Generate embeddings for the reference corpus

    try:
        reference_embeddings = model.encode(
            reference_texts,
            normalize_embeddings=embedding_normalization,
            batch_size=batch_size,
            convert_to_numpy=True,
            show_progress_bar=True
        )

    except Exception:
        logger.exception("Failed to generate reference embeddings")
        raise

    if reference_embeddings.ndim != 2:
        raise ValueError("Invalid reference embedding matrix")

    if reference_embeddings.shape[0] != len(reference_records):
        raise ValueError(
            "Reference embedding count does not match corpus count"
        )

    logger.info(
        "Reference embeddings created successfully: %s",
        reference_embeddings.shape
    )

    return model, reference_records, reference_embeddings


print("services/semantic-detector/config/config.yaml","libraries/semantic-corpus/curated/references.jsonl")
