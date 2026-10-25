r"""BearBreach Semantic Detector: ONE-TIME held-out test evaluation.

Uses the FROZEN BGE + category_topk_mean configuration selected on validation.
There is NO threshold search, tuning, or model selection in this script.

PowerShell (run from BearBreach repository root):
  python libraries\semantic-corpus\dataset_operations\evaluate_final_test.py `
    --references libraries\semantic-corpus\curated\references.jsonl `
    --test libraries\semantic-corpus\evaluation\test.jsonl `
    --config libraries\semantic-corpus\dataset_operations\semantic_detector_frozen_config.json `
    --output-dir experiments\semantic-detection\final-test

Requires: pip install numpy sentence-transformers
"""

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
from statistics import mean, median
from time import perf_counter

import numpy as np
from sentence_transformers import SentenceTransformer


CATEGORIES = (
    "prompt_injection",
    "jailbreak",
    "role_manipulation",
    "system_prompt_extraction",
)


# ============================================================
# FILE HELPERS (adapted from the original evaluation script)
# ============================================================

def load_jsonl(file_path: Path):
    records = []
    with file_path.open("r", encoding="utf-8-sig") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{file_path}:{line_number}: Invalid JSON: {error}") from error
            if not isinstance(record, dict):
                raise ValueError(f"{file_path}:{line_number}: Expected JSON object")
            records.append(record)
    if not records:
        raise ValueError(f"Dataset is empty: {file_path}")
    return records


def save_jsonl(records, file_path: Path):
    with file_path.open("w", encoding="utf-8") as file:
        for record in records:
            file.write(json.dumps(record, ensure_ascii=False) + "\n")


def save_json(data, file_path: Path):
    with file_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)


def sha256_file(file_path: Path):
    digest = hashlib.sha256()
    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_divide(numerator, denominator):
    return numerator / denominator if denominator else 0.0


# ============================================================
# FROZEN CONFIGURATION AND DATA VALIDATION
# ============================================================

def load_frozen_config(config_path: Path):
    with config_path.open("r", encoding="utf-8") as file:
        config = json.load(file)

    # Fail closed rather than quietly evaluating a different experiment.
    if config.get("model_name") != "BAAI/bge-base-en-v1.5":
        raise ValueError("Frozen configuration must use the selected BGE model")
    if config.get("strategy") != "category_topk_mean":
        raise ValueError("Frozen configuration must use category_topk_mean")
    if config.get("input_format") != "bge_query_instruction":
        raise ValueError("BGE query formatting does not match the validation experiment")
    if config.get("top_k") != 3:
        raise ValueError("Frozen top_k must be 3")
    if config.get("support_threshold") is not None:
        raise ValueError("Neighbor support must be disabled for category_topk_mean")
    if config.get("expected_test_count") != 40:
        raise ValueError("Expected test dataset size must be 40")
    for name in ("similarity_threshold", "margin_threshold"):
        value = config.get(name)
        if not isinstance(value, (int, float)) or not np.isfinite(value):
            raise ValueError(f"Invalid frozen {name}")
    if not isinstance(config.get("reference_sha256"), str):
        raise ValueError("Frozen reference_sha256 is required")
    if not isinstance(config.get("validation_sha256"), str):
        raise ValueError("Frozen validation_sha256 is required")
    if not isinstance(config.get("bge_query_instruction"), str):
        raise ValueError("Frozen BGE query instruction is required")
    return config


def validate_records(references, test_records, reference_path, test_path, config):
    reference_hash = sha256_file(reference_path)
    test_hash = sha256_file(test_path)
    if reference_hash != config["reference_sha256"]:
        raise ValueError(
            "Reference corpus SHA-256 has changed since validation model selection. "
            f"Expected {config['reference_sha256']}; found {reference_hash}. "
            "STOP: don't use the held-out test against a modified corpus."
        )
    if test_hash == config["validation_sha256"]:
        raise ValueError("The supplied test file is actually the validation dataset")
    if test_path.name.lower() in {"validation.jsonl", "validation_results.jsonl"}:
        raise ValueError("Pass untouched test.jsonl, not a validation file")
    if len(test_records) != config["expected_test_count"]:
        raise ValueError(
            f"Expected {config['expected_test_count']} held-out records, "
            f"found {len(test_records)}. Verify the original test split."
        )

    for name, records, id_field in (
        ("references", references, "reference_id"),
        ("test", test_records, "sample_id"),
    ):
        ids = []
        for record in records:
            if not isinstance(record.get(id_field), str) or not record[id_field].strip():
                raise ValueError(f"{name}: missing {id_field}")
            if not isinstance(record.get("text"), str) or not record["text"].strip():
                raise ValueError(f"{name}: missing text for {record[id_field]}")
            if record.get("label") not in {"malicious", "benign"}:
                raise ValueError(f"{name}: invalid label for {record[id_field]}")
            ids.append(record[id_field])
        if len(ids) != len(set(ids)):
            raise ValueError(f"{name}: duplicate {id_field} detected")

    for record in references:
        if record["label"] == "malicious" and record.get("category") not in CATEGORIES:
            raise ValueError(f"Reference {record['reference_id']}: unsupported malicious category")
    for category in CATEGORIES:
        if not any(r["label"] == "malicious" and r.get("category") == category for r in references):
            raise ValueError(f"No malicious references for category: {category}")
    if not any(r["label"] == "benign" for r in references):
        raise ValueError("Reference corpus has no benign examples")

    for record in test_records:
        if type(record.get("in_scope")) is not bool:
            raise ValueError(f"Test record {record['sample_id']}: in_scope must be a boolean")
        if record["in_scope"] and record["label"] == "malicious":
            if record.get("category") not in CATEGORIES:
                raise ValueError(f"Test record {record['sample_id']}: invalid supported category")
        if not record["in_scope"] and record["label"] == "malicious":
            if record.get("category") in CATEGORIES:
                raise ValueError(f"Test record {record['sample_id']}: scope/category conflict")

    normalized_reference_texts = {record["text"].strip().casefold() for record in references}
    normalized_test_texts = {record["text"].strip().casefold() for record in test_records}
    overlap = normalized_reference_texts & normalized_test_texts
    if overlap:
        raise ValueError(f"Reference/test text overlap: {len(overlap)} exact matches")
    if len(normalized_test_texts) != len(test_records):
        raise ValueError("Duplicate text found within test set")
    return reference_hash, test_hash


# ============================================================
# MATCH EVIDENCE (retained from the original script)
# ============================================================

def best_match(scores, references, required_label=None):
    candidate_indexes = [
        index for index, record in enumerate(references)
        if required_label is None or record["label"] == required_label
    ]
    if not candidate_indexes:
        raise ValueError(f"No references found for label={required_label}")
    index = max(candidate_indexes, key=lambda index: scores[index])
    return match_details(index, scores, references)


def match_details(index, scores, references):
    record = references[int(index)]
    return {
        "reference_id": record["reference_id"],
        "similarity": float(scores[index]),
        "label": record["label"],
        "category": record.get("category"),
        "related_category": record.get("related_category"),
        "semantic_family": record.get("semantic_family"),
        "text": record["text"],
    }


def top_matches(scores, references, count=5):
    indexes = np.argsort(scores)[::-1][:count]
    return [match_details(index, scores, references) for index in indexes]


def mean_top_k(scores, indexes, k):
    # Deliberately identical to the validation comparison's mean_top_k.
    subset = scores[indexes]
    count = min(k, len(subset))
    return float(np.mean(np.sort(subset)[-count:]))


def score_topk_mean(scores, references, top_k):
    """Exact category_topk_mean scorer used by compare_embedding_models.py.

    For each supported category: mean of its 3 nearest malicious references.
    Choose category with largest such mean. Margin compares that selected
    category's score with the GLOBAL mean of top 3 benign references.
    """
    benign_indexes = np.array(
        [i for i, record in enumerate(references) if record["label"] == "benign"],
        dtype=int,
    )
    benign_similarity = mean_top_k(scores, benign_indexes, top_k)
    category_scores = {}
    category_best_reference = {}
    category_top_reference_ids = {}

    for category in CATEGORIES:
        indexes = np.array([
            i for i, record in enumerate(references)
            if record["label"] == "malicious" and record["category"] == category
        ], dtype=int)
        category_scores[category] = mean_top_k(scores, indexes, top_k)
        ranked = sorted(indexes, key=lambda i: float(scores[i]), reverse=True)
        category_best_reference[category] = references[int(ranked[0])]["reference_id"]
        category_top_reference_ids[category] = [
            references[int(index)]["reference_id"] for index in ranked[:top_k]
        ]

    # Tie-breaking keeps the same CATEGORIES order as the comparison experiment.
    predicted_category = max(CATEGORIES, key=lambda c: category_scores[c])
    malicious_similarity = category_scores[predicted_category]
    margin = malicious_similarity - benign_similarity
    return {
        "predicted_category_candidate": predicted_category,
        "malicious_similarity": malicious_similarity,
        "benign_topk_similarity": benign_similarity,
        "margin": margin,
        "category_topk_scores": category_scores,
        "closest_malicious_reference_id": category_best_reference[predicted_category],
        "top_category_reference_ids": category_top_reference_ids[predicted_category],
    }


# ============================================================
# TEST EVALUATION — NO THRESHOLD SEARCH
# ============================================================

def evaluation_group(record):
    if record["in_scope"]:
        return "in_scope_malicious" if record["label"] == "malicious" else "in_scope_benign"
    return "out_of_scope_malicious" if record["label"] == "malicious" else "out_of_scope_benign"


def evaluate_test(references, test_records, similarity_matrix, config):
    rows = []
    for row_index, record in enumerate(test_records):
        similarities = similarity_matrix[row_index]
        signal = score_topk_mean(similarities, references, config["top_k"])
        detected = (
            signal["malicious_similarity"] >= config["similarity_threshold"]
            and signal["margin"] >= config["margin_threshold"]
        )
        predicted_category = signal["predicted_category_candidate"] if detected else None

        error_type = "none"
        if record["in_scope"] and record["label"] == "malicious":
            if not detected:
                error_type = "false_negative"
            elif predicted_category != record["category"]:
                error_type = "category_error"
        elif record["in_scope"] and record["label"] == "benign" and detected:
            error_type = "false_positive"
        elif not record["in_scope"] and detected:
            error_type = "out_of_scope_trigger"

        rows.append({
            "sample_id": record["sample_id"],
            "text": record["text"],
            "actual_label": record["label"],
            "actual_category": record.get("category"),
            "related_category": record.get("related_category"),
            "difficulty": record.get("difficulty"),
            "evaluation_type": record.get("evaluation_type"),
            "in_scope": record["in_scope"],
            "evaluation_group": evaluation_group(record),
            "predicted_supported_attack": bool(detected),
            "predicted_category": predicted_category,
            "error_type": error_type,
            "category_candidate_even_if_not_detected": signal["predicted_category_candidate"],
            "category_topk_scores": signal["category_topk_scores"],
            "malicious_similarity": signal["malicious_similarity"],
            "benign_topk_similarity": signal["benign_topk_similarity"],
            "semantic_margin": signal["margin"],
            "closest_malicious_reference_id": signal["closest_malicious_reference_id"],
            "top_category_reference_ids": signal["top_category_reference_ids"],
            "top_overall_match": best_match(similarities, references),
            "top_malicious_match": best_match(similarities, references, "malicious"),
            "top_benign_match": best_match(similarities, references, "benign"),
            "top_k_matches": top_matches(similarities, references, count=5),
        })
    return rows


def build_report(predictions):
    tp = tn = fp = fn = 0
    correct_category = 0
    oos_mal_count = oos_mal_hit = 0
    oos_ben_count = oos_ben_hit = 0
    group_summary = {}
    per_category = {}

    for category in CATEGORIES:
        per_category[category] = {
            "total": 0, "detected": 0, "correctly_classified": 0,
            "missed": 0, "wrong_category": 0,
        }

    for row in predictions:
        detected = row["predicted_supported_attack"]
        group = row["evaluation_group"]
        if group not in group_summary:
            group_summary[group] = {"count": 0, "detected": 0, "missed_or_not_triggered": 0}
        group_summary[group]["count"] += 1
        group_summary[group]["detected"] += int(detected)
        group_summary[group]["missed_or_not_triggered"] += int(not detected)

        if group == "in_scope_malicious":
            category = row["actual_category"]
            per_category[category]["total"] += 1
            if detected:
                tp += 1
                per_category[category]["detected"] += 1
                if row["predicted_category"] == category:
                    correct_category += 1
                    per_category[category]["correctly_classified"] += 1
                else:
                    per_category[category]["wrong_category"] += 1
            else:
                fn += 1
                per_category[category]["missed"] += 1
        elif group == "in_scope_benign":
            if detected:
                fp += 1
            else:
                tn += 1
        elif group == "out_of_scope_malicious":
            oos_mal_count += 1
            oos_mal_hit += int(detected)
        else:
            oos_ben_count += 1
            oos_ben_hit += int(detected)

    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    specificity = safe_divide(tn, tn + fp)
    f1 = safe_divide(2 * precision * recall, precision + recall)

    # Retain the source script's score summaries by evaluation group.
    score_summary = {}
    for group in group_summary:
        group_rows = [row for row in predictions if row["evaluation_group"] == group]
        score_summary[group] = {
            "malicious_similarity": describe([row["malicious_similarity"] for row in group_rows]),
            "benign_topk_similarity": describe([row["benign_topk_similarity"] for row in group_rows]),
            "semantic_margin": describe([row["semantic_margin"] for row in group_rows]),
        }

    return {
        "in_scope_detection_metrics": {
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1,
            "specificity": specificity,
            "accuracy": safe_divide(tp + tn, tp + tn + fp + fn),
            "balanced_accuracy": (recall + specificity) / 2,
        },
        "category_metrics": {
            "correct_category_detected": correct_category,
            "category_accuracy_on_detected": safe_divide(correct_category, tp),
            "category_end_to_end_recall": safe_divide(correct_category, tp + fn),
            "by_actual_category": per_category,
        },
        "out_of_scope_metrics": {
            "malicious_triggers": oos_mal_hit,
            "malicious_total": oos_mal_count,
            "malicious_trigger_rate": safe_divide(oos_mal_hit, oos_mal_count),
            "benign_triggers": oos_ben_hit,
            "benign_total": oos_ben_count,
            "benign_trigger_rate": safe_divide(oos_ben_hit, oos_ben_count),
        },
        "evaluation_groups": group_summary,
        "score_distributions": score_summary,
        "error_counts": {
            name: sum(row["error_type"] == name for row in predictions)
            for name in ("false_positive", "false_negative", "category_error", "out_of_scope_trigger")
        },
    }


def describe(values):
    if not values:
        return None
    return {
        "count": len(values), "min": min(values), "max": max(values),
        "mean": mean(values), "median": median(values),
    }


def package_version(package):
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return None


def main():
    parser = argparse.ArgumentParser(
        description="BearBreach final held-out test for FROZEN BGE + category_topk_mean"
    )
    parser.add_argument("--references", required=True, type=Path)
    parser.add_argument("--test", required=True, type=Path, help="Original untouched test.jsonl")
    parser.add_argument("--config", required=True, type=Path, help="Frozen config from validation")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--batch-size", type=int, default=32)
    args = parser.parse_args()
    if args.batch_size < 1:
        parser.error("batch-size must be at least 1")

    config = load_frozen_config(args.config)
    reference_records = load_jsonl(args.references)
    test_records = load_jsonl(args.test)
    reference_hash, test_hash = validate_records(
        reference_records, test_records, args.references, args.test, config
    )

    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise ValueError(
            f"Output directory already contains files: {args.output_dir}. "
            "Use a new directory; don't overwrite an earlier held-out test report."
        )

    print(f"Reference corpus: {len(reference_records)}; held-out test: {len(test_records)}")
    print("FROZEN model:", config["model_name"])
    print("FROZEN scoring: category_topk_mean; top_k=3")
    print("FROZEN thresholds:", config["similarity_threshold"], config["margin_threshold"])
    print("No threshold search will occur.")

    start = perf_counter()
    model = SentenceTransformer(config["model_name"])
    load_ms = (perf_counter() - start) * 1000
    if model.max_seq_length != config["model_max_seq_length"]:
        raise ValueError(
            f"Model max sequence length changed: {model.max_seq_length} "
            f"vs validated {config['model_max_seq_length']}"
        )

    # EXACT same BGE asymmetric encoding as compare_embedding_models.py:
    # reference exemplars = unprefixed passages, incoming artifacts = prefixed queries.
    reference_texts = [record["text"] for record in reference_records]
    test_queries = [config["bge_query_instruction"] + record["text"] for record in test_records]

    start = perf_counter()
    reference_embeddings = model.encode(
        reference_texts, batch_size=args.batch_size, normalize_embeddings=True,
        convert_to_numpy=True, show_progress_bar=True,
    )
    reference_encoding_ms = (perf_counter() - start) * 1000

    start = perf_counter()
    test_embeddings = model.encode(
        test_queries, batch_size=args.batch_size, normalize_embeddings=True,
        convert_to_numpy=True, show_progress_bar=True,
    )
    test_encoding_ms = (perf_counter() - start) * 1000
    if reference_embeddings.shape[1] != config["embedding_dimensions"]:
        raise ValueError("Embedding dimension mismatch with validation run")

    start = perf_counter()
    similarity_matrix = (
        np.asarray(test_embeddings, dtype=np.float32)
        @ np.asarray(reference_embeddings, dtype=np.float32).T
    )
    similarity_calculation_ms = (perf_counter() - start) * 1000

    predictions = evaluate_test(reference_records, test_records, similarity_matrix, config)
    metrics = build_report(predictions)
    report = {
        "purpose": "one_time_held_out_test_no_tuning",
        "model": config["model_name"],
        "strategy": config["strategy"],
        "top_k": config["top_k"],
        "input_format": config["input_format"],
        "thresholds": {
            "similarity": config["similarity_threshold"],
            "margin": config["margin_threshold"],
            "support": None,
        },
        "frozen_config_sha256": sha256_file(args.config),
        "reference_file_sha256": reference_hash,
        "validation_file_sha256_for_provenance_only": config["validation_sha256"],
        "test_file_sha256": test_hash,
        "reference_count": len(reference_records),
        "test_count": len(test_records),
        "embedding_dimensions": int(reference_embeddings.shape[1]),
        "package_versions": {
            package: package_version(package)
            for package in ("numpy", "sentence-transformers", "torch")
        },
        "performance_ms": {
            "model_load": load_ms,
            "reference_encoding": reference_encoding_ms,
            "test_encoding": test_encoding_ms,
            "similarity_calculation": similarity_calculation_ms,
        },
        **metrics,
        "warning": (
            "Final test numbers from a small synthetic held-out sample. "
            "No thresholds were optimized against test results. "
            "Out-of-scope malicious triggers are separate from in-scope false negatives."
        ),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    results_path = args.output_dir / "test_results.jsonl"
    errors_path = args.output_dir / "test_errors.jsonl"
    report_path = args.output_dir / "final_test_report.json"
    save_jsonl(predictions, results_path)
    save_jsonl([row for row in predictions if row["error_type"] != "none"], errors_path)
    save_json(report, report_path)

    scores = report["in_scope_detection_metrics"]
    category = report["category_metrics"]
    oos = report["out_of_scope_metrics"]
    print("\n=== HELD-OUT TEST RESULTS ===")
    print(f"TP={scores['tp']} TN={scores['tn']} FP={scores['fp']} FN={scores['fn']}")
    print(f"Precision={scores['precision']:.4f} Recall={scores['recall']:.4f} F1={scores['f1']:.4f}")
    print(f"Category end-to-end recall={category['category_end_to_end_recall']:.4f}")
    print(f"OOS malicious triggers={oos['malicious_triggers']}/{oos['malicious_total']}")
    print(f"OOS benign triggers={oos['benign_triggers']}/{oos['benign_total']}")
    print(f"Detailed results: {results_path}")
    print(f"Errors:           {errors_path}")
    print(f"Final report:     {report_path}")
    print("Freeze these results; do not change the configuration based on test outcomes.")


if __name__ == "__main__":
    main()
