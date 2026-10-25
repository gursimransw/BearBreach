"""Compare BearBreach semantic-detection scoring strategies on VALIDATION only.

Requires: numpy, sentence-transformers
Do not point --validation at the frozen test dataset while tuning.
"""

import argparse
import csv
import hashlib
import json
from pathlib import Path
from time import perf_counter

import numpy as np


CATEGORIES = (
    "prompt_injection",
    "jailbreak",
    "role_manipulation",
    "system_prompt_extraction",
)
STRATEGIES = (
    "global_max",
    "category_local_max",
    "category_topk_mean",
    "category_topk_margin",
    "neighbor_vote",
)
DEFAULT_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


def load_jsonl(path):
    records = []
    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}:{line_number}: {error}") from error
    if not records:
        raise ValueError(f"Empty dataset: {path}")
    return records


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def mean_top_k(scores, indexes, k):
    """Mean of the k nearest references in one group, not all references."""
    selected = scores[indexes]
    count = min(k, len(selected))
    return float(np.mean(np.sort(selected)[-count:]))


def make_signals(reference_records, validation_records, similarities, top_k, neighbor_k):
    """Compute one similarity signal and proposed category per strategy/sample.

    A signal is NOT a prediction until its thresholds are applied.
    """
    labels = np.array([record["label"] for record in reference_records])
    malicious_indexes = np.where(labels == "malicious")[0]
    benign_indexes = np.where(labels == "benign")[0]

    per_category_malicious = {}
    per_category_benign = {}
    for category in CATEGORIES:
        per_category_malicious[category] = np.array([
            index for index, record in enumerate(reference_records)
            if record["label"] == "malicious" and record["category"] == category
        ], dtype=int)
        per_category_benign[category] = np.array([
            index for index, record in enumerate(reference_records)
            if record["label"] == "benign"
            and record.get("related_category") == category
        ], dtype=int)
        if not len(per_category_malicious[category]) or not len(per_category_benign[category]):
            raise ValueError(f"Missing malicious or hard-benign references for {category}")

    malicious_corpus_fraction = len(malicious_indexes) / len(reference_records)
    signals = {strategy: [] for strategy in STRATEGIES}

    for row_number, record in enumerate(validation_records):
        scores = similarities[row_number]
        best_mal_index = int(malicious_indexes[np.argmax(scores[malicious_indexes])])
        best_ben_index = int(benign_indexes[np.argmax(scores[benign_indexes])])
        global_mal = float(scores[best_mal_index])
        global_ben = float(scores[best_ben_index])
        global_category = reference_records[best_mal_index]["category"]
        global_ben_topk = mean_top_k(scores, benign_indexes, top_k)

        local_mal_max = {}
        local_ben_max = {}
        local_mal_topk = {}
        local_ben_topk = {}
        local_best_ref = {}

        for category in CATEGORIES:
            mal_indices = per_category_malicious[category]
            ben_indices = per_category_benign[category]
            local_mal_max[category] = float(np.max(scores[mal_indices]))
            local_ben_max[category] = float(np.max(scores[ben_indices]))
            local_mal_topk[category] = mean_top_k(scores, mal_indices, top_k)
            local_ben_topk[category] = mean_top_k(scores, ben_indices, top_k)
            best_index = int(mal_indices[np.argmax(scores[mal_indices])])
            local_best_ref[category] = reference_records[best_index]["reference_id"]

        def signal(category, malicious_similarity, margin, support_delta=None):
            return {
                "sample_id": record["sample_id"],
                "category": category,
                "reference_id": local_best_ref[category],
                "malicious_similarity": float(malicious_similarity),
                "margin": float(margin),
                "support_delta": support_delta,
            }

        signals["global_max"].append(signal(
            global_category, global_mal, global_mal - global_ben
        ))

        signals["category_local_max"].append(signal(
            global_category, global_mal, global_mal - local_ben_max[global_category]
        ))

        topk_category = max(CATEGORIES, key=lambda category: local_mal_topk[category])
        signals["category_topk_mean"].append(signal(
            topk_category,
            local_mal_topk[topk_category],
            local_mal_topk[topk_category] - global_ben_topk,
        ))

        # Both sides are category-local, and the category is selected by
        # its strongest malicious-vs-related-benign contrast.
        margin_category = max(
            CATEGORIES,
            key=lambda category: (
                local_mal_topk[category] - local_ben_topk[category],
                local_mal_topk[category],
            ),
        )
        signals["category_topk_margin"].append(signal(
            margin_category,
            local_mal_topk[margin_category],
            local_mal_topk[margin_category] - local_ben_topk[margin_category],
        ))

        # Neighborhood vote: compare the proportion of similarity-weighted
        # malicious neighbors against the malicious proportion in the CORPUS.
        # The prior correction is exploratory, not a calibrated probability.
        nearest = np.argsort(scores)[-min(neighbor_k, len(scores)):]
        weights = np.maximum(scores[nearest], 0)
        weight_sum = float(weights.sum())
        if weight_sum <= 0:
            malicious_share = 0.0
        else:
            malicious_share = float(sum(
                float(weight) for index, weight in zip(nearest, weights)
                if reference_records[int(index)]["label"] == "malicious"
            )) / weight_sum
        support_delta = malicious_share - malicious_corpus_fraction

        category_votes = {}
        for category in CATEGORIES:
            category_votes[category] = sum(
                float(weight) for index, weight in zip(nearest, weights)
                if reference_records[int(index)]["label"] == "malicious"
                and reference_records[int(index)]["category"] == category
            )
        vote_category = max(CATEGORIES, key=lambda category: category_votes[category])
        if category_votes[vote_category] == 0:
            vote_category = global_category
        signals["neighbor_vote"].append(signal(
            vote_category, global_mal, global_mal - global_ben, support_delta
        ))

    return signals, malicious_corpus_fraction


def metrics(records, signals, similarity_threshold, margin_threshold, support_threshold):
    tp = tn = fp = fn = oos_mal = oos_ben = oos_mal_hit = oos_ben_hit = 0
    correct_category_detected = 0

    for record, signal in zip(records, signals):
        detected = (
            signal["malicious_similarity"] >= similarity_threshold
            and signal["margin"] >= margin_threshold
        )
        if support_threshold is not None:
            detected = detected and signal["support_delta"] >= support_threshold

        if record["in_scope"]:
            if record["label"] == "malicious":
                if detected:
                    tp += 1
                    if signal["category"] == record["category"]:
                        correct_category_detected += 1
                else:
                    fn += 1
            else:
                if detected:
                    fp += 1
                else:
                    tn += 1
        elif record["label"] == "malicious":
            oos_mal += 1
            oos_mal_hit += int(detected)
        else:
            oos_ben += 1
            oos_ben_hit += int(detected)

    def ratio(numerator, denominator):
        return numerator / denominator if denominator else 0.0

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    specificity = ratio(tn, tn + fp)
    f1 = ratio(2 * precision * recall, precision + recall)

    return {
        "similarity_threshold": similarity_threshold,
        "margin_threshold": margin_threshold,
        "support_threshold": support_threshold,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": ratio(tp + tn, tp + tn + fp + fn),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "specificity": specificity,
        "balanced_accuracy": (recall + specificity) / 2,
        "oos_mal_trigger_rate": ratio(oos_mal_hit, oos_mal),
        "oos_ben_trigger_rate": ratio(oos_ben_hit, oos_ben),
        "category_accuracy_on_detected": ratio(correct_category_detected, tp),
        "category_end_to_end_recall": ratio(correct_category_detected, tp + fn),
    }


def select_best(rows):
    if not rows:
        return None
    # Tie-break toward fewer FPs/OOS errors, then toward conservative thresholds.
    return max(rows, key=lambda row: (
        row["f1"], row["precision"], row["specificity"],
        -row["oos_mal_trigger_rate"], -row["oos_ben_trigger_rate"],
        row["similarity_threshold"], row["margin_threshold"],
        row["support_threshold"] if row["support_threshold"] is not None else 0,
    ))


def threshold_search(records, signals, strategy, max_fp, min_recall, max_oos):
    all_rows = []
    support_options = [None]
    if strategy == "neighbor_vote":
        support_options = [None,-0.25, -0.15, -0.05, 0.0, 0.05, 0.10, 0.15, 0.20]

    for similarity_int in range(20, 71):
        for margin_int in range(-10, 21):
            for support in support_options:
                row = metrics(
                    records, signals,
                    similarity_int / 100,
                    margin_int / 100,
                    support,
                )
                row["strategy"] = strategy
                all_rows.append(row)

    best_f1 = select_best(all_rows)
    fp_constrained = select_best([
        row for row in all_rows
        if row["fp"] <= max_fp and row["recall"] >= min_recall
    ])
    fully_constrained = select_best([
        row for row in all_rows
        if row["fp"] <= max_fp
        and row["recall"] >= min_recall
        and row["oos_mal_trigger_rate"] <= max_oos
    ])
    return all_rows, best_f1, fp_constrained, fully_constrained


def write_json(path, data):
    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)


def write_csv(path, rows):
    if not rows:
        return
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def write_predictions(path, records, signals, config):
    with path.open("w", encoding="utf-8") as file:
        for record, signal in zip(records, signals):
            detected = (
                signal["malicious_similarity"] >= config["similarity_threshold"]
                and signal["margin"] >= config["margin_threshold"]
            )
            if config["support_threshold"] is not None:
                detected = detected and signal["support_delta"] >= config["support_threshold"]
            if record["in_scope"] and record["label"] == "benign" and detected:
                finding = "false_positive"
            elif record["in_scope"] and record["label"] == "malicious" and not detected:
                finding = "false_negative"
            elif (record["in_scope"] and record["label"] == "malicious"
                  and detected and signal["category"] != record["category"]):
                finding = "category_error"
            elif not record["in_scope"] and detected:
                finding = "unsupported_or_unrelated_trigger"
            else:
                finding = "no_error"
            output = {
                "error_type": finding,
                "sample_id": record["sample_id"],
                "text": record["text"],
                "actual_label": record["label"],
                "actual_category": record["category"],
                "in_scope": record["in_scope"],
                "predicted_supported_attack": bool(detected),
                "predicted_category": signal["category"] if detected else None,
                "closest_reference_id": signal["reference_id"],
                "malicious_similarity": signal["malicious_similarity"],
                "margin": signal["margin"],
                "support_delta": signal["support_delta"],
            }
            file.write(json.dumps(output, ensure_ascii=False) + "\n")


def display_row(strategy, selection, config):
    if config is None:
        print(f"{strategy:<22} {selection:<16} NO QUALIFYING CONFIGURATION")
        return
    support = "-" if config["support_threshold"] is None else f"{config['support_threshold']:.2f}"
    print(
        f"{strategy:<22} {selection:<16} "
        f"{config['similarity_threshold']:>4.2f} "
        f"{config['margin_threshold']:>6.2f} "
        f"{support:>6} "
        f"{config['precision']:>5.2f} "
        f"{config['recall']:>5.2f} "
        f"{config['f1']:>5.2f} "
        f"{config['specificity']:>5.2f} "
        f"{config['fp']:>3} "
        f"{config['fn']:>3} "
        f"{config['oos_mal_trigger_rate']:>5.2f} "
        f"{config['category_end_to_end_recall']:>5.2f}"
    )


def main():
    parser = argparse.ArgumentParser(description="Compare five BearBreach semantic scoring strategies.")
    parser.add_argument("--references", required=True, type=Path)
    parser.add_argument("--validation", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument("--neighbor-k", type=int, default=10)
    parser.add_argument("--max-fp", type=int, default=5)
    parser.add_argument("--min-recall", type=float, default=0.70)
    parser.add_argument("--max-oos-mal-trigger-rate", type=float, default=0.33)
    args = parser.parse_args()

    if args.validation.name.lower() == "test.jsonl":
        raise ValueError("This script tunes thresholds. Use validation.jsonl, not the frozen test.jsonl.")

    if args.top_k < 1 or args.neighbor_k < 1:
        raise ValueError("--top-k and --neighbor-k must be positive.")

    references = load_jsonl(args.references)
    validation = load_jsonl(args.validation)

    reference_texts = [record["text"] for record in references]
    validation_texts = [record["text"] for record in validation]
    if not all(isinstance(record.get("in_scope"), bool) for record in validation):
        raise ValueError("Every validation record needs a Boolean 'in_scope'.")
    if not all(record.get("label") in {"benign", "malicious"} for record in validation):
        raise ValueError("Validation labels must be 'benign' or 'malicious'.")
    if not all(record.get("category") in CATEGORIES for record in validation
               if record["in_scope"] and record["label"] == "malicious"):
        raise ValueError("Found an invalid in-scope malicious category.")

    overlap = set(reference_texts) & set(validation_texts)
    if overlap:
        raise ValueError(f"Exact text leakage: {len(overlap)} validation texts occur in the references.")

    from sentence_transformers import SentenceTransformer

    print(f"Model: {args.model}")
    print(f"References: {len(references)} | Validation samples: {len(validation)}")
    start = perf_counter()
    model = SentenceTransformer(args.model)
    reference_vectors = model.encode(reference_texts, normalize_embeddings=True, convert_to_numpy=True)
    validation_vectors = model.encode(validation_texts, normalize_embeddings=True, convert_to_numpy=True)
    similarities = np.dot(validation_vectors, reference_vectors.T)
    print(f"Embedding dimension: {reference_vectors.shape[1]}")
    print(f"Encoding + similarity setup: {perf_counter() - start:.2f}s")

    signals_by_strategy, corpus_mal_fraction = make_signals(
        references, validation, similarities, args.top_k, args.neighbor_k
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    all_rows = []
    summary = {
        "model": args.model,
        "reference_sha256": file_sha256(args.references),
        "validation_sha256": file_sha256(args.validation),
        "reference_count": len(references),
        "validation_count": len(validation),
        "top_k": args.top_k,
        "neighbor_k": args.neighbor_k,
        "malicious_reference_fraction": corpus_mal_fraction,
        "selection_constraints": {
            "max_fp": args.max_fp,
            "min_recall": args.min_recall,
            "max_oos_mal_trigger_rate": args.max_oos_mal_trigger_rate,
        },
        "strategies": {},
    }

    print("\nComparison: OOS-M = unsupported-malicious trigger rate; CAT = category-correct detection recall")
    print(f"{'STRATEGY':<22} {'SELECTION':<16} SIM MARGIN SUPPORT  PREC RECALL    F1  SPEC  FP  FN OOS-M   CAT")
    print("-" * 117)

    for strategy in STRATEGIES:
        rows, best_f1, fp_limited, constrained = threshold_search(
            validation, signals_by_strategy[strategy], strategy,
            args.max_fp, args.min_recall, args.max_oos_mal_trigger_rate
        )
        all_rows.extend(rows)
        summary["strategies"][strategy] = {
            "best_f1": best_f1,
            "fp_limited": fp_limited,
            "fully_constrained": constrained,
        }
        for selection, config in (
            ("best_f1", best_f1),
            ("fp_limited", fp_limited),
            ("all_constraints", constrained),
        ):
            display_row(strategy, selection, config)
            if config is not None:
                path = args.output_dir / f"{strategy}_{selection}_predictions.jsonl"
                write_predictions(path, validation, signals_by_strategy[strategy], config)
        print()

    write_csv(args.output_dir / "all_threshold_results.csv", all_rows)
    write_json(args.output_dir / "strategy_comparison.json", summary)
    print(f"Searched {len(all_rows)} total configurations (validation only).")
    print(f"Saved comparison, all thresholds, and per-sample predictions to: {args.output_dir}")
    print("Do not tune against test.jsonl until you have selected and frozen your design.")


if __name__ == "__main__":
    main()
