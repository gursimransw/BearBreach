"""BearBreach: VALIDATION-ONLY comparison of embedding models for semantic detection.

Example (PowerShell):
  python libraries/semantic-corpus/dataset_operations/compare_embedding_models.py `
    --references libraries/semantic-corpus/curated/references.jsonl `
    --validation libraries/semantic-corpus/evaluation/validation.jsonl `
    --output-dir experiments/semantic-detection/results/model-comparison

Requires: pip install numpy sentence-transformers
Optional for process RAM measurements: pip install psutil

This script selects/tunes on validation only. NEVER pass test.jsonl here.
"""

import argparse
import csv
import gc
import hashlib
import importlib.metadata
import json
from pathlib import Path
from statistics import median
from time import perf_counter

import numpy as np

CATEGORIES = (
    "prompt_injection", "jailbreak", "role_manipulation", "system_prompt_extraction",
)
STRATEGIES = (
    "global_max", "category_local_max", "category_topk_mean",
    "category_topk_margin", "neighbor_vote",
)
DEFAULT_MODELS = (
    "sentence-transformers/all-MiniLM-L6-v2",
    "BAAI/bge-base-en-v1.5",
    "intfloat/e5-base-v2",
)
BGE_QUERY_INSTRUCTION = "Represent this sentence for searching relevant passages: "
SUPPORT_THRESHOLDS = (None, -0.25, -0.15, -0.05, 0.0, 0.05, 0.10, 0.15, 0.20)


def load_jsonl(path):
    records = []
    with path.open("r", encoding="utf-8-sig") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"{path}:{line_number}: record must be a JSON object")
            records.append(record)
    if not records:
        raise ValueError(f"No records found in {path}")
    return records


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_data(references, validation, validation_path):
    lowered = validation_path.name.lower()
    if lowered == "test.jsonl" or lowered.startswith("test_") or lowered.startswith("holdout"):
        raise ValueError("Do not tune using held-out test data. Pass validation.jsonl.")
    if lowered == "validation_results.jsonl":
        raise ValueError("Pass the original validation.jsonl, NOT validation_results.jsonl.")
    for dataset_name, records in (("references", references), ("validation", validation)):
        ids = []
        for record in records:
            if not isinstance(record.get("text"), str) or not record["text"].strip():
                raise ValueError(f"{dataset_name}: missing or empty text")
            if record.get("label") not in {"malicious", "benign"}:
                raise ValueError(
                    f"{dataset_name}: labels must be 'malicious' or 'benign'. "
                    "For validation, use validation.jsonl, not validation_results.jsonl."
                )
            sample_id = record.get("sample_id") if dataset_name == "validation" else record.get("reference_id")
            if not isinstance(sample_id, str) or not sample_id:
                raise ValueError(f"{dataset_name}: missing sample_id/reference_id")
            ids.append(sample_id)
        if len(ids) != len(set(ids)):
            raise ValueError(f"{dataset_name}: duplicate IDs found")
    for record in validation:
        if not isinstance(record.get("in_scope"), bool):
            raise ValueError(f"Validation sample {record['sample_id']} has invalid in_scope")
        if record["in_scope"] and record["label"] == "malicious" and record.get("category") not in CATEGORIES:
            raise ValueError(f"Invalid in-scope category on {record['sample_id']}")
    if not any(r["in_scope"] and r["label"] == "malicious" for r in validation):
        raise ValueError("Validation dataset must contain in-scope malicious samples")
    if not any(r["in_scope"] and r["label"] == "benign" for r in validation):
        raise ValueError("Validation dataset must contain in-scope benign samples")
    overlaps = {r["text"].strip().casefold() for r in references} & {
        r["text"].strip().casefold() for r in validation
    }
    if overlaps:
        raise ValueError(f"Reference-validation exact text leakage: {len(overlaps)} overlapping texts")
    for category in CATEGORIES:
        if not any(r["label"] == "malicious" and r.get("category") == category for r in references):
            raise ValueError(f"No malicious reference for category {category}")
        if not any(r["label"] == "benign" and r.get("related_category") == category for r in references):
            raise ValueError(f"No hard-benign reference for category {category}")


def input_texts(model_name, references, validation):
    """Treat incoming artifacts as queries and reference exemplars as passages."""
    reference_texts = [r["text"] for r in references]
    validation_texts = [r["text"] for r in validation]
    name = model_name.lower()
    if "e5-" in name:
        return (
            ["passage: " + text for text in reference_texts],
            ["query: " + text for text in validation_texts],
            "e5_asymmetric_query_passage",
        )
    if "bge-" in name:
        return (
            reference_texts,
            [BGE_QUERY_INSTRUCTION + text for text in validation_texts],
            "bge_query_instruction",
        )
    return reference_texts, validation_texts, "no_prefix"


def mean_top_k(scores, indexes, k):
    subset = scores[indexes]
    count = min(k, len(subset))
    return float(np.mean(np.sort(subset)[-count:]))


def make_signals(references, validation, similarity_matrix, top_k, neighbor_k):
    """Same five scoring definitions as compare_scoring_strategies.py."""
    label_array = np.array([r["label"] for r in references])
    malicious_indexes = np.where(label_array == "malicious")[0]
    benign_indexes = np.where(label_array == "benign")[0]
    by_category_mal = {}
    by_category_ben = {}
    for category in CATEGORIES:
        by_category_mal[category] = np.array([
            i for i, r in enumerate(references)
            if r["label"] == "malicious" and r.get("category") == category
        ], dtype=int)
        by_category_ben[category] = np.array([
            i for i, r in enumerate(references)
            if r["label"] == "benign" and r.get("related_category") == category
        ], dtype=int)
    malicious_reference_fraction = len(malicious_indexes) / len(references)
    result = {strategy: [] for strategy in STRATEGIES}

    for row_index, record in enumerate(validation):
        scores = similarity_matrix[row_index]
        best_mal_index = int(malicious_indexes[np.argmax(scores[malicious_indexes])])
        best_ben_index = int(benign_indexes[np.argmax(scores[benign_indexes])])
        global_mal = float(scores[best_mal_index])
        global_ben = float(scores[best_ben_index])
        global_category = references[best_mal_index]["category"]
        global_ben_topk = mean_top_k(scores, benign_indexes, top_k)

        local_mal_max = {}
        local_ben_max = {}
        local_mal_topk = {}
        local_ben_topk = {}
        best_ref_ids = {}
        for category in CATEGORIES:
            mi = by_category_mal[category]
            bi = by_category_ben[category]
            local_mal_max[category] = float(np.max(scores[mi]))
            local_ben_max[category] = float(np.max(scores[bi]))
            local_mal_topk[category] = mean_top_k(scores, mi, top_k)
            local_ben_topk[category] = mean_top_k(scores, bi, top_k)
            best_index = int(mi[np.argmax(scores[mi])])
            best_ref_ids[category] = references[best_index]["reference_id"]

        def build_signal(category, malicious_similarity, margin, support_delta=None):
            return {
                "sample_id": record["sample_id"],
                "category": category,
                "reference_id": best_ref_ids[category],
                "malicious_similarity": float(malicious_similarity),
                "margin": float(margin),
                "support_delta": support_delta,
            }

        result["global_max"].append(build_signal(
            global_category, global_mal, global_mal - global_ben,
        ))
        result["category_local_max"].append(build_signal(
            global_category, global_mal, global_mal - local_ben_max[global_category],
        ))
        topk_category = max(CATEGORIES, key=lambda c: local_mal_topk[c])
        result["category_topk_mean"].append(build_signal(
            topk_category, local_mal_topk[topk_category],
            local_mal_topk[topk_category] - global_ben_topk,
        ))
        margin_category = max(
            CATEGORIES,
            key=lambda c: (local_mal_topk[c] - local_ben_topk[c], local_mal_topk[c]),
        )
        result["category_topk_margin"].append(build_signal(
            margin_category, local_mal_topk[margin_category],
            local_mal_topk[margin_category] - local_ben_topk[margin_category],
        ))

        nearest = np.argsort(scores)[-min(neighbor_k, len(scores)):]
        weights = np.maximum(scores[nearest], 0)
        weight_sum = float(weights.sum())
        if weight_sum <= 0:
            malicious_share = 0.0
        else:
            malicious_share = float(sum(
                float(weight) for i, weight in zip(nearest, weights)
                if references[int(i)]["label"] == "malicious"
            )) / weight_sum
        support_delta = malicious_share - malicious_reference_fraction
        category_votes = {
            c: sum(
                float(weight) for i, weight in zip(nearest, weights)
                if references[int(i)]["label"] == "malicious"
                and references[int(i)]["category"] == c
            ) for c in CATEGORIES
        }
        vote_category = max(CATEGORIES, key=lambda c: category_votes[c])
        if category_votes[vote_category] == 0:
            vote_category = global_category
        result["neighbor_vote"].append(build_signal(
            vote_category, global_mal, global_mal - global_ben, support_delta,
        ))
    return result, malicious_reference_fraction


def predicted(signal, sim_threshold, margin_threshold, support_threshold):
    detected = (
        signal["malicious_similarity"] >= sim_threshold
        and signal["margin"] >= margin_threshold
    )
    if support_threshold is not None:
        detected = detected and signal["support_delta"] >= support_threshold
    return bool(detected)


def score_metrics(validation, signals, sim_threshold, margin_threshold, support_threshold):
    tp = tn = fp = fn = oos_mal = oos_ben = oos_mal_hit = oos_ben_hit = 0
    correct_category = 0
    for record, signal in zip(validation, signals):
        detected = predicted(signal, sim_threshold, margin_threshold, support_threshold)
        if record["in_scope"]:
            if record["label"] == "malicious":
                if detected:
                    tp += 1
                    correct_category += int(signal["category"] == record["category"])
                else:
                    fn += 1
            elif detected:
                fp += 1
            else:
                tn += 1
        elif record["label"] == "malicious":
            oos_mal += 1
            oos_mal_hit += int(detected)
        else:
            oos_ben += 1
            oos_ben_hit += int(detected)

    def div(a, b):
        return a / b if b else 0.0

    precision = div(tp, tp + fp)
    recall = div(tp, tp + fn)
    specificity = div(tn, tn + fp)
    f1 = div(2 * precision * recall, precision + recall)
    return {
        "similarity_threshold": sim_threshold,
        "margin_threshold": margin_threshold,
        "support_threshold": support_threshold,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": div(tp + tn, tp + tn + fp + fn),
        "precision": precision, "recall": recall, "f1": f1,
        "specificity": specificity,
        "balanced_accuracy": (recall + specificity) / 2,
        "oos_mal_triggers": oos_mal_hit,
        "oos_mal_total": oos_mal,
        "oos_mal_trigger_rate": div(oos_mal_hit, oos_mal),
        "oos_ben_triggers": oos_ben_hit,
        "oos_ben_total": oos_ben,
        "oos_ben_trigger_rate": div(oos_ben_hit, oos_ben),
        "correct_category_detected": correct_category,
        "category_accuracy_on_detected": div(correct_category, tp),
        "category_end_to_end_recall": div(correct_category, tp + fn),
    }


def threshold_candidates(signal_values, size):
    """Model-specific, unlabeled-score-derived candidates, including reject-all boundary."""
    scores = np.asarray(signal_values, dtype=np.float64)
    levels = np.quantile(scores, np.linspace(0.0, 1.0, size))
    return sorted(set(float(x) for x in [float(np.min(scores)) - 1e-5, *levels, float(np.max(scores)) + 1e-5]))


def select_best(rows):
    if not rows:
        return None
    return max(rows, key=lambda row: (
        row["f1"], row["precision"], row["specificity"],
        -row["oos_mal_trigger_rate"], -row["oos_ben_trigger_rate"],
        row["category_end_to_end_recall"],
        row["similarity_threshold"], row["margin_threshold"],
        row["support_threshold"] if row["support_threshold"] is not None else -999,
    ))


def tune_strategy(validation, signals, strategy, grid_size, constraints, csv_path=None):
    sim_grid = threshold_candidates([s["malicious_similarity"] for s in signals], grid_size)
    margin_grid = threshold_candidates([s["margin"] for s in signals], grid_size)
    support_values = SUPPORT_THRESHOLDS if strategy == "neighbor_vote" else (None,)
    fields = None
    rows = []
    for sim_threshold in sim_grid:
        for margin_threshold in margin_grid:
            for support_threshold in support_values:
                row = score_metrics(validation, signals, sim_threshold, margin_threshold, support_threshold)
                row["strategy"] = strategy
                rows.append(row)
    best_f1 = select_best(rows)
    fp_limited = select_best([
        row for row in rows
        if row["fp"] <= constraints["max_fp"] and row["recall"] >= constraints["min_recall"]
    ])
    fully_constrained = select_best([
        row for row in rows
        if row["fp"] <= constraints["max_fp"]
        and row["recall"] >= constraints["min_recall"]
        and row["oos_mal_trigger_rate"] <= constraints["max_oos_mal_trigger_rate"]
    ])
    if csv_path is not None:
        with csv_path.open("a", encoding="utf-8", newline="") as target:
            writer = csv.DictWriter(target, fieldnames=list(rows[0]))
            if target.tell() == 0:
                writer.writeheader()
            writer.writerows(rows)
    return {
        "best_f1": best_f1,
        "fp_limited": fp_limited,
        "fully_constrained": fully_constrained,
        "threshold_combinations_evaluated": len(rows),
        "grid_dimensions": {"similarity": len(sim_grid), "margin": len(margin_grid), "support": len(support_values)},
    }


def save_json(path, value):
    with path.open("w", encoding="utf-8") as target:
        json.dump(value, target, indent=2, ensure_ascii=False)


def save_predictions(path, validation, signals, selection):
    with path.open("w", encoding="utf-8") as target:
        for record, signal in zip(validation, signals):
            detected = predicted(
                signal, selection["similarity_threshold"],
                selection["margin_threshold"], selection["support_threshold"],
            )
            error = "none"
            if record["in_scope"] and record["label"] == "benign" and detected:
                error = "false_positive"
            elif record["in_scope"] and record["label"] == "malicious" and not detected:
                error = "false_negative"
            elif record["in_scope"] and record["label"] == "malicious" and detected and signal["category"] != record["category"]:
                error = "category_error"
            elif not record["in_scope"] and detected:
                error = "out_of_scope_trigger"
            row = {
                "sample_id": record["sample_id"], "text": record["text"],
                "actual_label": record["label"], "actual_category": record.get("category"),
                "in_scope": record["in_scope"], "predicted_supported_attack": detected,
                "predicted_category": signal["category"] if detected else None,
                "error_type": error, "nearest_malicious_reference_id": signal["reference_id"],
                "malicious_similarity": signal["malicious_similarity"],
                "margin": signal["margin"], "support_delta": signal["support_delta"],
            }
            target.write(json.dumps(row, ensure_ascii=False) + "\n")


def rss_mb():
    try:
        import psutil
        return psutil.Process().memory_info().rss / (1024 ** 2)
    except ImportError:
        return None


def synchronize_if_cuda(device):
    if str(device).startswith("cuda"):
        import torch
        torch.cuda.synchronize(device)


def single_query_benchmark(model, queries, repetitions, device):
    # Warm up before measuring. Measure request-time single-input encode calls.
    for text in queries[:min(3, len(queries))]:
        model.encode([text], normalize_embeddings=True, convert_to_numpy=True, show_progress_bar=False)
    synchronize_if_cuda(device)
    samples = []
    for i in range(repetitions):
        text = queries[i % len(queries)]
        synchronize_if_cuda(device)
        start = perf_counter()
        model.encode([text], normalize_embeddings=True, convert_to_numpy=True, show_progress_bar=False)
        synchronize_if_cuda(device)
        samples.append((perf_counter() - start) * 1000)
    return {"samples": repetitions, "median_ms": median(samples), "p95_ms": float(np.percentile(samples, 95))}


def encode_model(model_name, references, validation, batch_size, latency_samples, device_arg, max_seq_length):
    from sentence_transformers import SentenceTransformer

    references_formatted, queries_formatted, format_name = input_texts(model_name, references, validation)
    before_load_rss = rss_mb()
    start = perf_counter()
    kwargs = {} if device_arg == "auto" else {"device": device_arg}
    model = SentenceTransformer(model_name, **kwargs)
    if max_seq_length is not None:
        model.max_seq_length = max_seq_length
    device = str(model.device)
    synchronize_if_cuda(device)
    load_seconds = perf_counter() - start
    after_load_rss = rss_mb()

    import torch
    if device.startswith("cuda"):
        torch.cuda.reset_peak_memory_stats(device)

    start = perf_counter()
    refs = model.encode(
        references_formatted, batch_size=batch_size,
        normalize_embeddings=True, convert_to_numpy=True, show_progress_bar=False,
    )
    synchronize_if_cuda(device)
    ref_seconds = perf_counter() - start

    start = perf_counter()
    queries = model.encode(
        queries_formatted, batch_size=batch_size,
        normalize_embeddings=True, convert_to_numpy=True, show_progress_bar=False,
    )
    synchronize_if_cuda(device)
    query_seconds = perf_counter() - start

    start = perf_counter()
    matrix = np.asarray(queries, dtype=np.float32) @ np.asarray(refs, dtype=np.float32).T
    similarity_seconds = perf_counter() - start
    latency = single_query_benchmark(model, queries_formatted, latency_samples, device)
    after_encode_rss = rss_mb()
    params = sum(p.numel() for p in model.parameters())
    param_bytes = sum(p.numel() * p.element_size() for p in model.parameters())
    gpu_peak = float(torch.cuda.max_memory_allocated(device) / (1024 ** 2)) if device.startswith("cuda") else None
    measurements = {
        "device": device,
        "embedding_dimensions": int(refs.shape[1]),
        "model_max_seq_length": model.max_seq_length,
        "input_format": format_name,
        "batch_size": batch_size,
        "load_seconds": load_seconds,
        "reference_encoding_seconds": ref_seconds,
        "validation_encoding_seconds": query_seconds,
        "similarity_matrix_seconds": similarity_seconds,
        "reference_records_per_second": len(references) / ref_seconds,
        "validation_records_per_second": len(validation) / query_seconds,
        "single_query_latency": latency,
        "parameter_count": int(params),
        "parameter_storage_mib": param_bytes / (1024 ** 2),
        "process_rss_before_load_mib": before_load_rss,
        "process_rss_after_load_mib": after_load_rss,
        "process_rss_after_encoding_mib": after_encode_rss,
        "gpu_peak_allocated_mib": gpu_peak,
    }
    del model, refs, queries
    gc.collect()
    if device.startswith("cuda"):
        torch.cuda.empty_cache()
    return matrix, measurements


def format_short(model, strategy, selection, row):
    if row is None:
        return f"{model:<14} {strategy:<21} {selection:<18} no qualifying configuration"
    return (
        f"{model:<14} {strategy:<21} {selection:<18} "
        f"P={row['precision']:.3f} R={row['recall']:.3f} F1={row['f1']:.3f} "
        f"FP={row['fp']:>2} OOS-M={row['oos_mal_triggers']}/{row['oos_mal_total']} "
        f"CAT={row['category_end_to_end_recall']:.3f}"
    )


def main():
    parser = argparse.ArgumentParser(description="BearBreach validation-only embedding model comparison")
    parser.add_argument("--references", required=True, type=Path)
    parser.add_argument("--validation", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--models", nargs="+", default=list(DEFAULT_MODELS), help="Hugging Face model names")
    parser.add_argument("--strategies", nargs="+", choices=STRATEGIES, default=list(STRATEGIES))
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument("--neighbor-k", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--grid-size", type=int, default=31, help="Score quantile steps per axis (model-specific)")
    parser.add_argument("--max-fp", type=int, default=5)
    parser.add_argument("--min-recall", type=float, default=0.70)
    parser.add_argument("--max-oos-mal-trigger-rate", type=float, default=0.33)
    parser.add_argument("--latency-samples", type=int, default=20)
    parser.add_argument("--device", default="auto", help="auto, cpu, cuda, cuda:0, etc.")
    parser.add_argument("--max-seq-length", type=int, default=None, help="Optional common truncation limit")
    parser.add_argument("--save-all-thresholds", action="store_true", help="Save large threshold CSV per model")
    args = parser.parse_args()

    if args.top_k < 1 or args.neighbor_k < 1 or args.batch_size < 1 or args.latency_samples < 1:
        parser.error("top-k, neighbor-k, batch-size, and latency-samples must be positive")
    if args.grid_size < 3:
        parser.error("grid-size must be >= 3")
    if args.max_seq_length is not None and args.max_seq_length < 1:
        parser.error("max-seq-length must be >= 1")
    if len(args.models) != len(set(args.models)):
        parser.error("models contains duplicates")
    if args.validation.name.lower() == "validation_results.jsonl":
        parser.error("Use the original validation.jsonl, NOT validation_results.jsonl")
    if args.validation.name.lower() == "test.jsonl" or args.validation.name.lower().startswith("holdout"):
        parser.error("Do not tune on held-out test data; use validation.jsonl")
    if not 0 <= args.min_recall <= 1 or not 0 <= args.max_oos_mal_trigger_rate <= 1:
        parser.error("recall and OOS trigger rate constraints must be in [0, 1]")

    references = load_jsonl(args.references)
    validation = load_jsonl(args.validation)
    check_data(references, validation, args.validation)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    constraints = {
        "max_fp": args.max_fp,
        "min_recall": args.min_recall,
        "max_oos_mal_trigger_rate": args.max_oos_mal_trigger_rate,
    }
    versions = {}
    for package in ("numpy", "sentence-transformers", "torch"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = None
    summary = {
        "purpose": "validation_only_model_comparison",
        "reference_file_sha256": sha256_file(args.references),
        "validation_file_sha256": sha256_file(args.validation),
        "reference_count": len(references), "validation_count": len(validation),
        "corpus_malicious_reference_fraction": sum(r["label"] == "malicious" for r in references) / len(references),
        "top_k": args.top_k, "neighbor_k": args.neighbor_k,
        "grid_size": args.grid_size, "constraints": constraints,
        "package_versions": versions, "models": {},
        "warning": (
            "Scores and thresholds are model-specific. These are validation-tuned, exploratory "
            "results on a small synthetic dataset; do not use the held-out test set to tune. "
            "Model download can inflate first-load timing."
        ),
    }
    leaderboard = []
    print(f"References={len(references)} Validation={len(validation)}")
    print("Selection: fully_constrained > fp_limited > best_f1 (report separately; never treat as test results)")
    for model_name in args.models:
        short_name = model_name.rsplit("/", 1)[-1]
        out_dir = args.output_dir / short_name
        out_dir.mkdir(parents=True, exist_ok=True)
        print(f"\n=== MODEL: {model_name} ===", flush=True)
        matrix, performance = encode_model(
            model_name, references, validation, args.batch_size, args.latency_samples,
            args.device, args.max_seq_length,
        )
        signals_by_strategy, prior = make_signals(
            references, validation, matrix, args.top_k, args.neighbor_k,
        )
        del matrix
        csv_path = out_dir / "all_threshold_results.csv" if args.save_all_thresholds else None
        if csv_path is not None and csv_path.exists():
            csv_path.unlink()
        model_result = {"model": model_name, "performance": performance, "strategies": {},
                        "malicious_reference_fraction": prior}
        for strategy in args.strategies:
            configurations = tune_strategy(
                validation, signals_by_strategy[strategy], strategy,
                args.grid_size, constraints, csv_path,
            )
            model_result["strategies"][strategy] = configurations
            for selection in ("best_f1", "fp_limited", "fully_constrained"):
                row = configurations[selection]
                print(format_short(short_name, strategy, selection, row), flush=True)
                if row is not None:
                    save_predictions(
                        out_dir / f"{strategy}_{selection}_predictions.jsonl",
                        validation, signals_by_strategy[strategy], row,
                    )
                    leaderboard.append({
                        "model": model_name, "strategy": strategy, "selection": selection,
                        **row,
                        "single_query_median_ms": performance["single_query_latency"]["median_ms"],
                        "single_query_p95_ms": performance["single_query_latency"]["p95_ms"],
                        "parameter_storage_mib": performance["parameter_storage_mib"],
                        "gpu_peak_allocated_mib": performance["gpu_peak_allocated_mib"],
                    })
        save_json(out_dir / "model_results.json", model_result)
        summary["models"][model_name] = model_result
        # Preserve completed models if a later model download/inference fails.
        save_json(args.output_dir / "model_comparison.json", summary)
    if leaderboard:
        with (args.output_dir / "model_leaderboard.csv").open("w", newline="", encoding="utf-8") as target:
            writer = csv.DictWriter(target, fieldnames=list(leaderboard[0]))
            writer.writeheader()
            writer.writerows(leaderboard)
    print(f"\nSaved to {args.output_dir}")
    print("Compare fully_constrained or fp_limited rows FIRST; do not select by F1 alone.")
    print("Do not run the held-out test set until ONE model + strategy + thresholds is frozen.")


if __name__ == "__main__":
    main()
