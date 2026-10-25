import argparse
import csv
import json
from pathlib import Path


# ============================================================
# LOAD JSONL
# ============================================================

def load_jsonl(file_path: Path):

    records = []

    with open(file_path, "r", encoding="utf-8") as file:

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

            records.append(record)

    return records


# ============================================================
# SAFE DIVISION
# ============================================================

def safe_divide(numerator, denominator):

    if denominator == 0:
        return 0.0

    return numerator / denominator


# ============================================================
# CALCULATE BINARY METRICS
# ============================================================

def calculate_binary_metrics(
    results,
    similarity_threshold,
    margin_threshold
):

    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0

    in_scope_records = [
        record
        for record in results
        if record["in_scope"] is True
    ]

    for record in in_scope_records:

        actual_label = record["actual_label"]

        max_malicious_similarity = record[
            "max_malicious_similarity"
        ]

        semantic_margin = record[
            "semantic_margin"
        ]


        # ----------------------------------------------------
        # DETECTION RULE
        # ----------------------------------------------------
        #
        # A sample is predicted malicious only when:
        #
        # 1. It is sufficiently close to a malicious reference
        #
        # AND
        #
        # 2. Malicious similarity is sufficiently stronger
        #    than benign similarity.
        #
        predicted_malicious = (
            max_malicious_similarity
            >= similarity_threshold
            and
            semantic_margin
            >= margin_threshold
        )


        if (
            actual_label == "malicious"
            and predicted_malicious
        ):
            true_positive += 1


        elif (
            actual_label == "benign"
            and not predicted_malicious
        ):
            true_negative += 1


        elif (
            actual_label == "benign"
            and predicted_malicious
        ):
            false_positive += 1


        elif (
            actual_label == "malicious"
            and not predicted_malicious
        ):
            false_negative += 1


    total = (
        true_positive
        + true_negative
        + false_positive
        + false_negative
    )


    accuracy = safe_divide(
        true_positive + true_negative,
        total
    )


    precision = safe_divide(
        true_positive,
        true_positive + false_positive
    )


    recall = safe_divide(
        true_positive,
        true_positive + false_negative
    )


    specificity = safe_divide(
        true_negative,
        true_negative + false_positive
    )


    if precision + recall == 0:
        f1_score = 0.0

    else:
        f1_score = (
            2
            * precision
            * recall
            / (precision + recall)
        )


    false_positive_rate = safe_divide(
        false_positive,
        false_positive + true_negative
    )


    false_negative_rate = safe_divide(
        false_negative,
        false_negative + true_positive
    )


    balanced_accuracy = (
        recall + specificity
    ) / 2


    return {
        "similarity_threshold": similarity_threshold,
        "margin_threshold": margin_threshold,

        "true_positive": true_positive,
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,

        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1_score,
        "specificity": specificity,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
        "balanced_accuracy": balanced_accuracy,
    }


# ============================================================
# CALCULATE OUT-OF-SCOPE BEHAVIOUR
# ============================================================

def calculate_out_of_scope_metrics(
    results,
    similarity_threshold,
    margin_threshold
):

    out_of_scope_records = [
        record
        for record in results
        if record["in_scope"] is False
    ]


    unsupported_malicious_total = 0
    unsupported_malicious_triggered = 0

    unrelated_benign_total = 0
    unrelated_benign_triggered = 0


    for record in out_of_scope_records:

        predicted_supported_attack = (
            record["max_malicious_similarity"]
            >= similarity_threshold
            and
            record["semantic_margin"]
            >= margin_threshold
        )


        # Malicious, but not one of our supported semantic
        # categories.
        if record["actual_label"] == "malicious":

            unsupported_malicious_total += 1

            if predicted_supported_attack:
                unsupported_malicious_triggered += 1


        # Benign and unrelated to the supported categories.
        elif record["actual_label"] == "benign":

            unrelated_benign_total += 1

            if predicted_supported_attack:
                unrelated_benign_triggered += 1


    unsupported_malicious_abstained = (
        unsupported_malicious_total
        - unsupported_malicious_triggered
    )


    unrelated_benign_abstained = (
        unrelated_benign_total
        - unrelated_benign_triggered
    )


    unsupported_malicious_abstention_rate = safe_divide(
        unsupported_malicious_abstained,
        unsupported_malicious_total
    )


    unrelated_benign_abstention_rate = safe_divide(
        unrelated_benign_abstained,
        unrelated_benign_total
    )


    unsupported_malicious_trigger_rate = safe_divide(
        unsupported_malicious_triggered,
        unsupported_malicious_total
    )


    unrelated_benign_trigger_rate = safe_divide(
        unrelated_benign_triggered,
        unrelated_benign_total
    )


    return {
        "unsupported_malicious_total":
            unsupported_malicious_total,

        "unsupported_malicious_triggered":
            unsupported_malicious_triggered,

        "unsupported_malicious_abstained":
            unsupported_malicious_abstained,

        "unsupported_malicious_abstention_rate":
            unsupported_malicious_abstention_rate,

        "unsupported_malicious_trigger_rate":
            unsupported_malicious_trigger_rate,

        "unrelated_benign_total":
            unrelated_benign_total,

        "unrelated_benign_triggered":
            unrelated_benign_triggered,

        "unrelated_benign_abstained":
            unrelated_benign_abstained,

        "unrelated_benign_abstention_rate":
            unrelated_benign_abstention_rate,

        "unrelated_benign_trigger_rate":
            unrelated_benign_trigger_rate,
    }


# ============================================================
# CATEGORY ACCURACY
# ============================================================

def calculate_category_metrics(
    results,
    similarity_threshold,
    margin_threshold
):

    total_in_scope_malicious = 0

    correct_closest_category = 0

    detected_malicious = 0

    correct_category_when_detected = 0


    supported_categories = [
        "prompt_injection",
        "jailbreak",
        "role_manipulation",
        "system_prompt_extraction",
    ]


    confusion_matrix = {}

    for actual_category in supported_categories:

        confusion_matrix[actual_category] = {}

        for predicted_category in supported_categories:

            confusion_matrix[actual_category][
                predicted_category
            ] = 0


    for record in results:

        if not (
            record["in_scope"] is True
            and
            record["actual_label"] == "malicious"
        ):
            continue


        total_in_scope_malicious += 1


        actual_category = record[
            "actual_category"
        ]


        predicted_category = record[
            "closest_malicious_category"
        ]


        if actual_category == predicted_category:
            correct_closest_category += 1


        if (
            actual_category in confusion_matrix
            and
            predicted_category
            in confusion_matrix[actual_category]
        ):
            confusion_matrix[
                actual_category
            ][
                predicted_category
            ] += 1


        predicted_malicious = (
            record["max_malicious_similarity"]
            >= similarity_threshold
            and
            record["semantic_margin"]
            >= margin_threshold
        )


        if predicted_malicious:

            detected_malicious += 1

            if actual_category == predicted_category:
                correct_category_when_detected += 1


    closest_category_accuracy = safe_divide(
        correct_closest_category,
        total_in_scope_malicious
    )


    detected_category_accuracy = safe_divide(
        correct_category_when_detected,
        detected_malicious
    )


    return {
        "total_in_scope_malicious":
            total_in_scope_malicious,

        "correct_closest_category":
            correct_closest_category,

        "closest_category_accuracy":
            closest_category_accuracy,

        "detected_malicious":
            detected_malicious,

        "correct_category_when_detected":
            correct_category_when_detected,

        "detected_category_accuracy":
            detected_category_accuracy,

        "confusion_matrix":
            confusion_matrix,
    }


# ============================================================
# PRINT CONFUSION MATRIX
# ============================================================

def print_category_confusion_matrix(
    confusion_matrix
):

    categories = [
        "prompt_injection",
        "jailbreak",
        "role_manipulation",
        "system_prompt_extraction",
    ]


    short_names = {
        "prompt_injection": "PI",
        "jailbreak": "JB",
        "role_manipulation": "RM",
        "system_prompt_extraction": "SPE",
    }


    print("\nCategory confusion matrix")
    print(
        "Actual \\ Predicted".ljust(22),
        "PI".rjust(7),
        "JB".rjust(7),
        "RM".rjust(7),
        "SPE".rjust(7),
    )


    for actual_category in categories:

        row = confusion_matrix[
            actual_category
        ]

        print(
            short_names[
                actual_category
            ].ljust(22),

            str(
                row["prompt_injection"]
            ).rjust(7),

            str(
                row["jailbreak"]
            ).rjust(7),

            str(
                row["role_manipulation"]
            ).rjust(7),

            str(
                row["system_prompt_extraction"]
            ).rjust(7),
        )


# ============================================================
# SAVE ALL THRESHOLD RESULTS
# ============================================================

def save_csv(records, file_path: Path):

    file_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )


    if not records:
        raise ValueError(
            "No threshold results were generated."
        )


    field_names = list(
        records[0].keys()
    )


    with open(
        file_path,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=field_names
        )

        writer.writeheader()

        writer.writerows(
            records
        )


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Sweep semantic detector thresholds and "
            "calculate validation metrics."
        )
    )


    parser.add_argument(
        "--results",
        required=True,
        help=(
            "Path to validation_results.jsonl "
            "created by evaluate_validation.py."
        )
    )


    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory where threshold metrics will be saved."
    )


    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of best threshold combinations to display."
    )


    arguments = parser.parse_args()


    results_path = Path(
        arguments.results
    )


    output_directory = Path(
        arguments.output_dir
    )


    results = load_jsonl(
        results_path
    )


    if not results:
        raise ValueError(
            "Validation results file is empty."
        )


    print("=" * 100)
    print("THRESHOLD EVALUATION")
    print("=" * 100)


    print(
        f"Loaded validation results: "
        f"{len(results)}"
    )


    # ========================================================
    # THRESHOLD SEARCH RANGE
    # ========================================================
    #
    # Similarity:
    # 0.20 -> 0.70
    #
    # Margin:
    # -0.10 -> 0.20
    #
    # Step:
    # 0.01
    #
    # Using integers avoids floating-point range issues.
    # ========================================================


    threshold_results = []


    for similarity_integer in range(
        20,
        71
    ):

        similarity_threshold = (
            similarity_integer / 100
        )


        for margin_integer in range(
            -10,
            21
        ):

            margin_threshold = (
                margin_integer / 100
            )


            binary_metrics = (
                calculate_binary_metrics(
                    results,
                    similarity_threshold,
                    margin_threshold
                )
            )


            out_of_scope_metrics = (
                calculate_out_of_scope_metrics(
                    results,
                    similarity_threshold,
                    margin_threshold
                )
            )


            combined_result = {
                **binary_metrics,

                "unsupported_malicious_trigger_rate":
                    out_of_scope_metrics[
                        "unsupported_malicious_trigger_rate"
                    ],

                "unsupported_malicious_abstention_rate":
                    out_of_scope_metrics[
                        "unsupported_malicious_abstention_rate"
                    ],

                "unrelated_benign_trigger_rate":
                    out_of_scope_metrics[
                        "unrelated_benign_trigger_rate"
                    ],

                "unrelated_benign_abstention_rate":
                    out_of_scope_metrics[
                        "unrelated_benign_abstention_rate"
                    ],
            }


            threshold_results.append(
                combined_result
            )


    print(
        f"Threshold combinations tested: "
        f"{len(threshold_results)}"
    )


    # ========================================================
    # SORT BY F1
    # ========================================================

    ranked_results = sorted(
        threshold_results,
        key=lambda result: (
            result["f1"],
            result["precision"],
            result["recall"],
            result["specificity"],
        ),
        reverse=True
    )


    # ========================================================
    # DISPLAY BEST RESULTS
    # ========================================================

    top_count = min(
        arguments.top,
        len(ranked_results)
    )


    print("\n" + "=" * 100)
    print(
        f"TOP {top_count} CONFIGURATIONS BY F1"
    )
    print("=" * 100)


    header = (
        f"{'#':<4}"
        f"{'SIM':>7}"
        f"{'MARGIN':>9}"
        f"{'ACC':>8}"
        f"{'PREC':>8}"
        f"{'RECALL':>8}"
        f"{'F1':>8}"
        f"{'SPEC':>8}"
        f"{'FP':>5}"
        f"{'FN':>5}"
        f"{'OOS-M':>8}"
        f"{'OOS-B':>8}"
    )


    print(header)
    print("-" * len(header))


    for index in range(top_count):

        result = ranked_results[index]


        print(
            f"{index + 1:<4}"
            f"{result['similarity_threshold']:>7.2f}"
            f"{result['margin_threshold']:>9.2f}"
            f"{result['accuracy']:>8.3f}"
            f"{result['precision']:>8.3f}"
            f"{result['recall']:>8.3f}"
            f"{result['f1']:>8.3f}"
            f"{result['specificity']:>8.3f}"
            f"{result['false_positive']:>5}"
            f"{result['false_negative']:>5}"
            f"{result['unsupported_malicious_trigger_rate']:>8.3f}"
            f"{result['unrelated_benign_trigger_rate']:>8.3f}"
        )


    # ========================================================
    # BEST RESULT
    # ========================================================

    best_result = ranked_results[
        0
    ]


    print("\n" + "=" * 100)
    print("BEST F1 CONFIGURATION")
    print("=" * 100)


    print(
        f"Similarity threshold: "
        f"{best_result['similarity_threshold']:.2f}"
    )


    print(
        f"Margin threshold: "
        f"{best_result['margin_threshold']:.2f}"
    )


    print("\nConfusion matrix:")


    print(
        f"TP: {best_result['true_positive']}"
    )

    print(
        f"TN: {best_result['true_negative']}"
    )

    print(
        f"FP: {best_result['false_positive']}"
    )

    print(
        f"FN: {best_result['false_negative']}"
    )


    print("\nMetrics:")


    print(
        f"Accuracy:          "
        f"{best_result['accuracy']:.4f}"
    )


    print(
        f"Precision:         "
        f"{best_result['precision']:.4f}"
    )


    print(
        f"Recall:            "
        f"{best_result['recall']:.4f}"
    )


    print(
        f"F1:                "
        f"{best_result['f1']:.4f}"
    )


    print(
        f"Specificity:       "
        f"{best_result['specificity']:.4f}"
    )


    print(
        f"Balanced accuracy: "
        f"{best_result['balanced_accuracy']:.4f}"
    )


    print(
        f"False positive rate: "
        f"{best_result['false_positive_rate']:.4f}"
    )


    print(
        f"False negative rate: "
        f"{best_result['false_negative_rate']:.4f}"
    )


    # ========================================================
    # OUT-OF-SCOPE RESULTS FOR BEST THRESHOLDS
    # ========================================================

    best_out_of_scope = (
        calculate_out_of_scope_metrics(
            results,

            best_result[
                "similarity_threshold"
            ],

            best_result[
                "margin_threshold"
            ]
        )
    )


    print("\n" + "=" * 100)
    print("OUT-OF-SCOPE BEHAVIOUR")
    print("=" * 100)


    print(
        "Unsupported malicious:"
    )


    print(
        f"  Total:      "
        f"{best_out_of_scope['unsupported_malicious_total']}"
    )


    print(
        f"  Triggered:  "
        f"{best_out_of_scope['unsupported_malicious_triggered']}"
    )


    print(
        f"  Abstained:  "
        f"{best_out_of_scope['unsupported_malicious_abstained']}"
    )


    print(
        f"  Abstention rate: "
        f"{best_out_of_scope['unsupported_malicious_abstention_rate']:.4f}"
    )


    print(
        "\nUnrelated benign:"
    )


    print(
        f"  Total:      "
        f"{best_out_of_scope['unrelated_benign_total']}"
    )


    print(
        f"  Triggered:  "
        f"{best_out_of_scope['unrelated_benign_triggered']}"
    )


    print(
        f"  Abstained:  "
        f"{best_out_of_scope['unrelated_benign_abstained']}"
    )


    print(
        f"  Abstention rate: "
        f"{best_out_of_scope['unrelated_benign_abstention_rate']:.4f}"
    )


    # ========================================================
    # CATEGORY METRICS
    # ========================================================

    category_metrics = (
        calculate_category_metrics(
            results,

            best_result[
                "similarity_threshold"
            ],

            best_result[
                "margin_threshold"
            ]
        )
    )


    print("\n" + "=" * 100)
    print("CATEGORY PERFORMANCE")
    print("=" * 100)


    print(
        f"Total in-scope malicious: "
        f"{category_metrics['total_in_scope_malicious']}"
    )


    print(
        f"Correct closest category: "
        f"{category_metrics['correct_closest_category']}"
    )


    print(
        f"Closest-category accuracy: "
        f"{category_metrics['closest_category_accuracy']:.4f}"
    )


    print(
        f"\nDetected malicious: "
        f"{category_metrics['detected_malicious']}"
    )


    print(
        f"Correct category when detected: "
        f"{category_metrics['correct_category_when_detected']}"
    )


    print(
        f"Category accuracy when detected: "
        f"{category_metrics['detected_category_accuracy']:.4f}"
    )


    print_category_confusion_matrix(
        category_metrics[
            "confusion_matrix"
        ]
    )


    # ========================================================
    # SAVE RESULTS
    # ========================================================

    output_directory.mkdir(
        parents=True,
        exist_ok=True
    )


    csv_path = (
        output_directory
        / "threshold_results.csv"
    )


    best_result_path = (
        output_directory
        / "best_thresholds.json"
    )


    save_csv(
        threshold_results,
        csv_path
    )


    final_best_result = {
        "thresholds": {
            "similarity_threshold":
                best_result[
                    "similarity_threshold"
                ],

            "margin_threshold":
                best_result[
                    "margin_threshold"
                ],
        },

        "binary_metrics":
            best_result,

        "out_of_scope_metrics":
            best_out_of_scope,

        "category_metrics":
            category_metrics,
    }


    with open(
        best_result_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            final_best_result,
            file,
            indent=2,
            ensure_ascii=False
        )


    print("\n" + "=" * 100)
    print("OUTPUT FILES")
    print("=" * 100)


    print(
        f"All threshold combinations: "
        f"{csv_path}"
    )


    print(
        f"Best configuration: "
        f"{best_result_path}"
    )


if __name__ == "__main__":
    main()