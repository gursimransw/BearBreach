#This script will check for errors like False Positives, Flase Negatives, Category Mismatch issues
#Within the evaluation results that have been calculated for all the samples with respect to the 
#Reference Corpus
import argparse
import json
from collections import Counter
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
# SAVE JSONL
# ============================================================

def save_jsonl(records, file_path: Path):

    file_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(file_path, "w", encoding="utf-8") as file:

        for record in records:

            file.write(
                json.dumps(
                    record,
                    ensure_ascii=False
                )
                + "\n"
            )


# ============================================================
# SAVE JSON
# ============================================================

def save_json(data, file_path: Path):

    file_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(file_path, "w", encoding="utf-8") as file:

        json.dump(
            data,
            file,
            indent=2,
            ensure_ascii=False
        )


# ============================================================
# APPLY CURRENT DETECTION RULE
# ============================================================

def is_predicted_malicious(
    record,
    similarity_threshold,
    margin_threshold
):

    return (
        record["max_malicious_similarity"]
        >= similarity_threshold

        and

        record["semantic_margin"]
        >= margin_threshold
    )


# ============================================================
# BUILD ERROR RECORD
# ============================================================

def build_error_record(
    record,
    error_type,
    similarity_threshold,
    margin_threshold
):

    predicted_malicious = is_predicted_malicious(
        record,
        similarity_threshold,
        margin_threshold
    )


    return {

        "error_type":
            error_type,

        "sample_id":
            record["sample_id"],

        "text":
            record["text"],

        "actual_label":
            record["actual_label"],

        "actual_category":
            record["actual_category"],

        "related_category":
            record.get(
                "related_category"
            ),

        "difficulty":
            record["difficulty"],

        "evaluation_type":
            record["evaluation_type"],

        "in_scope":
            record["in_scope"],

        "predicted_malicious":
            predicted_malicious,

        "closest_malicious_category":
            record[
                "closest_malicious_category"
            ],

        "max_malicious_similarity":
            record[
                "max_malicious_similarity"
            ],

        "max_benign_similarity":
            record[
                "max_benign_similarity"
            ],

        "semantic_margin":
            record[
                "semantic_margin"
            ],

        "top_overall_match":
            record[
                "top_overall_match"
            ],

        "top_malicious_match":
            record[
                "top_malicious_match"
            ],

        "top_benign_match":
            record[
                "top_benign_match"
            ],

        "top_k_matches":
            record[
                "top_k_matches"
            ],
    }


# ============================================================
# ANALYZE RESULTS
# ============================================================

def analyze_errors(
    results,
    similarity_threshold,
    margin_threshold
):

    false_positives = []
    false_negatives = []

    category_errors = []

    unsupported_malicious_triggers = []
    unrelated_benign_triggers = []


    for record in results:

        predicted_malicious = is_predicted_malicious(
            record,
            similarity_threshold,
            margin_threshold
        )


        # ====================================================
        # IN-SCOPE MALICIOUS
        # ====================================================

        if (
            record["in_scope"] is True
            and
            record["actual_label"] == "malicious"
        ):

            # False negative:
            #
            # This should have triggered,
            # but the detector abstained.
            if not predicted_malicious:

                false_negatives.append(
                    build_error_record(
                        record,
                        "false_negative",
                        similarity_threshold,
                        margin_threshold
                    )
                )


            # Category error:
            #
            # The detector identified malicious evidence,
            # but the closest malicious category was wrong.
            if (
                predicted_malicious
                and
                record["closest_malicious_category"]
                != record["actual_category"]
            ):

                category_errors.append(
                    build_error_record(
                        record,
                        "category_error",
                        similarity_threshold,
                        margin_threshold
                    )
                )


        # ====================================================
        # IN-SCOPE BENIGN
        # ====================================================

        elif (
            record["in_scope"] is True
            and
            record["actual_label"] == "benign"
        ):

            # False positive:
            #
            # Hard-benign sample incorrectly triggered
            # a malicious semantic finding.
            if predicted_malicious:

                false_positives.append(
                    build_error_record(
                        record,
                        "false_positive",
                        similarity_threshold,
                        margin_threshold
                    )
                )


        # ====================================================
        # OUT-OF-SCOPE MALICIOUS
        # ====================================================

        elif (
            record["in_scope"] is False
            and
            record["actual_label"] == "malicious"
        ):

            if predicted_malicious:

                unsupported_malicious_triggers.append(
                    build_error_record(
                        record,
                        "unsupported_malicious_trigger",
                        similarity_threshold,
                        margin_threshold
                    )
                )


        # ====================================================
        # UNRELATED BENIGN
        # ====================================================

        elif (
            record["in_scope"] is False
            and
            record["actual_label"] == "benign"
        ):

            if predicted_malicious:

                unrelated_benign_triggers.append(
                    build_error_record(
                        record,
                        "unrelated_benign_trigger",
                        similarity_threshold,
                        margin_threshold
                    )
                )


    return {
        "false_positives":
            false_positives,

        "false_negatives":
            false_negatives,

        "category_errors":
            category_errors,

        "unsupported_malicious_triggers":
            unsupported_malicious_triggers,

        "unrelated_benign_triggers":
            unrelated_benign_triggers,
    }


# ============================================================
# COUNT FIELD VALUES
# ============================================================

def count_field(records, field_name):

    values = []

    for record in records:

        value = record.get(
            field_name
        )

        if value is not None:
            values.append(value)


    return dict(
        Counter(values)
    )


# ============================================================
# BUILD ERROR SUMMARY
# ============================================================

def build_error_summary(
    error_groups,
    similarity_threshold,
    margin_threshold
):

    summary = {

        "thresholds": {
            "similarity_threshold":
                similarity_threshold,

            "margin_threshold":
                margin_threshold,
        },

        "error_counts": {},

        "false_positive_breakdown": {},

        "false_negative_breakdown": {},

        "category_error_breakdown": {},

        "unsupported_malicious_breakdown": {},

        "unrelated_benign_breakdown": {},
    }


    for group_name, records in error_groups.items():

        summary[
            "error_counts"
        ][
            group_name
        ] = len(records)


    false_positives = error_groups[
        "false_positives"
    ]

    false_negatives = error_groups[
        "false_negatives"
    ]

    category_errors = error_groups[
        "category_errors"
    ]

    unsupported_malicious = error_groups[
        "unsupported_malicious_triggers"
    ]

    unrelated_benign = error_groups[
        "unrelated_benign_triggers"
    ]


    summary[
        "false_positive_breakdown"
    ] = {

        "by_related_category":
            count_field(
                false_positives,
                "related_category"
            ),

        "by_difficulty":
            count_field(
                false_positives,
                "difficulty"
            ),

        "by_evaluation_type":
            count_field(
                false_positives,
                "evaluation_type"
            ),

        "by_predicted_category":
            count_field(
                false_positives,
                "closest_malicious_category"
            ),
    }


    summary[
        "false_negative_breakdown"
    ] = {

        "by_actual_category":
            count_field(
                false_negatives,
                "actual_category"
            ),

        "by_difficulty":
            count_field(
                false_negatives,
                "difficulty"
            ),

        "by_evaluation_type":
            count_field(
                false_negatives,
                "evaluation_type"
            ),
    }


    summary[
        "category_error_breakdown"
    ] = {

        "by_actual_category":
            count_field(
                category_errors,
                "actual_category"
            ),

        "by_predicted_category":
            count_field(
                category_errors,
                "closest_malicious_category"
            ),

        "by_difficulty":
            count_field(
                category_errors,
                "difficulty"
            ),

        "by_evaluation_type":
            count_field(
                category_errors,
                "evaluation_type"
            ),
    }


    summary[
        "unsupported_malicious_breakdown"
    ] = {

        "by_predicted_category":
            count_field(
                unsupported_malicious,
                "closest_malicious_category"
            ),

        "by_difficulty":
            count_field(
                unsupported_malicious,
                "difficulty"
            ),
    }


    summary[
        "unrelated_benign_breakdown"
    ] = {

        "by_predicted_category":
            count_field(
                unrelated_benign,
                "closest_malicious_category"
            ),

        "by_difficulty":
            count_field(
                unrelated_benign,
                "difficulty"
            ),
    }


    return summary


# ============================================================
# PRINT BREAKDOWN
# ============================================================

def print_breakdown(
    title,
    records
):

    print("\n" + "=" * 100)
    print(title)
    print("=" * 100)

    print(
        f"Count: {len(records)}"
    )


    if not records:
        return


    print(
        "\nDifficulty:"
    )

    for value, count in count_field(
        records,
        "difficulty"
    ).items():

        print(
            f"  {value}: {count}"
        )


    print(
        "\nEvaluation type:"
    )

    for value, count in count_field(
        records,
        "evaluation_type"
    ).items():

        print(
            f"  {value}: {count}"
        )


# ============================================================
# PRINT INDIVIDUAL ERROR
# ============================================================

def print_error_record(
    record,
    show_top_matches
):

    print("\n" + "-" * 100)

    print(
        f"Sample ID: "
        f"{record['sample_id']}"
    )

    print(
        f"Error type: "
        f"{record['error_type']}"
    )

    print(
        f"Actual label: "
        f"{record['actual_label']}"
    )

    print(
        f"Actual category: "
        f"{record['actual_category']}"
    )

    print(
        f"Related category: "
        f"{record['related_category']}"
    )

    print(
        f"Predicted category: "
        f"{record['closest_malicious_category']}"
    )

    print(
        f"Difficulty: "
        f"{record['difficulty']}"
    )

    print(
        f"Evaluation type: "
        f"{record['evaluation_type']}"
    )


    print(
        "\nScores:"
    )

    print(
        f"  Malicious similarity: "
        f"{record['max_malicious_similarity']:.4f}"
    )

    print(
        f"  Benign similarity:    "
        f"{record['max_benign_similarity']:.4f}"
    )

    print(
        f"  Semantic margin:      "
        f"{record['semantic_margin']:.4f}"
    )


    print(
        "\nInput:"
    )

    print(
        record["text"]
    )


    print(
        "\nClosest malicious reference:"
    )

    malicious_match = record[
        "top_malicious_match"
    ]

    print(
        f"  ID: "
        f"{malicious_match['reference_id']}"
    )

    print(
        f"  Category: "
        f"{malicious_match['category']}"
    )

    print(
        f"  Similarity: "
        f"{malicious_match['similarity']:.4f}"
    )

    print(
        f"  Text: "
        f"{malicious_match['text']}"
    )


    print(
        "\nClosest benign reference:"
    )

    benign_match = record[
        "top_benign_match"
    ]

    print(
        f"  ID: "
        f"{benign_match['reference_id']}"
    )

    print(
        f"  Related category: "
        f"{benign_match['related_category']}"
    )

    print(
        f"  Similarity: "
        f"{benign_match['similarity']:.4f}"
    )

    print(
        f"  Text: "
        f"{benign_match['text']}"
    )


    if show_top_matches:

        print(
            "\nTop semantic matches:"
        )

        for rank, match in enumerate(
            record["top_k_matches"],
            start=1
        ):

            print(
                f"\n  #{rank}"
            )

            print(
                f"    Similarity: "
                f"{match['similarity']:.4f}"
            )

            print(
                f"    Label: "
                f"{match['label']}"
            )

            print(
                f"    Category: "
                f"{match['category']}"
            )

            print(
                f"    Related category: "
                f"{match['related_category']}"
            )

            print(
                f"    Reference ID: "
                f"{match['reference_id']}"
            )

            print(
                f"    Text: "
                f"{match['text']}"
            )


# ============================================================
# PRINT CATEGORY CONFUSIONS
# ============================================================

def print_category_confusions(
    category_errors
):

    print("\n" + "=" * 100)
    print("CATEGORY CONFUSIONS")
    print("=" * 100)


    if not category_errors:

        print(
            "No category errors."
        )

        return


    confusion_counter = Counter()


    for record in category_errors:

        confusion_key = (
            record["actual_category"],
            record["closest_malicious_category"]
        )

        confusion_counter[
            confusion_key
        ] += 1


    for (
        actual_category,
        predicted_category
    ), count in confusion_counter.most_common():

        print(
            f"{actual_category} "
            f"-> "
            f"{predicted_category}: "
            f"{count}"
        )


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Explore BearBreach semantic detector "
            "false positives, false negatives, "
            "category errors and out-of-scope triggers."
        )
    )


    parser.add_argument(
        "--results",
        required=True,
        help=(
            "Path to validation_results.jsonl."
        )
    )


    parser.add_argument(
        "--output-dir",
        required=True,
        help=(
            "Directory where error analysis "
            "files will be saved."
        )
    )


    parser.add_argument(
        "--similarity-threshold",
        type=float,
        default=0.20,
        help=(
            "Malicious similarity threshold."
        )
    )


    parser.add_argument(
        "--margin-threshold",
        type=float,
        default=-0.05,
        help=(
            "Semantic margin threshold."
        )
    )


    parser.add_argument(
        "--show-details",
        action="store_true",
        help=(
            "Print every error sample."
        )
    )


    parser.add_argument(
        "--show-top-matches",
        action="store_true",
        help=(
            "Print the top-k references "
            "for each displayed error."
        )
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
    print("BEARBREACH SEMANTIC ERROR ANALYSIS")
    print("=" * 100)


    print(
        f"Validation records: "
        f"{len(results)}"
    )


    print(
        f"Similarity threshold: "
        f"{arguments.similarity_threshold:.2f}"
    )


    print(
        f"Margin threshold: "
        f"{arguments.margin_threshold:.2f}"
    )


    # ========================================================
    # ANALYZE ERRORS
    # ========================================================

    error_groups = analyze_errors(
        results,
        arguments.similarity_threshold,
        arguments.margin_threshold
    )


    summary = build_error_summary(
        error_groups,
        arguments.similarity_threshold,
        arguments.margin_threshold
    )


    # ========================================================
    # PRINT HIGH-LEVEL BREAKDOWN
    # ========================================================

    print_breakdown(
        "FALSE POSITIVES",
        error_groups[
            "false_positives"
        ]
    )


    print_breakdown(
        "FALSE NEGATIVES",
        error_groups[
            "false_negatives"
        ]
    )


    print_breakdown(
        "CATEGORY ERRORS",
        error_groups[
            "category_errors"
        ]
    )


    print_breakdown(
        "UNSUPPORTED MALICIOUS TRIGGERS",
        error_groups[
            "unsupported_malicious_triggers"
        ]
    )


    print_breakdown(
        "UNRELATED BENIGN TRIGGERS",
        error_groups[
            "unrelated_benign_triggers"
        ]
    )


    print_category_confusions(
        error_groups[
            "category_errors"
        ]
    )


    # ========================================================
    # OPTIONAL DETAILED OUTPUT
    # ========================================================

    if arguments.show_details:

        print("\n" + "=" * 100)
        print("DETAILED FALSE POSITIVES")
        print("=" * 100)

        for record in error_groups[
            "false_positives"
        ]:

            print_error_record(
                record,
                arguments.show_top_matches
            )


        print("\n" + "=" * 100)
        print("DETAILED FALSE NEGATIVES")
        print("=" * 100)

        for record in error_groups[
            "false_negatives"
        ]:

            print_error_record(
                record,
                arguments.show_top_matches
            )


        print("\n" + "=" * 100)
        print("DETAILED CATEGORY ERRORS")
        print("=" * 100)

        for record in error_groups[
            "category_errors"
        ]:

            print_error_record(
                record,
                arguments.show_top_matches
            )


        print("\n" + "=" * 100)
        print("DETAILED UNSUPPORTED MALICIOUS TRIGGERS")
        print("=" * 100)

        for record in error_groups[
            "unsupported_malicious_triggers"
        ]:

            print_error_record(
                record,
                arguments.show_top_matches
            )


        print("\n" + "=" * 100)
        print("DETAILED UNRELATED BENIGN TRIGGERS")
        print("=" * 100)

        for record in error_groups[
            "unrelated_benign_triggers"
        ]:

            print_error_record(
                record,
                arguments.show_top_matches
            )


    # ========================================================
    # SAVE OUTPUT
    # ========================================================

    output_directory.mkdir(
        parents=True,
        exist_ok=True
    )


    false_positive_path = (
        output_directory
        / "false_positives.jsonl"
    )


    false_negative_path = (
        output_directory
        / "false_negatives.jsonl"
    )


    category_errors_path = (
        output_directory
        / "category_errors.jsonl"
    )


    unsupported_path = (
        output_directory
        / "unsupported_malicious_triggers.jsonl"
    )


    unrelated_benign_path = (
        output_directory
        / "unrelated_benign_triggers.jsonl"
    )


    summary_path = (
        output_directory
        / "error_summary.json"
    )


    save_jsonl(
        error_groups[
            "false_positives"
        ],
        false_positive_path
    )


    save_jsonl(
        error_groups[
            "false_negatives"
        ],
        false_negative_path
    )


    save_jsonl(
        error_groups[
            "category_errors"
        ],
        category_errors_path
    )


    save_jsonl(
        error_groups[
            "unsupported_malicious_triggers"
        ],
        unsupported_path
    )


    save_jsonl(
        error_groups[
            "unrelated_benign_triggers"
        ],
        unrelated_benign_path
    )


    save_json(
        summary,
        summary_path
    )


    print("\n" + "=" * 100)
    print("OUTPUT FILES")
    print("=" * 100)


    print(
        f"False positives: "
        f"{false_positive_path}"
    )

    print(
        f"False negatives: "
        f"{false_negative_path}"
    )

    print(
        f"Category errors: "
        f"{category_errors_path}"
    )

    print(
        f"Unsupported malicious triggers: "
        f"{unsupported_path}"
    )

    print(
        f"Unrelated benign triggers: "
        f"{unrelated_benign_path}"
    )

    print(
        f"Summary: "
        f"{summary_path}"
    )


if __name__ == "__main__":
    main()