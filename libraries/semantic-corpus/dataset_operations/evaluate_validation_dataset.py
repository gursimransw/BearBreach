import argparse
import json
from pathlib import Path
from statistics import mean, median
from time import perf_counter

import numpy as np
from sentence_transformers import SentenceTransformer


DEFAULT_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
TOP_K = 5


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
# DETERMINE EVALUATION GROUP
# ============================================================

def get_evaluation_group(record):

    if (
        record["in_scope"] is True
        and record["label"] == "malicious"
    ):
        return "in_scope_malicious"

    if (
        record["in_scope"] is True
        and record["label"] == "benign"
    ):
        return "in_scope_benign"

    if (
        record["in_scope"] is False
        and record["label"] == "malicious"
    ):
        return "out_of_scope_malicious"

    if (
        record["in_scope"] is False
        and record["label"] == "benign"
    ):
        return "out_of_scope_benign"

    raise ValueError(
        f"Unable to determine evaluation group "
        f"for sample: {record.get('sample_id')}"
    )


# ============================================================
# FIND BEST MATCH
# ============================================================

def find_best_match(
    similarities,
    reference_records,
    required_label=None
):

    best_index = -1
    best_similarity = -1.0

    for index, reference in enumerate(reference_records):

        # If we are searching specifically for malicious
        # or benign references, skip everything else.
        if (
            required_label is not None
            and reference["label"] != required_label
        ):
            continue

        similarity_score = float(
            similarities[index]
        )

        if similarity_score > best_similarity:

            best_similarity = similarity_score
            best_index = index


    # Previously this function returned None here.
    #
    # That caused the interpreter to correctly warn that
    # later code such as:
    #
    # top_malicious_match["similarity"]
    #
    # could potentially attempt to index None.
    #
    # A missing match is not a valid condition for this
    # experiment, so we fail explicitly instead.
    if best_index == -1:

        if required_label is None:
            match_description = "reference"
        else:
            match_description = (
                f"{required_label} reference"
            )

        raise ValueError(
            f"No {match_description} was found "
            f"in the reference corpus."
        )


    reference = reference_records[
        best_index
    ]


    return {
        "reference_id": reference["reference_id"],
        "similarity": best_similarity,
        "label": reference["label"],
        "category": reference["category"],
        "related_category": reference.get(
            "related_category"
        ),
        "semantic_family": reference.get(
            "semantic_family"
        ),
        "text": reference["text"],
    }


# ============================================================
# GET TOP-K MATCHES
# ============================================================

def get_top_k_matches(
    similarities,
    reference_records,
    top_k
):

    sorted_indexes = np.argsort(
        similarities
    )[::-1]

    top_indexes = sorted_indexes[
        :top_k
    ]

    matches = []

    for reference_index in top_indexes:

        reference = reference_records[
            reference_index
        ]

        matches.append(
            {
                "reference_id": reference[
                    "reference_id"
                ],

                "similarity": float(
                    similarities[
                        reference_index
                    ]
                ),

                "label": reference[
                    "label"
                ],

                "category": reference[
                    "category"
                ],

                "related_category": reference.get(
                    "related_category"
                ),

                "semantic_family": reference.get(
                    "semantic_family"
                ),

                "text": reference[
                    "text"
                ],
            }
        )

    return matches


# ============================================================
# CALCULATE STATISTICS
# ============================================================

def calculate_statistics(values):

    # Previously this returned None.
    #
    # Since build_summary only calls this when a group
    # contains results, an empty list represents an error.
    if not values:
        raise ValueError(
            "Cannot calculate statistics "
            "for an empty list."
        )

    return {
        "count": len(values),
        "min": float(min(values)),
        "max": float(max(values)),
        "mean": float(mean(values)),
        "median": float(median(values)),
    }


# ============================================================
# BUILD SUMMARY
# ============================================================

def build_summary(results):

    groups = {}

    possible_groups = [
        "in_scope_malicious",
        "in_scope_benign",
        "out_of_scope_malicious",
        "out_of_scope_benign",
    ]

    for group_name in possible_groups:

        group_results = [
            result
            for result in results
            if result["evaluation_group"]
            == group_name
        ]

        # It is perfectly valid for one evaluation dataset
        # not to contain a particular group.
        #
        # In that case we simply do not add the group
        # to the summary.
        if not group_results:
            continue


        malicious_scores = [
            result["max_malicious_similarity"]
            for result in group_results
        ]


        benign_scores = [
            result["max_benign_similarity"]
            for result in group_results
        ]


        margins = [
            result["semantic_margin"]
            for result in group_results
        ]


        groups[group_name] = {

            "count": len(
                group_results
            ),

            "max_malicious_similarity":
                calculate_statistics(
                    malicious_scores
                ),

            "max_benign_similarity":
                calculate_statistics(
                    benign_scores
                ),

            "semantic_margin":
                calculate_statistics(
                    margins
                ),
        }


    return groups


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Evaluate BearBreach semantic references "
            "against the validation dataset."
        )
    )


    parser.add_argument(
        "--references",
        required=True,
        help="Path to references.jsonl."
    )


    parser.add_argument(
        "--validation",
        required=True,
        help="Path to validation.jsonl."
    )


    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory where results will be saved."
    )


    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help="Sentence Transformer model name."
    )


    arguments = parser.parse_args()


    reference_path = Path(
        arguments.references
    )

    validation_path = Path(
        arguments.validation
    )

    output_directory = Path(
        arguments.output_dir
    )


    # ========================================================
    # LOAD DATA
    # ========================================================

    print("=" * 100)
    print("LOADING DATA")
    print("=" * 100)


    reference_records = load_jsonl(
        reference_path
    )


    validation_records = load_jsonl(
        validation_path
    )


    if not reference_records:
        raise ValueError(
            "Reference corpus is empty."
        )


    if not validation_records:
        raise ValueError(
            "Validation dataset is empty."
        )


    print(
        f"Reference records: "
        f"{len(reference_records)}"
    )


    print(
        f"Validation records: "
        f"{len(validation_records)}"
    )


    # Make sure the reference corpus contains
    # both labels required by our experiment.
    reference_labels = {
        record["label"]
        for record in reference_records
    }


    if "malicious" not in reference_labels:
        raise ValueError(
            "Reference corpus contains no "
            "malicious references."
        )


    if "benign" not in reference_labels:
        raise ValueError(
            "Reference corpus contains no "
            "benign references."
        )


    reference_texts = [
        record["text"]
        for record in reference_records
    ]


    validation_texts = [
        record["text"]
        for record in validation_records
    ]


    # ========================================================
    # LOAD MODEL
    # ========================================================

    print("\n" + "=" * 100)
    print("LOADING MODEL")
    print("=" * 100)


    model_load_start = perf_counter()


    model = SentenceTransformer(
        arguments.model
    )


    model_load_time_ms = (
        perf_counter()
        - model_load_start
    ) * 1000


    print(
        f"Model: {arguments.model}"
    )


    print(
        f"Model load time: "
        f"{model_load_time_ms:.2f} ms"
    )


    # ========================================================
    # REFERENCE EMBEDDINGS
    # ========================================================

    print("\n" + "=" * 100)
    print("ENCODING REFERENCE CORPUS")
    print("=" * 100)


    reference_start = perf_counter()


    reference_embeddings = model.encode(
        reference_texts,
        normalize_embeddings=True,
        convert_to_numpy=True,
        show_progress_bar=True
    )


    reference_encoding_time_ms = (
        perf_counter()
        - reference_start
    ) * 1000


    print(
        f"Reference matrix shape: "
        f"{reference_embeddings.shape}"
    )


    print(
        f"Reference encoding time: "
        f"{reference_encoding_time_ms:.2f} ms"
    )


    # ========================================================
    # VALIDATION EMBEDDINGS
    # ========================================================

    print("\n" + "=" * 100)
    print("ENCODING VALIDATION DATASET")
    print("=" * 100)


    validation_start = perf_counter()


    validation_embeddings = model.encode(
        validation_texts,
        normalize_embeddings=True,
        convert_to_numpy=True,
        show_progress_bar=True
    )


    validation_encoding_time_ms = (
        perf_counter()
        - validation_start
    ) * 1000


    print(
        f"Validation matrix shape: "
        f"{validation_embeddings.shape}"
    )


    print(
        f"Validation encoding time: "
        f"{validation_encoding_time_ms:.2f} ms"
    )


    # ========================================================
    # SIMILARITY MATRIX
    # ========================================================

    print("\n" + "=" * 100)
    print("CALCULATING SIMILARITIES")
    print("=" * 100)


    similarity_start = perf_counter()


    similarity_matrix = np.dot(
        validation_embeddings,
        reference_embeddings.T
    )


    similarity_time_ms = (
        perf_counter()
        - similarity_start
    ) * 1000


    print(
        f"Similarity matrix shape: "
        f"{similarity_matrix.shape}"
    )


    print(
        f"Similarity calculation time: "
        f"{similarity_time_ms:.2f} ms"
    )


    # ========================================================
    # ANALYZE EACH VALIDATION SAMPLE
    # ========================================================

    results = []


    for validation_index, validation_record in enumerate(
        validation_records
    ):

        similarities = similarity_matrix[
            validation_index
        ]


        top_overall_match = find_best_match(
            similarities,
            reference_records
        )


        top_malicious_match = find_best_match(
            similarities,
            reference_records,
            required_label="malicious"
        )


        top_benign_match = find_best_match(
            similarities,
            reference_records,
            required_label="benign"
        )


        top_k_matches = get_top_k_matches(
            similarities,
            reference_records,
            TOP_K
        )


        max_malicious_similarity = float(
            top_malicious_match[
                "similarity"
            ]
        )


        max_benign_similarity = float(
            top_benign_match[
                "similarity"
            ]
        )


        semantic_margin = (
            max_malicious_similarity
            -
            max_benign_similarity
        )


        result = {

            "sample_id":
                validation_record[
                    "sample_id"
                ],

            "text":
                validation_record[
                    "text"
                ],

            "actual_label":
                validation_record[
                    "label"
                ],

            "actual_category":
                validation_record[
                    "category"
                ],

            "related_category":
                validation_record.get(
                    "related_category"
                ),

            "difficulty":
                validation_record[
                    "difficulty"
                ],

            "evaluation_type":
                validation_record[
                    "evaluation_type"
                ],

            "in_scope":
                validation_record[
                    "in_scope"
                ],

            "evaluation_group":
                get_evaluation_group(
                    validation_record
                ),

            "max_malicious_similarity":
                max_malicious_similarity,

            "max_benign_similarity":
                max_benign_similarity,

            "semantic_margin":
                semantic_margin,

            "closest_malicious_category":
                top_malicious_match[
                    "category"
                ],

            "top_overall_match":
                top_overall_match,

            "top_malicious_match":
                top_malicious_match,

            "top_benign_match":
                top_benign_match,

            "top_k_matches":
                top_k_matches,
        }


        results.append(
            result
        )


    # ========================================================
    # BUILD SUMMARY
    # ========================================================

    summary = {

        "model":
            arguments.model,

        "reference_count":
            len(reference_records),

        "validation_count":
            len(validation_records),

        "embedding_dimension":
            int(
                reference_embeddings.shape[1]
            ),

        "performance": {

            "model_load_ms":
                model_load_time_ms,

            "reference_encoding_ms":
                reference_encoding_time_ms,

            "validation_encoding_ms":
                validation_encoding_time_ms,

            "similarity_calculation_ms":
                similarity_time_ms,
        },

        "groups":
            build_summary(
                results
            ),
    }


    # ========================================================
    # SAVE OUTPUT
    # ========================================================

    results_path = (
        output_directory
        / "validation_results.jsonl"
    )


    summary_path = (
        output_directory
        / "validation_summary.json"
    )


    save_jsonl(
        results,
        results_path
    )


    save_json(
        summary,
        summary_path
    )


    # ========================================================
    # PRINT SUMMARY
    # ========================================================

    print("\n" + "=" * 100)
    print("VALIDATION SUMMARY")
    print("=" * 100)


    for group_name, group_data in summary[
        "groups"
    ].items():

        malicious_statistics = (
            group_data[
                "max_malicious_similarity"
            ]
        )

        benign_statistics = (
            group_data[
                "max_benign_similarity"
            ]
        )

        margin_statistics = (
            group_data[
                "semantic_margin"
            ]
        )


        print(
            f"\n{group_name}"
        )


        print(
            "  Count:",
            group_data[
                "count"
            ]
        )


        print(
            "  Malicious similarity mean:",
            f"{malicious_statistics['mean']:.4f}"
        )


        print(
            "  Benign similarity mean:",
            f"{benign_statistics['mean']:.4f}"
        )


        print(
            "  Margin mean:",
            f"{margin_statistics['mean']:.4f}"
        )


        print(
            "  Margin median:",
            f"{margin_statistics['median']:.4f}"
        )


    print("\n" + "=" * 100)
    print("OUTPUT")
    print("=" * 100)


    print(
        f"Detailed results: "
        f"{results_path}"
    )


    print(
        f"Summary: "
        f"{summary_path}"
    )


    print(
        "\nNo detection threshold "
        "has been applied."
    )


if __name__ == "__main__":
    main()