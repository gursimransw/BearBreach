#This script will be used to split the evaluation dataset into 2 sets, for both validation and test

import argparse
import json
from collections import Counter
from pathlib import Path

from sklearn.model_selection import train_test_split


RANDOM_STATE = 42
VALIDATION_SIZE = 100
TEST_SIZE = 40


def load_jsonl(file_path: Path):
    records = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):

            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
                records.append(record)

            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Invalid JSON on line {line_number}: {error}"
                ) from error

    return records


def save_jsonl(records, file_path: Path):
    file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(file_path, "w", encoding="utf-8") as file:
        for record in records:
            file.write(
                json.dumps(
                    record,
                    ensure_ascii=False
                )
                + "\n"
            )


def get_stratum(record):
    """
    Create the main grouping used during stratified splitting.

    We do not stratify on every field such as difficulty +
    evaluation_type + semantic_family because that would create
    many tiny groups.

    Instead we preserve the security-relevant groups.
    """

    label = record["label"]
    category = record["category"]
    related_category = record.get("related_category", "none")
    in_scope = record["in_scope"]

    # Supported malicious category.
    if in_scope and label == "malicious":
        return f"in_scope_malicious::{category}"

    # Hard-benign example associated with one supported category.
    if in_scope and label == "benign":
        return f"in_scope_benign::{related_category}"

    # Malicious but not one of the currently supported semantic categories.
    if not in_scope and label == "malicious":
        return "out_of_scope_malicious"

    # Normal unrelated benign request.
    if not in_scope and label == "benign":
        return "out_of_scope_benign"

    return "unknown"


def print_distribution(name, records):
    print("\n" + "=" * 100)
    print(name)
    print("=" * 100)

    print(f"Total records: {len(records)}")

    print("\nLabels:")
    print(
        dict(
            Counter(
                record["label"]
                for record in records
            )
        )
    )

    print("\nCategories:")
    print(
        dict(
            Counter(
                record["category"]
                for record in records
            )
        )
    )

    print("\nRelated categories:")
    print(
        dict(
            Counter(
                record.get("related_category", "none")
                for record in records
            )
        )
    )

    print("\nIn scope:")
    print(
        dict(
            Counter(
                record["in_scope"]
                for record in records
            )
        )
    )

    print("\nDifficulty:")
    print(
        dict(
            Counter(
                record["difficulty"]
                for record in records
            )
        )
    )

    print("\nEvaluation type:")
    print(
        dict(
            Counter(
                record["evaluation_type"]
                for record in records
            )
        )
    )

    print("\nEvaluation strata:")
    print(
        dict(
            Counter(
                get_stratum(record)
                for record in records
            )
        )
    )


def validate_records(records):
    required_fields = [
        "sample_id",
        "text",
        "label",
        "category",
        "related_category",
        "semantic_family",
        "difficulty",
        "evaluation_type",
        "in_scope",
        "artifact_type",
        "language",
    ]

    sample_ids = set()

    for index, record in enumerate(records, start=1):

        for field in required_fields:
            if field not in record:
                raise ValueError(
                    f"Record {index} is missing required field: {field}"
                )

        sample_id = record["sample_id"]

        if sample_id in sample_ids:
            raise ValueError(
                f"Duplicate sample_id found: {sample_id}"
            )

        sample_ids.add(sample_id)

    print(
        f"Validated {len(records)} evaluation records."
    )


def main():
    parser = argparse.ArgumentParser(
        description="Split BearBreach semantic evaluation dataset."
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to complete evaluation JSONL dataset."
    )

    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory where validation.jsonl and test.jsonl will be saved."
    )

    arguments = parser.parse_args()

    input_path = Path(arguments.input)
    output_directory = Path(arguments.output_dir)

    records = load_jsonl(input_path)

    validate_records(records)

    expected_total = VALIDATION_SIZE + TEST_SIZE

    if len(records) != expected_total:
        raise ValueError(
            f"Expected {expected_total} records, "
            f"but found {len(records)}."
        )

    strata = [
        get_stratum(record)
        for record in records
    ]

    stratum_counts = Counter(strata)

    print("\nStratum counts before splitting:")
    for stratum, count in sorted(stratum_counts.items()):
        print(f"{stratum}: {count}")

    # Stratified splitting requires every group to have enough
    # examples to appear in both partitions.
    for stratum, count in stratum_counts.items():
        if count < 2:
            raise ValueError(
                f"Stratum '{stratum}' only contains {count} record(s). "
                f"Stratified splitting cannot safely split this group."
            )

    validation_records, test_records = train_test_split(
        records,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        shuffle=True,
        stratify=strata
    )

    # Sort by sample_id so the resulting files remain readable.
    validation_records.sort(
        key=lambda record: record["sample_id"]
    )

    test_records.sort(
        key=lambda record: record["sample_id"]
    )

    validation_path = (
        output_directory / "validation.jsonl"
    )

    test_path = (
        output_directory / "test.jsonl"
    )

    save_jsonl(
        validation_records,
        validation_path
    )

    save_jsonl(
        test_records,
        test_path
    )

    print_distribution(
        "VALIDATION DATASET",
        validation_records
    )

    print_distribution(
        "TEST DATASET",
        test_records
    )

    print("\n" + "=" * 100)
    print("SPLIT COMPLETE")
    print("=" * 100)

    print(
        f"Validation dataset: "
        f"{validation_path} "
        f"({len(validation_records)} records)"
    )

    print(
        f"Test dataset: "
        f"{test_path} "
        f"({len(test_records)} records)"
    )

    print(
        f"\nRandom state: {RANDOM_STATE}"
    )


if __name__ == "__main__":
    main()