#!/usr/bin/env python3
"""Explore a BearBreach JSONL corpus and generate a dataset manifest.

Examples:
    python explore_corpus.py final_candidates/corpus.jsonl
    python explore_corpus.py final_candidates/corpus.jsonl --version 0.1.0 --json
    python explore_corpus.py final_candidates/corpus.jsonl --output manifest.json

Uses Python's standard library. Does not modify the dataset or generate embeddings.
Exit codes: 0 = manifest saved, integrity checks passed; 1 = manifest saved with
data-quality problems; 2 = malformed input, command-line error, or save failure.
This is an exploration/integrity tool, not a replacement for validate_corpus.py
or human review of malicious/benign labels.
"""

import argparse  # Parses the dataset path, version, and output options.
import hashlib  # Fingerprints the file and verifies individual text hashes.
import json  # Reads each JSONL object and serializes the JSON manifest.
import os  # Atomically replaces a completed manifest and syncs file contents.
import statistics  # Calculates mean and median text lengths.
import sys  # Supplies exit codes and stderr for operational failures.
import tempfile  # Writes the manifest safely before publishing its final name.
from collections import Counter, defaultdict  # Counts values and groups duplicates.
from datetime import datetime, timezone  # Parses record dates and records UTC time.
from pathlib import Path  # Handles input/output paths.


# These fields support exploration of the current canonical corpus schema.
REQUIRED_FIELDS = [
    "reference_id", "text", "label", "category", "related_category",
    "semantic_family", "artifact_type", "source_type", "source_name",
    "source_id", "language", "review_status", "sha256", "created_at",
]
STRING_FIELDS = [field for field in REQUIRED_FIELDS if field not in ("sha256", "created_at")]
MALICIOUS_CATEGORIES = [
    "prompt_injection", "jailbreak", "role_manipulation", "system_prompt_extraction",
]
COUNT_FIELDS = [
    "label", "category", "related_category", "semantic_family", "language",
    "artifact_type", "source_name", "source_type", "review_status",
]


def reject_constant(value):
    """Reject nonstandard JSON values such as NaN and Infinity."""
    raise ValueError(f"Nonstandard JSON constant: {value}")


def reject_duplicate_keys(pairs):
    """Catch duplicate keys before json.loads could silently overwrite them."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Repeated JSON key: {key!r}")
        result[key] = value
    return result


def load_corpus(path):
    """Read one byte snapshot for both parsing and the whole-file fingerprint."""
    # Hash the original bytes, including formatting and line endings. Parsing
    # the same snapshot ensures the counts and fingerprint describe one file.
    raw_bytes = Path(path).read_bytes()
    decoded = raw_bytes.decode("utf-8")
    records = []
    # Split on LF rather than all Unicode separators, which can occur in text.
    lines = decoded.split("\n")
    if lines[-1] == "":
        lines.pop()  # A normal terminating newline is not an empty JSONL record.
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            raise ValueError(f"Line {line_number}: blank JSONL line.")
        try:
            sample = json.loads(line, object_pairs_hook=reject_duplicate_keys,
                                parse_constant=reject_constant)
        except (ValueError, RecursionError) as error:
            raise ValueError(f"Line {line_number}: {error}") from error
        if not isinstance(sample, dict):
            raise ValueError(f"Line {line_number}: expected a JSON object.")
        missing = [field for field in REQUIRED_FIELDS if field not in sample]
        if missing:
            raise ValueError(f"Line {line_number}: missing fields {missing!r}.")
        for field in STRING_FIELDS:
            if not isinstance(sample[field], str) or not sample[field].strip():
                raise ValueError(f"Line {line_number}: {field} must be a nonempty string.")
        # Known labels are essential: otherwise the requested malicious/benign
        # totals could silently exclude records and misrepresent this dataset.
        if sample["label"] not in ("malicious", "benign"):
            raise ValueError(f"Line {line_number}: unknown label {sample['label']!r}.")
        records.append(sample)
    if not records:
        raise ValueError("The corpus is empty.")
    return records, raw_bytes


def value_counts(records, field):
    """Return alphabetically sorted counts for stable, readable manifests."""
    return dict(sorted(Counter(sample[field] for sample in records).items()))


def duplicate_summary(records, field, normalize=False):
    """Report duplicate groups with their physical JSONL line numbers."""
    groups = defaultdict(list)
    for line_number, sample in enumerate(records, 1):
        value = sample[field]
        # Normalize only for text comparison; never modify the saved text/hash.
        key = " ".join(value.split()).casefold() if normalize else value
        groups[key].append(line_number)
    duplicates = [lines for lines in groups.values() if len(lines) > 1]
    return {
        "group_count": len(duplicates),
        # Count only occurrences after the first, not all members of each group.
        "extra_record_count": sum(len(lines) - 1 for lines in duplicates),
        "groups": [{"lines": lines} for lines in duplicates],
    }


def length_summary(lengths):
    """Summarize a nonempty list of lengths; these are not tokenizer counts."""
    return {
        "min": min(lengths), "max": max(lengths),
        "mean": round(statistics.mean(lengths), 2),
        "median": statistics.median(lengths),
    }


def build_manifest(records, raw_bytes, dataset_path, corpus_name, version):
    """Build statistics and preparation-integrity checks without altering records."""
    counts = {field: value_counts(records, field) for field in COUNT_FIELDS}
    problems = []
    valid_dates = []
    verified_hash_count = 0

    def problem(line, field, message):
        problems.append({"line": line, "field": field, "message": message})

    for line_number, sample in enumerate(records, 1):
        # For prepared candidates, each hash must match the exact text bytes.
        actual_hash = hashlib.sha256(sample["text"].encode("utf-8")).hexdigest()
        if sample["sha256"] != actual_hash:
            problem(line_number, "sha256", "Missing or incorrect text SHA-256.")
        else:
            verified_hash_count += 1

        # Accept ISO-8601 timestamps with an explicit UTC offset, including Z.
        # Null values in raw seeds become reported preparation problems.
        timestamp = sample["created_at"]
        try:
            if not isinstance(timestamp, str) or "T" not in timestamp:
                raise ValueError("Expected an ISO-8601 timestamp.")
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            offset = parsed.utcoffset()
            if offset is None or offset.total_seconds() != 0:
                raise ValueError("Expected a UTC timestamp with an explicit offset.")
            valid_dates.append(parsed.astimezone(timezone.utc))
        except (ValueError, OverflowError):
            problem(line_number, "created_at", "Missing or invalid UTC creation timestamp.")

        # Ensure benign records name a related malicious concept, while
        # malicious records use the same category and related_category.
        if sample["related_category"] not in MALICIOUS_CATEGORIES:
            problem(line_number, "related_category", "Unknown related category.")
        if sample["label"] == "benign":
            if sample["category"] != "benign":
                problem(line_number, "category", "Benign label requires benign category.")
        elif (sample["category"] not in MALICIOUS_CATEGORIES
              or sample["related_category"] != sample["category"]):
            problem(line_number, "category", "Invalid malicious category relationship.")
        extras = sorted(set(sample) - set(REQUIRED_FIELDS))
        if extras:
            problem(line_number, None, f"Unexpected fields: {extras!r}.")

    duplicates = {
        "reference_id": duplicate_summary(records, "reference_id"),
        "source_id": duplicate_summary(records, "source_id"),
        "exact_text": duplicate_summary(records, "text"),
        "normalized_text": duplicate_summary(records, "text", normalize=True),
    }
    # Exact text duplicates also occur in normalized groups; these overlapping
    # checks are displayed separately and their totals should not be added.
    has_duplicates = any(value["group_count"] for value in duplicates.values())
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    format_date = lambda value: value.isoformat().replace("+00:00", "Z")

    # All figures come from the records, not the illustrative counts in the prompt.
    return {
        "manifest_schema_version": "1.0.0",
        "corpus_name": corpus_name,
        "version": version,
        "purpose": "embedding_reference_corpus",
        "generated_at": now,
        "dataset_file": Path(dataset_path).name,
        "dataset_size_bytes": len(raw_bytes),
        "dataset_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "reference_count": len(records),
        "malicious_count": counts["label"].get("malicious", 0),
        "benign_count": counts["label"].get("benign", 0),
        "languages": list(counts["language"]),
        "artifact_types": list(counts["artifact_type"]),
        "sources": list(counts["source_name"]),
        "label_counts": counts["label"],
        "category_counts": counts["category"],
        "related_category_counts": counts["related_category"],
        "benign_related_category_counts": value_counts(
            [sample for sample in records if sample["label"] == "benign"], "related_category"),
        "semantic_family_counts": counts["semantic_family"],
        "language_counts": counts["language"],
        "artifact_type_counts": counts["artifact_type"],
        "source_counts": counts["source_name"],
        "source_type_counts": counts["source_type"],
        "review_status_counts": counts["review_status"],
        "text_length_statistics": {
            "characters": length_summary([len(sample["text"]) for sample in records]),
            "utf8_bytes": length_summary([len(sample["text"].encode("utf-8")) for sample in records]),
            "whitespace_separated_words": length_summary([len(sample["text"].split()) for sample in records]),
        },
        "record_created_at_range": {
            "earliest": format_date(min(valid_dates)) if valid_dates else None,
            "latest": format_date(max(valid_dates)) if valid_dates else None,
        },
        "data_quality": {
            "integrity_checks_passed": not problems and not has_duplicates,
            "verified_text_hash_count": verified_hash_count,
            "valid_creation_timestamp_count": len(valid_dates),
            "duplicates": duplicates,
            "record_issue_count": len(problems),
            "record_issues": problems,
            "normalized_text_comparison": "casefold_and_collapse_whitespace",
            "semantic_near_duplicates_checked": False,
            "human_label_review_performed_by_script": False,
        },
    }


def save_manifest(manifest, output_path):
    """Publish a complete JSON manifest; refresh an existing manifest on reruns."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        # Keeping the temporary file in the same folder permits atomic replace.
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=output_path.parent, delete=False,
                                         prefix=".manifest-", suffix=".json") as handle:
            temporary_path = Path(handle.name)
            json.dump(manifest, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main():
    # The default output is <dataset-stem>.manifest.json beside the dataset.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="Final JSONL dataset")
    parser.add_argument("--corpus-name", default="bearbreach-semantic-corpus")
    parser.add_argument("--version", default="0.1.0", help="Dataset version, assigned by you")
    parser.add_argument("--output", type=Path, help="Manifest destination; refreshed on reruns")
    parser.add_argument("--json", action="store_true", help="Also print the full manifest as JSON")
    args = parser.parse_args()
    if not args.corpus_name.strip() or not args.version.strip():
        parser.error("Corpus name and version must be nonempty.")
    output = args.output if args.output is not None else args.file.with_suffix(".manifest.json")
    # Resolve paths and check hard links to prevent replacing the input dataset.
    if output.resolve() == args.file.resolve() or (
        output.exists() and args.file.exists() and output.samefile(args.file)
    ):
        parser.error("Manifest output must be different from the input dataset.")
    try:
        records, raw_bytes = load_corpus(args.file)
        manifest = build_manifest(records, raw_bytes, args.file, args.corpus_name, args.version)
        save_manifest(manifest, output)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"Cannot create manifest: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(manifest, indent=2, ensure_ascii=False))
    else:
        print(f"Corpus: {manifest['corpus_name']} | Version: {manifest['version']}")
        print(f"References: {manifest['reference_count']} | Malicious: {manifest['malicious_count']} | Benign: {manifest['benign_count']}")
        for title, field in [("Categories", "category_counts"),
                             ("Sources", "source_counts"),
                             ("Review statuses", "review_status_counts")]:
            print(f"{title}:")
            for value, count in manifest[field].items():
                print(f"  {value}: {count}")
        lengths = manifest["text_length_statistics"]["characters"]
        print(f"Text characters: min={lengths['min']}, median={lengths['median']}, mean={lengths['mean']}, max={lengths['max']}")
        for field, summary in manifest["data_quality"]["duplicates"].items():
            print(f"Duplicate {field}: {summary['group_count']} groups, {summary['extra_record_count']} extra records")
        print(f"Integrity: {'PASS' if manifest['data_quality']['integrity_checks_passed'] else 'FAIL (see manifest details)'}")
        print(f"Manifest saved: {output}")
    # A problem manifest is still useful for exploration, but exit 1 tells
    # automated pipelines that this corpus should not advance without fixes.
    return 0 if manifest["data_quality"]["integrity_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())  # Importing the module does not execute the CLI.
