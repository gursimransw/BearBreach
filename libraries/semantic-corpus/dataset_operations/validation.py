#!/usr/bin/env python3
"""Validate BearBreach's v1 synthetic seed JSONL corpus (standard library only).

Run: python validate_corpus.py corpus.jsonl
Use --json for a machine-readable report or --expected-count 200 for a count check.
Use --prepare to save a validated copy in final_candidates beside the input.
Use --output-dir PATH with --prepare to choose a different destination folder.
Exit codes: 0 = valid, 1 = validation errors, 2 = file/CLI errors.

This validates the pre-ingestion schema: sha256 and created_at must be null.
semantic_family is an open vocabulary. Text duplicate detection normalizes case
and whitespace; it does not detect semantic near-duplicates or review labels.
"""

import argparse  # Reads command-line arguments such as --prepare and --json.
import hashlib  # Calculates SHA-256 fingerprints from text bytes.
import json  # Converts JSON strings to Python values and back again.
import os  # Provides file syncing and atomic hard-link publication.
import re  # Checks ID formats with regular expressions.
import sys  # Supplies stderr and lets the program return an exit code.
import tempfile  # Creates a temporary file while the final copy is being written.
from collections import Counter  # Counts categories and types of validation issue.
from datetime import datetime, timezone  # Generates timestamps explicitly in UTC.
from pathlib import Path  # Handles file paths and folders across operating systems.


# These lists describe the allowed vocabulary of the initial synthetic corpus.
# Expand them deliberately when supporting more sources or artifact types.
MALICIOUS_CATEGORIES = [
    "prompt_injection", "jailbreak", "role_manipulation",
    "system_prompt_extraction",
]
# The * unpacks the malicious list, then adds the benign category.
VALID_CATEGORIES = [*MALICIOUS_CATEGORIES, "benign"]
VALID_LABELS = ["malicious", "benign"]
# Even benign examples identify the malicious concept they resemble.
# copy() creates a separate list instead of sharing the same mutable list.
VALID_RELATED_CATEGORIES = MALICIOUS_CATEGORIES.copy()
VALID_ARTIFACT_TYPES = ["user_input"]
VALID_SOURCE_TYPES = ["llm_generated"]
VALID_SOURCE_NAMES = ["synthetic_seed_corpus"]
VALID_LANGUAGES = ["en"]
VALID_REVIEW_STATUSES = ["candidate"]
# Raw inputs have JSON null in these fields, which Python parses as None.
# --prepare fills them only AFTER validation. Prepared files are therefore
# outputs of this raw-input validator, not inputs it will accept unchanged.
VALID_SHA256_VALUES = [None]
VALID_CREATED_AT_VALUES = [None]

# Mapping a field to its allowed values lets one loop validate many fields.
# semantic_family is intentionally absent: new nonempty subtype names are valid.
ALLOWED_VALUES = {
    "category": VALID_CATEGORIES,
    "label": VALID_LABELS,
    "related_category": VALID_RELATED_CATEGORIES,
    "artifact_type": VALID_ARTIFACT_TYPES,
    "source_type": VALID_SOURCE_TYPES,
    "source_name": VALID_SOURCE_NAMES,
    "language": VALID_LANGUAGES,
    "review_status": VALID_REVIEW_STATUSES,
    "sha256": VALID_SHA256_VALUES,
    "created_at": VALID_CREATED_AT_VALUES,
}

# Every record must contain exactly these keys, including the two null fields.
REQUIRED_FIELDS = [
    "reference_id", "text", "label", "category", "related_category",
    "semantic_family", "artifact_type", "source_type", "source_name",
    "source_id", "language", "review_status", "sha256", "created_at",
]
# This list comprehension keeps fields whose raw values must be strings.
STRING_FIELDS = [f for f in REQUIRED_FIELDS if f not in ("sha256", "created_at")]
# Compile each ID pattern once and reuse it for all rows. [0-9]{6} means
# exactly six ASCII digits. fullmatch() later requires the whole ID to match.
ID_PATTERNS = {
    "reference_id": re.compile(r"BB-SEM-[0-9]{6}"),
    "source_id": re.compile(r"SYN-[0-9]{6}"),
}


def reject_constant(value):
    """Reject Python's otherwise accepted NaN/Infinity JSON extensions."""
    # json.loads calls this hook for NaN or Infinity, which are not valid JSON.
    raise ValueError(f"Nonstandard JSON constant: {value}")


def reject_duplicate_keys(pairs):
    """Avoid silently overwriting repeated keys during JSON parsing."""
    # The parser supplies key/value pairs before building a dictionary.
    # Checking here catches repeated keys that a normal dictionary would hide.
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Repeated JSON key: {key!r}")
        result[key] = value
    return result


def normalize_text(text):
    """Create a comparison key without changing the stored or hashed text."""
    # split() removes surrounding whitespace and splits on runs of whitespace.
    # join() replaces those runs with one space; casefold() ignores letter case.
    # This catches formatting duplicates, not paraphrases with similar meaning.
    return " ".join(text.split()).casefold()


def validate_corpus(path, expected_count=None, validated_records=None):
    """Return a report; optionally collect records only when the whole file passes.

    Retain the parsed records so preparation uses the exact data validated,
    even if the input file changes after this function returns.
    """
    # Accumulate all issues rather than stopping at the first bad record.
    issues = []
    # None means validation only. A supplied list requests records for --prepare.
    # An empty list is a valid request, so test "is not None", not truthiness.
    records = [] if validated_records is not None else None
    total_lines = 0
    object_count = 0
    category_counts = Counter()
    # Each inner dictionary maps an observed value to its first line number.
    # Dictionary lookup avoids searching a growing list for every new sample.
    seen = {"reference_id": {}, "source_id": {}, "text": {}}
    # A set supports fast membership checks and key-set subtraction below.
    required = set(REQUIRED_FIELDS)

    def issue(line, code, field, message, reference_id=None, first_line=None):
        # This nested helper shares the outer issues list and records a uniform
        # error structure. File-wide issues use line=None rather than a fake row.
        entry = {
            "line": line, "code": code, "field": field,
            "reference_id": reference_id, "message": message,
        }
        if first_line is not None:
            entry["first_line"] = first_line
        issues.append(entry)

    # with closes the file automatically, including if reading raises an error.
    # Reading one line at a time keeps JSONL parsing tied to physical line numbers.
    with Path(path).open(encoding="utf-8") as handle:
        # enumerate(..., 1) numbers the first line as 1 rather than 0.
        for line_number, raw_line in enumerate(handle, 1):
            total_lines = line_number
            if not raw_line.strip():
                issue(line_number, "blank_line", None, "Blank JSONL line.")
                # continue skips the remaining checks for this unusable line.
                continue
            try:
                # Each JSON object becomes a Python dict. These parser hooks
                # reject duplicate keys and nonstandard numeric constants.
                sample = json.loads(
                    raw_line, object_pairs_hook=reject_duplicate_keys,
                    parse_constant=reject_constant,
                )
            except (ValueError, RecursionError) as error:
                # Record malformed or excessively nested JSON, then keep reading.
                issue(line_number, "invalid_json", None, str(error))
                continue
            if not isinstance(sample, dict):
                # Valid JSON can also be a list, string, number, or null;
                # those values cannot represent a corpus record.
                issue(line_number, "invalid_record", None,
                      "Each line must contain one JSON object.")
                continue

            object_count += 1
            # Keep parsed objects internally, but release them to preparation
            # only if the ENTIRE corpus has no issues at the end of this function.
            if records is not None:
                records.append(sample)
            ref = sample.get("reference_id")
            # get() safely returns None if the key is absent. Only string IDs
            # are included in error context, so malformed values stay out of it.
            ref = ref if isinstance(ref, str) else None

            # 1. Check the exact set of fields.
            for field in REQUIRED_FIELDS:
                # Membership in a dict checks its keys, not its values.
                if field not in sample:
                    issue(line_number, "missing_field", field,
                          "Required field is missing.", ref)
            for field in sorted(set(sample) - required):
                # Subtract required keys from present keys to find extras.
                # Sorting gives a predictable order in the error report.
                issue(line_number, "unexpected_field", field,
                      "Field is not part of the canonical schema.", ref)

            # 2. Check string types and nonempty values before other checks.
            valid_strings = set()
            # Track fields whose string checks pass so later code can safely
            # apply string operations and use their values as dictionary keys.
            for field in STRING_FIELDS:
                if field not in sample:
                    continue
                value = sample[field]
                if not isinstance(value, str):
                    issue(line_number, "invalid_type", field,
                          "Expected a string.", ref)
                elif not value.strip():
                    # strip() is used for the check only; preserve the actual text.
                    issue(line_number, "empty_value", field,
                          "Expected a nonempty string.", ref)
                else:
                    valid_strings.add(field)

            # 3. Check closed vocabularies; semantic_family has no fixed enum.
            for field, allowed_values in ALLOWED_VALUES.items():
                # items() supplies both a field name and its allowed-value list.
                if field not in sample:
                    continue
                if field in STRING_FIELDS and field not in valid_strings:
                    # Missing/type/empty errors are already reported above.
                    continue
                if sample[field] not in allowed_values:
                    issue(line_number, "invalid_value", field,
                          f"Allowed values: {allowed_values!r}.", ref)

            # 4. Check ID syntax, excluding the all-zero ID.
            valid_ids = set()
            for field, pattern in ID_PATTERNS.items():
                if field not in valid_strings:
                    continue
                value = sample[field]
                if not pattern.fullmatch(value) or value.endswith("000000"):
                    issue(line_number, "invalid_id", field,
                          f"Expected {pattern.pattern}; numeric part must be positive.", ref)
                else:
                    valid_ids.add(field)
            if len(valid_ids) == 2:
                # Both IDs have valid syntax, so [-6:] safely extracts the number.
                # Matching numbers is a rule for this synthetic seed corpus;
                # external source IDs may follow different rules in a future version.
                if sample["reference_id"][-6:] != sample["source_id"][-6:]:
                    issue(line_number, "id_mismatch", "source_id",
                          "Synthetic source and reference ID numbers must match.", ref)

            # 5. Check relationships between fields.
            label = sample.get("label")
            category = sample.get("category")
            related = sample.get("related_category")
            if label in VALID_LABELS and category in VALID_CATEGORIES:
                # Check relationships only after individual values are valid,
                # avoiding misleading combination errors for unknown values.
                if label == "benign" and category != "benign":
                    issue(line_number, "label_category_mismatch", "category",
                          "A benign record must have category 'benign'.", ref)
                elif label == "malicious" and category not in MALICIOUS_CATEGORIES:
                    issue(line_number, "label_category_mismatch", "category",
                          "A malicious record must use a malicious category.", ref)
                if (label == "malicious" and category in MALICIOUS_CATEGORIES
                        and related in VALID_RELATED_CATEGORIES and related != category):
                    issue(line_number, "related_category_mismatch", "related_category",
                          "For malicious records, related_category must equal category.", ref)

            # 6. Track duplicate IDs and normalized text, even on invalid rows.
            for field in seen:
                if field not in valid_strings:
                    continue
                value = sample[field]
                key = normalize_text(value) if field == "text" else value
                # IDs are compared exactly. Only text uses the normalized key.
                if key in seen[field]:
                    first_line = seen[field][key]
                    issue(line_number, "duplicate", field,
                          f"Duplicates {field} from line {first_line}.",
                          ref, first_line=first_line)
                else:
                    # Keep the first occurrence; every later duplicate points to it.
                    seen[field][key] = line_number
            if category in VALID_CATEGORIES:
                category_counts[category] += 1

    # These are whole-file checks, performed after every line has been examined.
    if total_lines == 0:
        issue(None, "empty_file", None, "The corpus file is empty.")
    if expected_count is not None and object_count != expected_count:
        issue(None, "count_mismatch", None,
              f"Expected {expected_count} JSON objects; found {object_count}.")

    if not issues and validated_records is not None:
        # extend() adds every parsed object to the caller's list. With any issue,
        # this step is skipped so main() cannot prepare a partially valid corpus.
        validated_records.extend(records)

    # The report supports both readable console output and JSON for a pipeline.
    # Counter(...) counts repeated issue codes, then dict() makes plain mappings.
    return {
        "valid": not issues,
        "file": str(path),
        "total_lines": total_lines,
        "parsed_objects": object_count,
        "category_counts": dict(category_counts),
        "issue_count": len(issues),
        "issue_counts_by_code": dict(Counter(i["code"] for i in issues)),
        "issues": issues,
    }


def prepare_candidates(records, output_path):
    """Save an enriched copy of successfully validated records.

    Hash only the exact text's UTF-8 bytes, with no case/whitespace normalization.
    created_at is the preparation time in UTC, identical for this whole batch.
    Publish a complete file without overwriting an existing destination.
    """
    # main() calls this function only after full validation succeeds.
    # If reusing this function directly, pass records already validated yourself.
    output_path = Path(output_path)
    if not records:
        raise ValueError("There are no validated records to prepare.")
    # Example: 2026-10-11T10:43:44Z. Z denotes UTC; one timestamp represents
    # this preparation batch, not the original source publication date.
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    prepared = []
    for sample in records:
        enriched = sample.copy()
        # Copy before adding fields so the validated in-memory record is unchanged.
        # encode() turns the exact Unicode text into bytes; hexdigest() returns
        # the digest as a 64-character hexadecimal string. Metadata is not hashed.
        enriched["sha256"] = hashlib.sha256(sample["text"].encode("utf-8")).hexdigest()
        enriched["created_at"] = created_at
        prepared.append(enriched)

    # Create missing parent folders; an existing directory is acceptable.
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        # Write a complete temporary file in the destination directory first.
        # delete=False keeps it available after closing, ready for publication.
        # newline="\n" ensures consistent JSONL line endings across platforms.
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", delete=False,
            dir=output_path.parent, prefix=".prepare-", suffix=".jsonl",
        ) as handle:
            temporary_path = Path(handle.name)
            for sample in prepared:
                # Preserve Unicode, use compact JSON, and end each object with
                # a newline. Embedded newlines in text are escaped by json.dumps.
                handle.write(json.dumps(sample, ensure_ascii=False, separators=(",", ":")) + "\n")
            handle.flush()
            # flush moves Python's buffer to the OS; fsync requests a disk sync.
            os.fsync(handle.fileno())
        # A hard link exposes the already-complete file under its final name.
        # Linking is atomic and raises FileExistsError if a destination exists.
        # The destination filesystem must support hard links; otherwise main()
        # reports an error. Keeping both paths in one directory avoids cross-device links.
        os.link(temporary_path, output_path)
    finally:
        # finally runs on success or failure. Remove only the temporary name;
        # after linking, the final name still refers to the complete file data.
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return created_at


def positive_int(value):
    """Convert an argument to a strictly positive expected record count."""
    # argparse supplies text. Invalid conversions and nonpositive counts become
    # command-line errors before the corpus is read.
    result = int(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("Expected a positive integer.")
    return result


def main():
    # Define the positional file argument and optional flags. store_true flags
    # default to False and become True when present on the command line.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="Path to the JSONL corpus")
    parser.add_argument("--expected-count", type=positive_int, default=None,
                        help="Optional expected number of JSON objects")
    parser.add_argument("--json", action="store_true", help="Print the report as JSON")
    parser.add_argument("--prepare", action="store_true",
                        help="After a full PASS, add hashes/dates and save a candidate copy")
    parser.add_argument("--output-dir", type=Path, default=None,
                        help="Destination folder for --prepare (default: input folder/final_candidates)")
    args = parser.parse_args()
    # A destination has no effect without preparation, so reject that combination.
    if args.output_dir is not None and not args.prepare:
        parser.error("--output-dir requires --prepare")
    # Collect records only for preparation; validation-only runs do not retain them.
    
    records = []
    try:
        report = validate_corpus(args.file, args.expected_count, validated_records=records if args.prepare else None)
    except (OSError, UnicodeError) as error:
        # File access and encoding failures are operational errors, not row issues.
        print(f"Cannot read corpus: {error}", file=sys.stderr)
        return 2
    preparation_error = None
    if args.prepare:
        # None means no prepared file exists for this run; JSON reports include
        # that value when validation fails or preparation cannot save the output.
        report["prepared_file"] = None
        
        if report["valid"]:
            output_dir = args.output_dir if args.output_dir is not None else args.file.parent / "final_candidates"
            # Path's / operator joins directory and filename without manual slashes.
            output_path = output_dir / args.file.name
            try:
                created_at = prepare_candidates(records, output_path)
                report["prepared_file"] = str(output_path)
                report["prepared_records"] = len(records)
                report["created_at"] = created_at
            except (OSError, ValueError) as error:
                # Preserve the validation report while separately recording a
                # save failure, including an existing output or filesystem error.
                preparation_error = str(error)
                report["preparation_error"] = preparation_error
    if args.json:
        # Emit one JSON document so another script can parse the whole report.
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        # Human-readable mode displays the result and every issue's location.
        print("PASS" if report["valid"] else "FAIL")
        print(f"Parsed objects: {report['parsed_objects']} | Issues: {report['issue_count']}")
        for item in report["issues"]:
            location = f"line {item['line']}" if item["line"] is not None else "file"
            field = f" [{item['field']}]" if item["field"] else ""
            print(f"{location}{field}: {item['code']} — {item['message']}")
        if args.prepare:
            if report.get("prepared_file"):
                print(f"Prepared {report['prepared_records']} candidates: {report['prepared_file']}")
            elif preparation_error is not None:
                print(f"Preparation failed: {preparation_error}", file=sys.stderr)
            else:
                print("Preparation skipped: fix every validation issue first.")
    if preparation_error is not None:
        # A valid input with a failed save still needs a nonzero process exit code.
        return 2
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    # Run the CLI only when executed directly. Importing this file lets another
    # Python script reuse the functions without automatically starting main().
    # sys.exit passes main()'s result to the shell or pipeline running the script.
    sys.exit(main())
