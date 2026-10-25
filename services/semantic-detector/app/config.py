#This package will be used to load the semantic-detector
#Configuration from teh config.yaml file to our program in form of a python dict

import yaml
import jsonschema 
import logging

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)

schema = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "service",
        "model",
        "references",
        "scoring",
        "input",
        "response",
        "logging",
    ],
    "properties": {
        "service": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "name",
                "version",
                "host",
                "port",
            ],
            "properties": {
                "name": {
                    "type": "string",
                    "minLength": 1,
                    "pattern": "^[a-zA-Z0-9_-]+$",
                },
                "version": {
                    "type": "string",
                    "pattern": "^\\d+\\.\\d+\\.\\d+$",
                },
                "host": {
                    "type": "string",
                    "minLength": 1,
                },
                "port": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 65535,
                },
            },
        },
        "model": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "provider",
                "name",
                "device",
                "batch_size",
                "normalize_embeddings",
                "reference_prefix",
                "query_prefix",
            ],
            "properties": {
                "provider": {
                    "type": "string",
                    "enum": [
                        "sentence-transformers",
                    ],
                },
                "name": {
                    "type": "string",
                    "minLength": 1,
                },
                "device": {
                    "type": "string",
                    "enum": [
                        "cpu",
                        "cuda",
                        "mps",
                    ],
                },
                "batch_size": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1024,
                },
                "normalize_embeddings": {
                    "type": "boolean",
                },
                "reference_prefix": {
                    "type": "string",
                },
                "query_prefix": {
                    "type": "string",
                },
            },
        },
        "references": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "source_path",
                "embeddings_path",
                "manifest_path",
                "preload_on_startup",
                "use_cached_embeddings",
                "verify_integrity",
                "expected_sha256",
            ],
            "properties": {
                "source_path": {
                    "type": "string",
                    "minLength": 1,
                },
                "embeddings_path": {
                    "type": "string",
                    "minLength": 1,
                },
                "manifest_path": {
                    "type": "string",
                    "minLength": 1,
                },
                "preload_on_startup": {
                    "type": "boolean",
                },
                "use_cached_embeddings": {
                    "type": "boolean",
                },
                "verify_integrity": {
                    "type": "boolean",
                },
                "expected_sha256": {
                    "type": "string",
                    "pattern": "^[a-fA-F0-9]{64}$",
                },
            },
        },
        "scoring": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "strategy",
                "top_k",
                "supported_categories",
                "benign_comparison",
                "thresholds",
            ],
            "properties": {
                "strategy": {
                    "type": "string",
                    "enum": [
                        "global_max",
                        "category_local_max",
                        "category_topk_mean",
                        "category_topk_margin",
                        "neighbor_vote",
                    ],
                },
                "top_k": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 50,
                },
                "supported_categories": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": True,
                    "items": {
                        "type": "string",
                        "enum": [
                            "prompt_injection",
                            "jailbreak",
                            "role_manipulation",
                            "system_prompt_extraction",
                        ],
                    },
                },
                "benign_comparison": {
                    "type": "string",
                    "enum": [
                        "global_topk_mean",
                    ],
                },
                "thresholds": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "similarity",
                        "margin",
                        "support",
                    ],
                    "properties": {
                        "similarity": {
                            "type": "number",
                            "minimum": -1.0,
                            "maximum": 1.0,
                        },
                        "margin": {
                            "type": "number",
                            "minimum": -2.0,
                            "maximum": 2.0,
                        },
                        "support": {
                            "type": ["number", "null"],
                            "minimum": -1.0,
                            "maximum": 1.0,
                        },
                    },
                },
            },
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "strategy": {
                                "const": "neighbor_vote",
                            }
                        }
                    },
                    "then": {
                        "properties": {
                            "thresholds": {
                                "properties": {
                                    "support": {
                                        "type": "number",
                                        "minimum": -1.0,
                                        "maximum": 1.0,
                                    }
                                }
                            }
                        }
                    },
                },
                {
                    "if": {
                        "properties": {
                            "strategy": {
                                "enum": [
                                    "global_max",
                                    "category_local_max",
                                    "category_topk_mean",
                                    "category_topk_margin",
                                ]
                            }
                        }
                    },
                    "then": {
                        "properties": {
                            "thresholds": {
                                "properties": {
                                    "support": {
                                        "type": "null"
                                    }
                                }
                            }
                        }
                    },
                },
            ],
        },
        "input": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "supported_artifacts",
                "max_character_bytes",
                "reject_empty_text",
            ],
            "properties": {
                "supported_artifacts": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": True,
                    "items": {
                        "type": "string",
                        "enum": [
                            "user_input",
                            "model_output",
                        ],
                    },
                },
                "max_character_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1000000,
                },
                "reject_empty_text": {
                    "type": "boolean",
                },
            },
        },
        "response": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "include_category_scores",
                "include_reference_ids",
                "max_evidence_references",
                "include_reference_text",
            ],
            "properties": {
                "include_category_scores": {
                    "type": "boolean",
                },
                "include_reference_ids": {
                    "type": "boolean",
                },
                "max_evidence_references": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 20,
                },
                "include_reference_text": {
                    "type": "boolean",
                },
            },
        },
        "logging": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "level",
                "structured",
                "log_artifact_text",
                "log_request_id",
                "log_processing_time",
            ],
            "properties": {
                "level": {
                    "type": "string",
                    "enum": [
                        "DEBUG",
                        "INFO",
                        "WARNING",
                        "ERROR",
                        "CRITICAL",
                    ],
                },
                "structured": {
                    "type": "boolean",
                },
                "log_artifact_text": {
                    "type": "boolean",
                },
                "log_request_id": {
                    "type": "boolean",
                },
                "log_processing_time": {
                    "type": "boolean",
                },
            },
        },
    },
}
def load_config(file_path: str) -> dict:

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            config = yaml.safe_load(file)

    except FileNotFoundError:
        logger.error("Configuration file not found: %s", file_path)
        raise

    except yaml.YAMLError as error:
        logger.error("Invalid YAML syntax: %s", error)
        raise

    try:
        jsonschema.validate(instance=config, schema=schema)

    except jsonschema.ValidationError as error:
        field = ".".join(str(part) for part in error.absolute_path)

        logger.error(
            "Configuration validation failed at '%s': %s",
            field or "root",
            error.message
        )

        raise ValueError(
            f"Invalid configuration at '{field or 'root'}': {error.message}"
        ) from error

    logger.info("Configuration loaded and validated successfully")

    return config

#print(load_config("services/semantic-detector/config/config.yaml"))