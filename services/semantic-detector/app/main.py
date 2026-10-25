"""HTTP API for BearBreach Semantic Detector.

Run from the BearBreach repository root:
    python -m uvicorn main:app --app-dir services/semantic-detector/app --host 0.0.0.0 --port 8001
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from config import load_config
from model_loader import load_model
from reference_store import ReferenceStore
from scorer import SemanticScorer

logger = logging.getLogger(__name__)

CONFIG_PATH = os.getenv(
    "SEMANTIC_DETECTOR_CONFIG",
    "services/semantic-detector/config/config.yaml",
)


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str
    artifact_type: str
    request_id: str | None = Field(default=None, min_length=1, max_length=128)
    tenant_id: str | None = Field(default=None, min_length=1, max_length=128)
    application_id: str | None = Field(default=None, min_length=1, max_length=128)


def initialize_detector(config_path: str):
    # Loading happens only at startup, not every time an artifact is analyzed.
    config = load_config(config_path)

    log_level = getattr(logging, config["logging"]["level"])
    logging.getLogger().setLevel(log_level)

    corpus_path = Path(config["references"]["source_path"])
    if not corpus_path.is_file():
        raise FileNotFoundError(f"Reference corpus not found: {corpus_path}")

    logger.info("Loading model and reference corpus")
    model, reference_records, reference_embeddings = load_model(
        config_path, str(corpus_path)
    )

    reference_store = ReferenceStore(
        reference_records, reference_embeddings, config["scoring"]
    )

    scorer = SemanticScorer(
        model=model,
        reference_store=reference_store,
        model_config=config["model"],
        scoring_config=config["scoring"],
        input_config=config["input"],
        response_config=config["response"],
    )

    return config, scorer, reference_store


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.ready = False
    app.state.scorer = None
    app.state.config = None

    started_at = perf_counter()
    try:
        config, scorer, store = await asyncio.to_thread(
            initialize_detector, CONFIG_PATH
        )
    except Exception:
        logger.exception("Semantic Detector could not initialize")
        raise

    app.state.config = config
    app.state.scorer = scorer
    app.state.inference_lock = asyncio.Lock()
    app.state.ready = True

    logger.info(
        "Semantic Detector ready: model=%s references=%d dimensions=%d startup_ms=%.1f",
        config["model"]["name"],
        len(store.reference_records),
        store.reference_embeddings.shape[1],
        (perf_counter() - started_at) * 1000,
    )

    try:
        yield
    finally:
        app.state.ready = False
        app.state.scorer = None
        logger.info("Semantic Detector shutting down")


app = FastAPI(
    title="BearBreach Semantic Detector",
    version="0.1.0",
    description="Semantic detection evidence service. Trust Guard handles policy and enforcement.",
    lifespan=lifespan,
)


@app.get("/health/live")
async def health_live():
    # Liveness does not depend on the embedding model being ready.
    return {"status": "alive"}


@app.get("/health/ready")
async def health_ready(request: Request):
    if not getattr(request.app.state, "ready", False):
        raise HTTPException(status_code=503, detail="Detector is not ready")
    return {"status": "ready"}


@app.post("/v1/analyze")
async def analyze(artifact: AnalyzeRequest, request: Request):
    if not getattr(request.app.state, "ready", False):
        raise HTTPException(status_code=503, detail="Detector is not ready")

    config = request.app.state.config
    request_id = artifact.request_id or str(uuid4())
    if artifact.artifact_type not in config["input"]["supported_artifacts"]:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported artifact_type: {artifact.artifact_type}",
        )

    started_at = perf_counter()
    try:
        # One inference at a time protects this shared model instance in v0.1.
        # A worker thread keeps the HTTP event loop responsive while encoding.
        async with request.app.state.inference_lock:
            result = await asyncio.to_thread(
                request.app.state.scorer.analyze, artifact.text
            )
    except (ValueError, TypeError) as error:
        logger.warning("Analysis rejected request_id=%s reason=%s", request_id, error)
        raise HTTPException(status_code=422, detail=str(error)) from error
    except Exception as error:
        logger.exception("Analysis failed request_id=%s", request_id)
        raise HTTPException(status_code=500, detail="Semantic analysis failed") from error

    elapsed_ms = round((perf_counter() - started_at) * 1000, 3)
    if config["logging"]["log_processing_time"]:
        logger.info(
            "Analysis completed request_id=%s artifact_type=%s detected=%s "
            "category=%s duration_ms=%.3f",
            request_id,
            artifact.artifact_type,
            result["detected"],
            result["predicted_category"],
            elapsed_ms,
        )
    else:
        logger.info("Analysis completed request_id=%s detected=%s", request_id, result["detected"])

    # A negative detection is not a verdict that the input is safe.
    return {
        "request_id": request_id,
        "tenant_id": artifact.tenant_id,
        "application_id": artifact.application_id,
        "artifact_type": artifact.artifact_type,
        "detector_version": config["service"]["version"],
        "model": config["model"]["name"],
        "result": result,
    }
