import asyncio
from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient

import main


@pytest.fixture
def client(settings, scorer):
    original_router_lifespan = main.app.router.lifespan_context

    @asynccontextmanager
    async def fake_lifespan(app):
        app.state.ready = True
        app.state.config = settings
        app.state.scorer = scorer
        app.state.inference_lock = asyncio.Lock()
        yield
        app.state.ready = False

    main.app.router.lifespan_context = fake_lifespan
    try:
        with TestClient(main.app) as test_client:
            yield test_client
    finally:
        main.app.router.lifespan_context = original_router_lifespan


REQUEST = {
    "request_id": "test-abc",
    "tenant_id": "tenant-test",
    "application_id": "app-test",
    "artifact_type": "user_input",
    "text": "Run a scan",
}


def test_liveness(client):
    assert client.get("/health/live").json() == {"status": "alive"}


def test_readiness(client):
    assert client.get("/health/ready").json() == {"status": "ready"}


def test_analyze_returns_structured_evidence(client, fake_model):
    response = client.post("/v1/analyze", json=REQUEST)
    assert response.status_code == 200
    payload = response.json()
    assert payload["request_id"] == "test-abc"
    assert payload["artifact_type"] == "user_input"
    assert payload["model"] == "BAAI/bge-base-en-v1.5"
    assert payload["result"]["detected"] is True
    assert fake_model.calls == 1


def test_rejects_unsupported_artifact(client, fake_model):
    response = client.post("/v1/analyze", json={**REQUEST, "artifact_type": "tool_response"})
    assert response.status_code == 422
    assert fake_model.calls == 0


def test_rejects_unknown_request_field(client):
    assert client.post("/v1/analyze", json={**REQUEST, "unknown": 5}).status_code == 422


def test_rejects_empty_and_long_inputs(client, fake_model):
    assert client.post("/v1/analyze", json={**REQUEST, "text": ""}).status_code == 422
    assert client.post("/v1/analyze", json={**REQUEST, "text": "x" * 16385}).status_code == 422
    assert fake_model.calls == 0


def test_returns_service_unavailable_when_not_ready(client):
    main.app.state.ready = False
    assert client.get("/health/ready").status_code == 503
    assert client.post("/v1/analyze", json=REQUEST).status_code == 503
    assert client.get("/health/live").status_code == 200


def test_internal_scorer_error_is_not_leaked(client, monkeypatch):
    def fail(_):
        raise RuntimeError("private-internal-error")
    monkeypatch.setattr(main.app.state.scorer, "analyze", fail)
    response = client.post("/v1/analyze", json=REQUEST)
    assert response.status_code == 500
    assert "private-internal-error" not in response.text
