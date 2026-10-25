<p align="center">
  <img src="assets/full_logo.png" alt="BearBreach Logo" width="220"/>
</p>

<h1 align="center">BearBreach</h1>

<p align="center">
  <strong>Open-Source AI Zero Trust Security Platform</strong>
</p>

<p align="center">
  Observe • Analyze • Detect • Enforce • Establish Trust
</p>

<p align="center">
  <a href="https://github.com/gursimransw/BearBreach"><img src="https://img.shields.io/badge/GitHub-BearBreach-181717?logo=github&logoColor=white" alt="GitHub" /></a>
  <img src="https://img.shields.io/badge/Go-Trust%20Guard-00ADD8?logo=go&logoColor=white" alt="Go" />
  <img src="https://img.shields.io/badge/Python-Semantic%20Detector-3776AB?logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Docker-Supported-2496ED?logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/Status-Experimental%20v0.1-orange" alt="Experimental v0.1" />
</p>

---

## Overview

**BearBreach is an open-source AI Zero Trust project for observing, analyzing, detecting, and enforcing security across AI trust boundaries.**

AI applications combine user input, application instructions, foundation models, retrieved content, tools, and downstream actions. Data crossing from one component to another may be untrusted, even when it appears to be part of a legitimate workflow.

BearBreach is being built to make these boundaries observable and enforceable through detection engines, configurable policies, and structured security events.

**Current implementation:** Trust Guard (Go) integrates signature-based detection, resource-abuse checks, and a Python Semantic Detector that identifies suspicious content using embedding similarity. The services communicate over HTTP and produce **AI Trust Boundary Events** with findings, component scores, and policy decisions.

> **Project status:** Active development. The current detection system is an experimental v0.1 implementation, not a production-validated AI security platform. Capabilities described as planned below are not yet implemented.

---

## What Is AI Zero Trust?

Traditional Zero Trust is commonly summarized as **“Never Trust, Always Verify.”**

BearBreach applies this principle to interactions in AI applications: content or actions should not become trusted simply because they came from a user, a retrieved document, an LLM, or a connected tool.

The long-term design emphasizes:

- Explicit verification at AI trust boundaries
- Context-aware threat detection
- Policy-driven security decisions
- Continuous telemetry and auditability
- Defense in depth across models, applications, retrieval, and tools

Today, BearBreach implements analysis for **user input** and **model output**. Verification of retrieval content, tool invocations, and agent actions is part of the broader roadmap.

---

## AI Trust Boundaries

| Boundary | Data crossing the boundary | Status |
| --- | --- | --- |
| **User → Application** | Untrusted user-controlled input enters the AI application | **Implemented:** input analysis endpoint |
| **Application → LLM** | Application instructions, user input, and context are assembled for model invocation | Planned |
| **LLM → Tools** | Model-generated instructions trigger API, database, or file operations | Planned |
| **External data → Application/LLM** | Retrieved documents and other third-party content enter the AI workflow | Planned |
| **Model → Application/User** | Generated model output returns to the application or end user | **Implemented:** output analysis endpoint |

The current endpoints analyze submitted artifacts; applications must integrate the returned decisions into their own workflows to actually enforce them.

---

## Implemented Components

### Trust Guard — Go

Trust Guard is the current policy and analysis entry point.

- **Signature detection:** configurable rules with artifact applicability, categories, weights, and findings.
- **Resource-abuse detection:** configurable byte limits, estimated-token limits, and repeated-character checks; supports scored detections and hard constraints.
- **Semantic integration:** calls the Python service, validates responses, and converts positive detections into security findings.
- **Policy-driven scoring:** aggregates component contributions into a normalized risk score from `0` to `1`, maps it to a severity and action, and preserves hard-constraint blocking.
- **Event generation:** emits structured AI Trust Boundary Events with request correlation, artifact metadata, findings, scores, and decisions.

#### Semantic detection modes

| Mode | Semantic finding | Score contribution |
| --- | --- | --- |
| `observation` | Recorded when detected | `0.00` |
| `enforcement` | Recorded when detected | Fixed configurable weight; currently `0.30` |

A failed Semantic Detector request is treated as an **analysis error**, not as a negative detection. In the current implementation, the API handler returns an error when the required semantic analysis cannot complete; graceful degraded-mode handling is future work.

### Semantic Detector — Python

The Semantic Detector is a separate FastAPI service that performs embedding-similarity analysis.

- **Model:** `BAAI/bge-base-en-v1.5` via Sentence Transformers.
- **Detection approach:** compare normalized artifact embeddings against curated malicious and benign references.
- **Scoring:** category-level top-k similarity and a benign-comparison margin, using a frozen v0.1 experimental configuration.
- **Supported categories:** `prompt_injection`, `jailbreak`, `role_manipulation`, and `system_prompt_extraction`.
- **Response:** detection status, predicted category, similarity scores, margin, matched reference IDs, and timing information.

The Python service supplies **detection evidence**. Trust Guard owns the final risk contribution, severity, and policy action.

---

## Architecture

```text
                          AI Application / Client
                                    |
                     +--------------+--------------+
                     |                             |
              POST /analyze-input           POST /analyze-output
                     |                             |
                     +--------------+--------------+
                                    |
                             Trust Guard (Go)
                                    |
             +----------------------+----------------------+
             |                      |                      |
      Signature Detector    Resource-Abuse Detector   Semantic Client
                                                           |
                                                      HTTP /v1/analyze
                                                           |
                                                 Semantic Detector (Python)
                                                    BGE + Reference Corpus
                                                           |
                                                    Semantic Finding
             |                      |                      |
             +----------------------+----------------------+
                                    |
                         Score / Policy Evaluation
                                    |
                         AI Trust Boundary Event
                                    |
                          Application Response
```

The current Docker setup runs Trust Guard and Semantic Detector as separate containers on a shared network.

---

## Policy-Driven Decisions

Trust Guard combines active component scores and normalizes the final score to the range `0–1`.

| Severity | Configured score range | Default action |
| --- | --- | --- |
| LOW | 0.00–0.24 | ALLOW |
| MEDIUM | 0.25–0.49 | LOG |
| HIGH | 0.50–0.74 | ALERT |
| CRITICAL | 0.75–1.00 | BLOCK |

Configured hard resource-abuse violations override score-based decisions and produce `CRITICAL → BLOCK`.

The scoring implementation also handles small gaps between the two-decimal threshold ranges. Detection weights are **policy contributions**, not calibrated probabilities of an attack.

Example semantic configuration in Trust Guard's `policy.json`:

```json
{
  "semantic_detection": {
    "enabled": true,
    "mode": "observation",
    "weight": 0.3
  }
}
```

In `enforcement` mode, a semantic-only finding with weight `0.30` maps to `MEDIUM → LOG` under the default policy. It does **not** independently cause blocking.

---

## API Endpoints

### Trust Guard

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/analyze-input` | Analyze user input |
| `POST` | `/api/v1/analyze-output` | Analyze model output |

Example request:

```json
{
  "content": "Explain how dinosaurs lived."
}
```

The response is an AI Trust Boundary Event including `findings`, `decision.component_scores`, `decision.final_risk_score`, `decision.severity`, and `decision.action`.

### Semantic Detector (internal service)

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | `/v1/analyze` | Analyze an artifact using the embedding model |
| `GET` | `/health/live` | Service liveness |
| `GET` | `/health/ready` | Model/service readiness |

The Semantic Detector API is intended for internal service-to-service communication. Do not expose it publicly without authentication and additional controls.

---

## Running with Docker

Build commands are run from the **BearBreach repository root**.

```powershell
docker build -t bearbreach-semantic:0.1.0 -f services/semantic-detector/Dockerfile .
docker build -t bearbreach-trust-guard:0.1.0 -f services/trust-guard/Dockerfile services/trust-guard
```

Create a network and start the services:

```powershell
docker network create bearbreach-network

docker run -d `
  --name bb-semantic-detector `
  --network bearbreach-network `
  -p 8001:8001 `
  bearbreach-semantic:0.1.0

docker run -d `
  --name bb-trust-guard `
  --network bearbreach-network `
  -p 8080:8000 `
  bearbreach-trust-guard:0.1.0
```

**Networking:** When Trust Guard runs in Docker, its Semantic Detector base URL must resolve to `http://bb-semantic-detector:8001` (not `127.0.0.1:8001`). The current Go configuration may require updating this URL before building; moving it to runtime configuration is planned.

Verify the services:

```powershell
curl.exe http://localhost:8001/health/ready
```

Test Trust Guard from PowerShell:

```powershell
$body = @{ content = "Explain how dinosaurs lived." } | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:8080/api/v1/analyze-input" -Method Post -ContentType "application/json" -Body $body
```

Model weights may need to be downloaded when the Semantic Detector starts. The reference corpus is required by its configured loader.

---

## Testing and Evaluation

The project includes Go unit and integration tests, Python service tests, and a separate semantic evaluation workflow.

Run the Trust Guard tests from `services/trust-guard`:

```powershell
go test ./...
```

The Go integration tests use a mocked Python HTTP service to verify request propagation, valid findings, observation/enforcement behavior, and failure handling.

The semantic corpus and evaluation utilities are under `libraries/semantic-corpus/`, including a curated reference set, validation/test examples, model comparisons, threshold experiments, and error analysis.

**Frozen v0.1 held-out evaluation (40 samples):**

- In-scope detection: **18 true positives, 10 true negatives, 2 false positives, 5 false negatives** across 35 samples.
- Malicious precision: **90.0%**; recall: **78.3%**; F1: **83.7%**.
- The remaining five samples were out-of-scope examples used to probe unsupported behavior.

These are small, curated experimental results—not generalizable production performance claims. The current detector has known false positives, false negatives, and category-classification weaknesses.

End-to-end Docker testing has also demonstrated that a semantic finding can identify an indirect system-instruction extraction attempt without a matching signature rule.

---

## Repository Layout

```text
BearBreach/
├── assets/
├── libraries/
│   └── semantic-corpus/
│       ├── candidates/
│       ├── curated/
│       ├── dataset_operations/
│       ├── evaluation/
│       └── raw/
└── services/
    ├── trust-guard/
    │   ├── cmd/server/
    │   ├── config/
    │   └── internal/
    │       ├── clients/
    │       ├── detector/
    │       ├── handlers/
    │       ├── policy/
    │       └── types/
    └── semantic-detector/
        ├── app/
        ├── config/
        ├── scripts/
        ├── tests/
        └── Dockerfile
```

---

## Roadmap

BearBreach aims to expand beyond its current input/output detection capabilities. Planned areas include:

- Richer semantic evidence and safer investigation workflows
- Improved calibration, model evaluation, and detection quality
- Resilient service-to-service communication and degraded-mode handling
- Policy management, tenant/application isolation, and authenticated integration
- RAG and retrieved-content inspection
- Agent and tool-action authorization
- AI telemetry, dashboarding, and SIEM/SOAR integrations
- AI CI/CD security checks
- Hosted, self-hosted, and customer-cloud deployment options

These are **future directions**, not completed features of v0.1.

---

## Project Philosophy

**Never trust an AI interaction solely because it appears to come from an expected component.**

BearBreach is being built to make trust boundaries explicit, security signals understandable, and enforcement decisions configurable—without requiring every application developer to become an AI security specialist.

**Observe • Analyze • Detect • Enforce • Establish Trust**
