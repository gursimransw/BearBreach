package modelOutput

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gursimransw/BearBreach/services/trust-guard/internal/types"
)

func TestOutputAnalyzerMaliciousContent(t *testing.T) {
	testRules := []types.DetectionRule{
		{
			ID:          "SD-002",
			Name:        "Generic API Key Assignment",
			Category:    "sensitive_data",
			FindingType: "api_key",
			AppliesTo:   []string{"model_output"},
			Pattern:     `(?i)(api[_-]?key)\s*(?::=|[:=])\s*["']?[^\s"']{8,}["']?`,
			Weight:      0.78,
			Severity:    "critical",
			Reason:      "Detected generic API key or secret key assignment",
		},
	}

	testPolicyConfig := types.PolicyConfig{
		SeverityConfig: []types.SeverityConfig{
			{
				Severity: "LOW",
				MinScore: 0.00,
				MaxScore: 0.49,
			},
			{
				Severity: "CRITICAL",
				MinScore: 0.50,
				MaxScore: 1.00,
			},
		},
		DefaultActionsConfig: map[string]string{
			"LOW":      "ALLOW",
			"CRITICAL": "BLOCK",
		},
		ResourceAbusePolicy: types.ResourceAbusePolicy{
			Enabled: true,
			ArtifactPolicies: map[types.ArtifactType]types.ArtifactResourcePolicy{
				types.ArtifactModelOutput: {
					MaxBytes: types.MaxBytesPolicy{
						Limit:       10000,
						Enforcement: types.EnforcementScored,
						Weight:      0.20,
					},
					MaxEstimatedTokens: types.MaxEstimatedTokensPolicy{
						Limit:       2500,
						Enforcement: types.EnforcementScored,
						Weight:      0.20,
					},
					RepeatedCharacters: types.RepeatedCharactersPolicy{
						MaxConsecutiveRun:   1000,
						MaxConsecutiveRatio: 1.00,
						MinimumCharacters:   1000,
						Enforcement:         types.EnforcementScored,
						Weight:              0.20,
					},
				},
			},
		},
	}

	requestBody := `{
		"content": "Here is the requested configuration: api_key = 'sk-test-1234567890abcdef'"
	}`

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/analyze-output",
		strings.NewReader(requestBody),
	)

	request.Header.Set(
		"Content-Type",
		"application/json",
	)

	responseRecorder := httptest.NewRecorder()

	handler := HandleModelOutput(
		&testRules,
		&testPolicyConfig,
	)

	handler.ServeHTTP(
		responseRecorder,
		request,
	)

	if responseRecorder.Code != http.StatusOK {
		t.Fatalf(
			"expected status code %d, got %d",
			http.StatusOK,
			responseRecorder.Code,
		)
	}

	var event types.AITrustBoundaryEvent

	if err := json.NewDecoder(responseRecorder.Body).Decode(&event); err != nil {
		t.Fatalf(
			"failed to decode response body: %v",
			err,
		)
	}

	if event.SchemaVersion != "1.0.0" {
		t.Fatalf(
			"expected schema version 1.0.0, got %s",
			event.SchemaVersion,
		)
	}

	if event.EventType != "ai_trust_boundary_event" {
		t.Fatalf(
			"expected event type ai_trust_boundary_event, got %s",
			event.EventType,
		)
	}

	if event.EventID == "" {
		t.Fatalf(
			"expected event ID to not be empty",
		)
	}

	if event.RequestID == "" {
		t.Fatalf(
			"expected request ID to not be empty",
		)
	}

	if event.Producer.Service != "trust_guard" {
		t.Fatalf(
			"expected producer service trust_guard, got %s",
			event.Producer.Service,
		)
	}

	if event.Producer.ServiceVersion != "1.0.0" {
		t.Fatalf(
			"expected producer version 1.0.0, got %s",
			event.Producer.ServiceVersion,
		)
	}

	if event.Context.TenantID != "tenant-001" {
		t.Fatalf(
			"expected tenant ID tenant-001, got %s",
			event.Context.TenantID,
		)
	}

	if event.Context.ApplicationID != "application-001" {
		t.Fatalf(
			"expected application ID application-001, got %s",
			event.Context.ApplicationID,
		)
	}

	if event.Boundary.Name != "model_to_application" {
		t.Fatalf(
			"expected boundary model_to_application, got %s",
			event.Boundary.Name,
		)
	}

	if event.Boundary.SourceComponent != "model" {
		t.Fatalf(
			"expected source component model, got %s",
			event.Boundary.SourceComponent,
		)
	}

	if event.Boundary.DestinationComponent != "application" {
		t.Fatalf(
			"expected destination component application, got %s",
			event.Boundary.DestinationComponent,
		)
	}

	if event.Boundary.Stage != "post_model" {
		t.Fatalf(
			"expected boundary stage post_model, got %s",
			event.Boundary.Stage,
		)
	}

	if event.Artifact.ArtifactType != types.ArtifactModelOutput {
		t.Fatalf(
			"expected artifact type model_output, got %s",
			event.Artifact.ArtifactType,
		)
	}

	if event.Artifact.Origin != "model" {
		t.Fatalf(
			"expected artifact origin model, got %s",
			event.Artifact.Origin,
		)
	}

	if event.Artifact.MessageRole != "assistant" {
		t.Fatalf(
			"expected message role assistant, got %s",
			event.Artifact.MessageRole,
		)
	}

	if event.Artifact.ContentType != "text/plain" {
		t.Fatalf(
			"expected content type text/plain, got %s",
			event.Artifact.ContentType,
		)
	}

	if event.Artifact.ContentEncoding != "utf-8" {
		t.Fatalf(
			"expected content encoding utf-8, got %s",
			event.Artifact.ContentEncoding,
		)
	}

	if !event.Decision.HasFindings {
		t.Fatalf(
			"expected malicious model output to create findings",
		)
	}

	if len(event.Findings) != 1 {
		t.Fatalf(
			"expected 1 finding, got %d",
			len(event.Findings),
		)
	}

	if event.Decision.ComponentScores["signature_detection"] != 0.78 {
		t.Fatalf(
			"expected signature detection score 0.78, got %f",
			event.Decision.ComponentScores["signature_detection"],
		)
	}

	if event.Decision.ComponentScores["resource_abuse"] != 0 {
		t.Fatalf(
			"expected resource abuse score 0, got %f",
			event.Decision.ComponentScores["resource_abuse"],
		)
	}

	if event.Decision.FinalRiskScore != 0.78 {
		t.Fatalf(
			"expected final risk score 0.78, got %f",
			event.Decision.FinalRiskScore,
		)
	}

	if event.Decision.Severity != "CRITICAL" {
		t.Fatalf(
			"expected severity CRITICAL, got %s",
			event.Decision.Severity,
		)
	}

	if event.Decision.Action != "BLOCK" {
		t.Fatalf(
			"expected action BLOCK, got %s",
			event.Decision.Action,
		)
	}

	if len(event.Decision.Basis) != 1 {
		t.Fatalf(
			"expected one decision basis, got %#v",
			event.Decision.Basis,
		)
	}

	if event.Decision.Basis[0] != "risk_score" {
		t.Fatalf(
			"expected decision basis risk_score, got %s",
			event.Decision.Basis[0],
		)
	}

	finding := event.Findings[0]

	if finding.FindingID != "finding-1" {
		t.Fatalf(
			"expected finding ID finding-1, got %s",
			finding.FindingID,
		)
	}

	if finding.RuleID != "SD-002" {
		t.Fatalf(
			"expected rule ID SD-002, got %s",
			finding.RuleID,
		)
	}

	if finding.FindingType != "api_key" {
		t.Fatalf(
			"expected finding type api_key, got %s",
			finding.FindingType,
		)
	}

	if finding.Category != "sensitive_data" {
		t.Fatalf(
			"expected category sensitive_data, got %s",
			finding.Category,
		)
	}

	if finding.Detector.Service != "trust_guard" {
		t.Fatalf(
			"expected detector service trust_guard, got %s",
			finding.Detector.Service,
		)
	}

	if finding.Detector.DetectorID != "signature_detector" {
		t.Fatalf(
			"expected detector ID signature_detector, got %s",
			finding.Detector.DetectorID,
		)
	}

	if len(finding.Evidence) != 1 {
		t.Fatalf(
			"expected 1 evidence item, got %d",
			len(finding.Evidence),
		)
	}

	evidence := finding.Evidence[0]

	if evidence.EvidenceType != "signature_match" {
		t.Fatalf(
			"expected evidence type signature_match, got %s",
			evidence.EvidenceType,
		)
	}

	if evidence.EndOffset <= evidence.StartOffset {
		t.Fatalf(
			"expected evidence end offset to be greater than start offset",
		)
	}

	if evidence.RedactedValue == "" {
		t.Fatalf(
			"expected redacted value to not be empty",
		)
	}

	if event.Processing.Status != "completed" {
		t.Fatalf(
			"expected processing status completed, got %s",
			event.Processing.Status,
		)
	}

	if event.Processing.DurationMS < 0 {
		t.Fatalf(
			"expected processing duration to not be negative",
		)
	}
}

func TestOutputAnalyzerCleanContent(t *testing.T) {
	testRules := []types.DetectionRule{
		{
			ID:          "SD-002",
			Name:        "Generic API Key Assignment",
			Category:    "sensitive_data",
			FindingType: "api_key",
			AppliesTo:   []string{"model_output"},
			Pattern:     `(?i)(api[_-]?key)\s*(?::=|[:=])\s*["']?[^\s"']{8,}["']?`,
			Weight:      0.78,
			Severity:    "critical",
			Reason:      "Detected generic API key or secret key assignment",
		},
	}

	testPolicyConfig := types.PolicyConfig{
		SeverityConfig: []types.SeverityConfig{
			{
				Severity: "LOW",
				MinScore: 0.00,
				MaxScore: 0.49,
			},
			{
				Severity: "CRITICAL",
				MinScore: 0.50,
				MaxScore: 1.00,
			},
		},
		DefaultActionsConfig: map[string]string{
			"LOW":      "ALLOW",
			"CRITICAL": "BLOCK",
		},
		ResourceAbusePolicy: types.ResourceAbusePolicy{
			Enabled: true,
			ArtifactPolicies: map[types.ArtifactType]types.ArtifactResourcePolicy{
				types.ArtifactModelOutput: {
					MaxBytes: types.MaxBytesPolicy{
						Limit:       10000,
						Enforcement: types.EnforcementScored,
						Weight:      0.20,
					},
					MaxEstimatedTokens: types.MaxEstimatedTokensPolicy{
						Limit:       2500,
						Enforcement: types.EnforcementScored,
						Weight:      0.20,
					},
					RepeatedCharacters: types.RepeatedCharactersPolicy{
						MaxConsecutiveRun:   1000,
						MaxConsecutiveRatio: 1.00,
						MinimumCharacters:   1000,
						Enforcement:         types.EnforcementScored,
						Weight:              0.20,
					},
				},
			},
		},
	}

	requestBody := `{
		"content": "Dinosaurs lived millions of years ago."
	}`

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/analyze-output",
		strings.NewReader(requestBody),
	)

	request.Header.Set(
		"Content-Type",
		"application/json",
	)

	responseRecorder := httptest.NewRecorder()

	handler := HandleModelOutput(
		&testRules,
		&testPolicyConfig,
	)

	handler.ServeHTTP(
		responseRecorder,
		request,
	)

	if responseRecorder.Code != http.StatusOK {
		t.Fatalf(
			"expected status code %d, got %d",
			http.StatusOK,
			responseRecorder.Code,
		)
	}

	var event types.AITrustBoundaryEvent

	if err := json.NewDecoder(responseRecorder.Body).Decode(&event); err != nil {
		t.Fatalf(
			"failed to decode response body: %v",
			err,
		)
	}

	if event.Decision.HasFindings {
		t.Fatalf(
			"expected clean model output to not create findings",
		)
	}

	if len(event.Findings) != 0 {
		t.Fatalf(
			"expected no findings, got %d",
			len(event.Findings),
		)
	}

	if event.Decision.FinalRiskScore != 0 {
		t.Fatalf(
			"expected final risk score 0, got %f",
			event.Decision.FinalRiskScore,
		)
	}

	if event.Decision.Severity != "LOW" {
		t.Fatalf(
			"expected severity LOW, got %s",
			event.Decision.Severity,
		)
	}

	if event.Decision.Action != "ALLOW" {
		t.Fatalf(
			"expected action ALLOW, got %s",
			event.Decision.Action,
		)
	}

	if event.Artifact.ArtifactType != types.ArtifactModelOutput {
		t.Fatalf(
			"expected artifact type model_output, got %s",
			event.Artifact.ArtifactType,
		)
	}
}

func TestOutputAnalyzerEmptyBody(t *testing.T) {
	testRules := []types.DetectionRule{}
	testPolicyConfig := types.PolicyConfig{}

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/analyze-output",
		nil,
	)

	responseRecorder := httptest.NewRecorder()

	handler := HandleModelOutput(
		&testRules,
		&testPolicyConfig,
	)

	handler.ServeHTTP(
		responseRecorder,
		request,
	)

	if responseRecorder.Code != http.StatusBadRequest {
		t.Fatalf(
			"expected status code %d, got %d",
			http.StatusBadRequest,
			responseRecorder.Code,
		)
	}
}

func TestOutputAnalyzerMalformedBody(t *testing.T) {
	testRules := []types.DetectionRule{}
	testPolicyConfig := types.PolicyConfig{}

	requestBody := `{
		"content": "invalid JSON"
	`

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/analyze-output",
		strings.NewReader(requestBody),
	)

	responseRecorder := httptest.NewRecorder()

	handler := HandleModelOutput(
		&testRules,
		&testPolicyConfig,
	)

	handler.ServeHTTP(
		responseRecorder,
		request,
	)

	if responseRecorder.Code != http.StatusBadRequest {
		t.Fatalf(
			"expected status code %d, got %d",
			http.StatusBadRequest,
			responseRecorder.Code,
		)
	}
}

func TestOutputAnalyzerMissingContent(t *testing.T) {
	testRules := []types.DetectionRule{}
	testPolicyConfig := types.PolicyConfig{}

	requestBody := `{}`

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/analyze-output",
		strings.NewReader(requestBody),
	)

	responseRecorder := httptest.NewRecorder()

	handler := HandleModelOutput(
		&testRules,
		&testPolicyConfig,
	)

	handler.ServeHTTP(
		responseRecorder,
		request,
	)

	if responseRecorder.Code != http.StatusBadRequest {
		t.Fatalf(
			"expected status code %d, got %d",
			http.StatusBadRequest,
			responseRecorder.Code,
		)
	}
}

func TestOutputAnalyzerUnknownField(t *testing.T) {
	testRules := []types.DetectionRule{}
	testPolicyConfig := types.PolicyConfig{}

	requestBody := `{
		"content": "This content is valid.",
		"unknown_field": "This field should fail."
	}`

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/analyze-output",
		strings.NewReader(requestBody),
	)

	responseRecorder := httptest.NewRecorder()

	handler := HandleModelOutput(
		&testRules,
		&testPolicyConfig,
	)

	handler.ServeHTTP(
		responseRecorder,
		request,
	)

	if responseRecorder.Code != http.StatusBadRequest {
		t.Fatalf(
			"expected status code %d, got %d",
			http.StatusBadRequest,
			responseRecorder.Code,
		)
	}
}
