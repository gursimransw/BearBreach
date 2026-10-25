package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gursimransw/BearBreach/services/trust-guard/internal/types"
)

const maxSemanticResponseBytes = 1 << 20

func NewSemanticDetectorClient(serviceURL string, timeout time.Duration) (types.SemanticDetectorClient, error) {
	parsed, err := url.Parse(serviceURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return types.SemanticDetectorClient{}, errors.New("semantic detector service URL must be an HTTP(S) origin without a path")
	}
	if timeout <= 0 {
		return types.SemanticDetectorClient{}, errors.New("semantic detector timeout must be positive")
	}
	return types.SemanticDetectorClient{
		ServiceURL: strings.TrimRight(serviceURL, "/"),
		HTTPClient: http.Client{Timeout: timeout},
	}, nil
}

func Analyze(ctx context.Context, client types.SemanticDetectorClient, request types.SemanticDetectorRequest) (types.SemanticDetectorServiceResponse, error) {
	empty := types.SemanticDetectorServiceResponse{}
	if strings.TrimSpace(client.ServiceURL) == "" {
		return empty, types.SemanticClientError{Kind: "invalid_request", Err: errors.New("client is not initialized")}
	}
	if strings.TrimSpace(request.RequestID) == "" || strings.TrimSpace(request.TenantID) == "" || strings.TrimSpace(request.ApplicationID) == "" || strings.TrimSpace(request.Text) == "" {
		return empty, types.SemanticClientError{Kind: "invalid_request", Err: errors.New("required request fields are missing")}
	}
	if request.ArtifactType != types.ArtifactType("user_input") && request.ArtifactType != types.ArtifactType("model_output") {
		return empty, types.SemanticClientError{Kind: "invalid_request", Err: errors.New("unsupported artifact type")}
	}

	body, err := json.Marshal(request)
	if err != nil {
		return empty, types.SemanticClientError{Kind: "invalid_request", Err: err}
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, client.ServiceURL+"/v1/analyze", bytes.NewReader(body))
	if err != nil {
		return empty, types.SemanticClientError{Kind: "invalid_request", Err: err}
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("X-Request-ID", request.RequestID)

	httpResponse, err := client.HTTPClient.Do(httpRequest)
	if err != nil {
		kind := "unavailable"
		var netError net.Error
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) || (errors.As(err, &netError) && netError.Timeout()) {
			kind = "timeout"
		} else if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			kind = "canceled"
		}
		return empty, types.SemanticClientError{Kind: kind, Err: err}
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != http.StatusOK {
		return empty, types.SemanticClientError{Kind: "http_error", StatusCode: httpResponse.StatusCode, Err: errors.New("service rejected analysis request")}
	}

	responseBody, err := io.ReadAll(io.LimitReader(httpResponse.Body, maxSemanticResponseBytes+1))
	if err != nil {
		return empty, types.SemanticClientError{Kind: "invalid_response", Err: err}
	}
	if len(responseBody) > maxSemanticResponseBytes {
		return empty, types.SemanticClientError{Kind: "invalid_response", Err: errors.New("response exceeds maximum size")}
	}
	if err := validateRequiredFields(responseBody); err != nil {
		return empty, types.SemanticClientError{Kind: "invalid_response", Err: err}
	}

	var response types.SemanticDetectorServiceResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return empty, types.SemanticClientError{Kind: "invalid_response", Err: err}
	}
	if err := validateSemanticResponse(request, response); err != nil {
		return empty, types.SemanticClientError{Kind: "invalid_response", Err: err}
	}
	return response, nil
}

func validateRequiredFields(body []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return err
	}
	if err := requireJSONFields(root, "request_id", "tenant_id", "application_id", "artifact_type", "detector_version", "model", "result"); err != nil {
		return err
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(root["result"], &result); err != nil || result == nil {
		return errors.New("result must be an object")
	}
	if err := requireJSONFields(result, "detected", "category_candidate", "malicious_similarity", "benign_similarity", "semantic_margin", "scoring_strategy", "processing_time_ms", "category_scores", "matched_reference_ids"); err != nil {
		return err
	}
	// Python returns null for predicted_category when no attack is detected.
	if _, ok := result["predicted_category"]; !ok {
		return errors.New("missing required field predicted_category")
	}
	return nil
}

func requireJSONFields(object map[string]json.RawMessage, names ...string) error {
	for _, name := range names {
		value, ok := object[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("missing or null required field %q", name)
		}
	}
	return nil
}

func validateSemanticResponse(request types.SemanticDetectorRequest, response types.SemanticDetectorServiceResponse) error {
	if response.RequestID != request.RequestID || response.TenantID != request.TenantID || response.ApplicationID != request.ApplicationID || response.ArtifactType != request.ArtifactType {
		return errors.New("response correlation fields do not match request")
	}
	if response.DetectorVersion == "" || response.Model == "" || response.Result.ScoringStrategy == "" {
		return errors.New("missing detector metadata")
	}
	result := response.Result
	if !validRange(result.MaliciousSimilarity, -1, 1) || !validRange(result.BenignSimilarity, -1, 1) || !validRange(result.SemanticMargin, -2, 2) || !validRange(result.ProcessingTimeMS, 0, math.MaxFloat64) {
		return errors.New("invalid numeric score")
	}
	if len(result.CategoryScores) == 0 {
		return errors.New("category_scores must not be empty")
	}
	for category, score := range result.CategoryScores {
		if !supportedCategory(category) || !validRange(score, -1, 1) {
			return fmt.Errorf("invalid category or similarity score for %q", category)
		}
	}
	if !supportedCategory(result.CategoryCandidate) {
		return errors.New("invalid category_candidate")
	}
	if result.Detected {
		if !supportedCategory(result.PredictedCategory) || result.PredictedCategory != result.CategoryCandidate {
			return errors.New("detected result has invalid predicted_category")
		}
	} else if result.PredictedCategory != "" {
		return errors.New("undetected result must have null predicted_category")
	}
	return nil
}

func validRange(value, min, max float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= min && value <= max
}

func supportedCategory(category string) bool {
	switch category {
	case "prompt_injection", "jailbreak", "role_manipulation", "system_prompt_extraction":
		return true
	default:
		return false
	}
}
