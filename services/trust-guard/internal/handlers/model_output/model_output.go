package modelOutput

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/gursimransw/BearBreach/services/trust-guard/internal/detector"
	"github.com/gursimransw/BearBreach/services/trust-guard/internal/events"
	"github.com/gursimransw/BearBreach/services/trust-guard/internal/models"
	"github.com/gursimransw/BearBreach/services/trust-guard/internal/types"
)

const (
	producerService        = "trust_guard"
	producerServiceVersion = "1.0.0"
)

var validate = validator.New()

func HandleModelOutput(
	detectionRules *[]types.DetectionRule,
	policyConfig *types.PolicyConfig,
	semanticClient types.SemanticDetectorClient,
) http.HandlerFunc {

	/*
		The semantic client is supplied when the handler is registered.
		The same configured client can be reused by both input and output handlers.
	*/

	return func(w http.ResponseWriter, r *http.Request) {
		startedAt := time.Now()
		requestID := uuid.NewString()

		slog.Info(
			"API request received",
			slog.String("method", r.Method),
			slog.String("endpoint", r.RequestURI),
			slog.String("remote_address", r.RemoteAddr),
			slog.String("user_agent", r.UserAgent()),
			slog.String("request_id", requestID),
		)

		/*
			Decode the request body and reject unknown JSON fields.
		*/

		var output types.Content

		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&output)

		if errors.Is(err, io.EOF) {
			models.WriteJson(
				w,
				http.StatusBadRequest,
				models.GeneralError(
					fmt.Errorf("empty request body"),
					requestID,
				),
			)

			slog.Warn(
				"Received an empty request body",
				slog.String("request_id", requestID),
			)

			return
		}

		if err != nil {
			models.WriteJson(
				w,
				http.StatusBadRequest,
				models.GeneralError(err, requestID),
			)

			slog.Warn(
				"Received a malformed request",
				slog.String("error", err.Error()),
				slog.String("request_id", requestID),
			)

			return
		}

		/*
			Validate the decoded request before passing its content
			to the detection pipeline.
		*/

		if err := validate.Struct(output); err != nil {
			validationErrors, ok := err.(validator.ValidationErrors)

			if !ok {
				models.WriteJson(
					w,
					http.StatusInternalServerError,
					models.GeneralError(err, requestID),
				)

				slog.Error(
					"Unexpected request validation error",
					slog.String("error", err.Error()),
					slog.String("request_id", requestID),
				)

				return
			}

			models.WriteJson(
				w,
				http.StatusBadRequest,
				models.ValidationError(
					validationErrors,
					requestID,
				),
			)

			slog.Warn(
				"Request validation failed",
				slog.String("error", validationErrors.Error()),
				slog.String("request_id", requestID),
			)

			return
		}

		/*
			ArtifactType is trusted because this is specifically
			the model-output handler.

			TenantID and ApplicationID remain hardcoded temporarily.
			Later:
			- TenantID should come from authentication.
			- ApplicationID should come from the route or request
			  and be validated against the tenant.
		*/

		scanContext := types.ScanContext{
			ArtifactType:  types.ArtifactModelOutput,
			TenantID:      "tenant-001",
			ApplicationID: "application-001",
		}

		/*
			AnalyzeContent runs signature, resource-abuse, and semantic
			detection. The request context allows the Python HTTP call
			to be canceled when this request is canceled.

			The same request ID is forwarded to the semantic service
			to correlate the two services' analysis records.
		*/

		analysisResult, err := detector.AnalyzeContent(
			r.Context(),
			requestID,
			detectionRules,
			policyConfig,
			output.Content,
			scanContext,
			semanticClient,
		)

		/*
			The current analysis pipeline returns an error if semantic
			analysis fails. Do not create a completed event or report
			the artifact as clean when the scan was incomplete.

			A future degraded-analysis mode can preserve successful
			detector results while identifying the failed component.
		*/

		if err != nil {
			slog.Error(
				"Model output analysis failed",
				slog.String("request_id", requestID),
				slog.String("error", err.Error()),
			)

			models.WriteJson(
				w,
				http.StatusServiceUnavailable,
				models.GeneralError(
					fmt.Errorf("content analysis could not be completed"),
					requestID,
				),
			)

			return
		}

		/*
			This duration measures processing from handler entry
			through completion of content analysis, including the
			semantic service request when enabled.
		*/

		durationMS :=
			float64(time.Since(startedAt).Microseconds()) / 1000.0

		processing := types.Processing{
			Status:     "completed",
			DurationMS: durationMS,
		}

		eventContext := types.EventContext{
			TenantID:      scanContext.TenantID,
			ApplicationID: scanContext.ApplicationID,
		}

		/*
			Producer information is server-owned and must not come
			from the request body.
		*/

		producer := types.Producer{
			Service:        producerService,
			ServiceVersion: producerServiceVersion,
		}

		/*
			This assumes the endpoint scans the model response
			immediately after generation, before the application
			processes or returns it to the user.
		*/

		boundary := types.TrustBoundary{
			Name:                 "model_to_application",
			SourceComponent:      "model",
			DestinationComponent: "application",
			Stage:                "post_model",
		}

		artifact := types.Artifact{
			ArtifactType:        scanContext.ArtifactType,
			Origin:              "model",
			MessageRole:         "assistant",
			ContentType:         "text/plain",
			ContentEncoding:     "utf-8",
			ByteCount:           analysisResult.ByteCount,
			CharacterCount:      analysisResult.CharacterCount,
			EstimatedTokenCount: analysisResult.EstimatedTokens,
		}

		/*
			ComponentScores now includes semantic_detection.
			Observation mode records semantic findings without adding
			the semantic weight to the enforced final risk score.
		*/

		decision := types.Decision{
			HasFindings:     analysisResult.HasFindings,
			ComponentScores: analysisResult.ComponentScores,
			FinalRiskScore:  analysisResult.FinalRiskScore,
			Severity:        analysisResult.Severity,
			Action:          analysisResult.Action,
			Basis:           analysisResult.DecisionBasis,
		}

		/*
			Create the AI Trust Boundary Event with findings gathered
			from all enabled detection components.
		*/

		event := events.GenerateAITrustBoundaryEvent(
			producer,
			eventContext,
			boundary,
			artifact,
			analysisResult.Findings,
			decision,
			processing,
			requestID,
		)

		slog.Info(
			"Model output analysis completed",
			slog.String("request_id", requestID),
			slog.String(
				"artifact_type",
				string(scanContext.ArtifactType),
			),
			slog.Float64(
				"risk_score",
				analysisResult.FinalRiskScore,
			),
			slog.Bool(
				"constraint_violated",
				analysisResult.ConstraintViolated,
			),
			slog.String(
				"severity",
				analysisResult.Severity,
			),
			slog.String(
				"action",
				analysisResult.Action,
			),
			slog.Int(
				"finding_count",
				len(analysisResult.Findings),
			),
			slog.Float64(
				"duration_ms",
				durationMS,
			),
		)

		models.WriteJson(
			w,
			http.StatusOK,
			event,
		)
	}
}
