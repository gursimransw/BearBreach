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
) http.HandlerFunc {

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

		analysisResult := detector.AnalyzeContent(
			detectionRules,
			policyConfig,
			output.Content,
			scanContext,
		)

		/*
			This duration measures processing from handler entry
			through completion of content analysis.
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

		decision := types.Decision{
			HasFindings:     analysisResult.HasFindings,
			ComponentScores: analysisResult.ComponentScores,
			FinalRiskScore:  analysisResult.FinalRiskScore,
			Severity:        analysisResult.Severity,
			Action:          analysisResult.Action,
			Basis:           analysisResult.DecisionBasis,
		}

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
