package userInput

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

func HandleUserInput(
	detectionRules *[]types.DetectionRule,
	policyConfig *types.PolicyConfig,
	semanticClient types.SemanticDetectorClient,
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

		var input types.Content

		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&input)

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

		if err := validate.Struct(input); err != nil {
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
			ArtifactType is trusted because this endpoint specifically
			handles user input.

			TenantID and ApplicationID remain hardcoded temporarily.

			Later:
			- TenantID should be resolved through authentication.
			- ApplicationID should come from the route or request and
			  be validated against the authenticated tenant.
		*/

		scanContext := types.ScanContext{
			ArtifactType:  types.ArtifactUserInput,
			TenantID:      "tenant-001",
			ApplicationID: "application-001",
		}

		/*
			Run signature, resource-abuse, and semantic detection.

			The same semantic client is shared across requests, while
			r.Context() lets an interrupted request cancel its HTTP call.
			The generated request ID is propagated to the Python service.
		*/

		analysisResult, err := detector.AnalyzeContent(
			r.Context(),
			requestID,
			detectionRules,
			policyConfig,
			input.Content,
			scanContext,
			semanticClient,
		)

		/*
			A failed semantic analysis is not the same as a clean scan.
			The current analysis pipeline returns an error instead of
			an incomplete result, so do not generate a completed event.
		*/

		if err != nil {
			slog.Error(
				"User input analysis failed",
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
			This measures processing from handler entry through
			completion of content analysis.
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
			Producer metadata is controlled by Trust Guard and must
			not be accepted from the request.
		*/

		producer := types.Producer{
			Service:        producerService,
			ServiceVersion: producerServiceVersion,
		}

		/*
			This handler represents untrusted user-controlled input
			entering the protected AI application.
		*/

		boundary := types.TrustBoundary{
			Name:                 "user_to_application",
			SourceComponent:      "end_user",
			DestinationComponent: "application",
			Stage:                "ingress",
		}

		artifact := types.Artifact{
			ArtifactType:        scanContext.ArtifactType,
			Origin:              "end_user",
			MessageRole:         "user",
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
			"User input analysis completed",
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
