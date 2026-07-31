package detector

import (
	"log/slog"
	"math"

	"github.com/gursimransw/BearBreach/services/trust-guard/internal/scoring"
	"github.com/gursimransw/BearBreach/services/trust-guard/internal/types"
)

func DetectResourceAbuse(
	policyConfig *types.PolicyConfig,
	targetString string,
	scanContext types.ScanContext,
) types.DetectionComponentResult {

	detectionComponentResult := types.DetectionComponentResult{
		ComponentName:      "resource_abuse",
		Score:              0.00,
		ConstraintViolated: false,
		Findings:           make([]types.EventFinding, 0),
	}

	artifactType := scanContext.ArtifactType

	artifactPolicy, exists :=
		policyConfig.ResourceAbusePolicy.ArtifactPolicies[artifactType]

	if !exists {
		slog.Error(
			"Unable to find resource abuse policy",
			slog.String("artifact_type", string(artifactType)),
		)

		detectionComponentResult.Score = 1.00
		detectionComponentResult.ConstraintViolated = true

		return detectionComponentResult
	}

	if !policyConfig.ResourceAbusePolicy.Enabled {
		slog.Info(
			"Resource abuse policy is disabled",
			slog.String("artifact_type", string(artifactType)),
		)

		return detectionComponentResult
	}

	slog.Info(
		"Using resource abuse policy",
		slog.String("artifact_type", string(artifactType)),
	)

	maxBytesWeight :=
		DetectMaxBytes(targetString, *policyConfig, scanContext)

	maxTokensWeight :=
		DetectMaxTokens(targetString, *policyConfig, scanContext)

	repeatedCharactersWeight :=
		DetectRepeatedCharacters(targetString, *policyConfig, scanContext)

	/*
		MAXIMUM BYTES
	*/

	contentBytes := len(targetString)

	if maxBytesWeight > 0.00 {
		maxBytesEvidence := types.Evidence{
			EvidenceType:    "metric_threshold",
			ObservedValue:   float64(contentBytes),
			ConfiguredLimit: float64(artifactPolicy.MaxBytes.Limit),
			Unit:            "bytes",
		}

		findingType := "resource_indicator"

		if artifactPolicy.MaxBytes.Enforcement == "hard" {
			findingType = "resource_constraint"
			detectionComponentResult.ConstraintViolated = true
		}

		maxBytesFinding := types.EventFinding{
			FindingType:      findingType,
			Category:         "maximum_bytes_exceeded",
			Title:            "Maximum artifact size exceeded",
			RiskContribution: maxBytesWeight,
			Detector: types.Detector{
				Service:    "trust_guard",
				DetectorID: "resource_abuse_detector",
				Version:    "1.0.0",
			},
			Evidence: []types.Evidence{
				maxBytesEvidence,
			},
		}

		detectionComponentResult.Findings = append(
			detectionComponentResult.Findings,
			maxBytesFinding,
		)
	}

	/*
		ESTIMATED TOKENS
	*/

	estimatedTokens :=
		math.Ceil(float64(len(targetString)) / 4.00)

	if maxTokensWeight > 0.00 {
		maxTokensEvidence := types.Evidence{
			EvidenceType:  "metric_threshold",
			ObservedValue: estimatedTokens,
			ConfiguredLimit: float64(
				artifactPolicy.MaxEstimatedTokens.Limit,
			),
			Unit: "estimated_tokens",
		}

		findingType := "resource_indicator"

		if artifactPolicy.MaxEstimatedTokens.Enforcement == "hard" {
			findingType = "resource_constraint"
			detectionComponentResult.ConstraintViolated = true
		}

		maxTokensFinding := types.EventFinding{
			FindingType:      findingType,
			Category:         "estimated_token_limit_exceeded",
			Title:            "Estimated token threshold exceeded",
			RiskContribution: maxTokensWeight,
			Detector: types.Detector{
				Service:    "trust_guard",
				DetectorID: "resource_abuse_detector",
				Version:    "1.0.0",
			},
			Evidence: []types.Evidence{
				maxTokensEvidence,
			},
		}

		detectionComponentResult.Findings = append(
			detectionComponentResult.Findings,
			maxTokensFinding,
		)
	}

	/*
		REPEATED CHARACTERS
	*/

	contentRunes := []rune(targetString)
	contentLength := len(contentRunes)

	if repeatedCharactersWeight > 0.00 && contentLength > 0 {
		longestRun :=
			GetLongestConsecutiveCharacterRun(targetString)

		repetitionRatio :=
			float64(longestRun) / float64(contentLength)

		repetitionEvidence := make([]types.Evidence, 0)

		if longestRun >
			artifactPolicy.RepeatedCharacters.MaxConsecutiveRun {

			repetitionEvidence = append(
				repetitionEvidence,
				types.Evidence{
					EvidenceType:  "metric_threshold",
					ObservedValue: float64(longestRun),
					ConfiguredLimit: float64(
						artifactPolicy.
							RepeatedCharacters.
							MaxConsecutiveRun,
					),
					Unit: "consecutive_characters",
				},
			)
		}

		if repetitionRatio >
			artifactPolicy.RepeatedCharacters.MaxConsecutiveRatio {

			repetitionEvidence = append(
				repetitionEvidence,
				types.Evidence{
					EvidenceType:  "metric_threshold",
					ObservedValue: repetitionRatio,
					ConfiguredLimit: artifactPolicy.
						RepeatedCharacters.
						MaxConsecutiveRatio,
					Unit: "ratio",
				},
			)
		}

		findingType := "resource_indicator"

		if artifactPolicy.RepeatedCharacters.Enforcement == "hard" {
			findingType = "resource_constraint"
			detectionComponentResult.ConstraintViolated = true
		}

		repeatedCharactersFinding := types.EventFinding{
			FindingType:      findingType,
			Category:         "repeated_character_flooding",
			Title:            "Excessive character repetition detected",
			RiskContribution: repeatedCharactersWeight,
			Detector: types.Detector{
				Service:    "trust_guard",
				DetectorID: "resource_abuse_detector",
				Version:    "1.0.0",
			},
			Evidence: repetitionEvidence,
		}

		detectionComponentResult.Findings = append(
			detectionComponentResult.Findings,
			repeatedCharactersFinding,
		)
	}

	/*
		COMBINE SCORES
	*/

	detectionComponentResult.Score = scoring.NormalizeScores(maxBytesWeight + maxTokensWeight + repeatedCharactersWeight)
	return detectionComponentResult
}
