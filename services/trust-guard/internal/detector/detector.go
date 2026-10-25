package detector

import (
	"context"
	"fmt"
	"math"
	"unicode/utf8"

	"github.com/gursimransw/BearBreach/services/trust-guard/internal/policy"
	"github.com/gursimransw/BearBreach/services/trust-guard/internal/scoring"
	"github.com/gursimransw/BearBreach/services/trust-guard/internal/types"
)

func AnalyzeContent(
	ctx context.Context,
	requestID string,
	Rules *[]types.DetectionRule,
	PolicyConfig *types.PolicyConfig,
	targetString string,
	scanContext types.ScanContext,
	semanticClient types.SemanticDetectorClient,
) (types.AnalysisResult, error) {

	/*
		Validate the policy configuration before running any detection components.
	*/

	if PolicyConfig == nil {
		return types.AnalysisResult{}, fmt.Errorf("content analysis: policy configuration is nil")
	}

	/*
		Run signature-based detection against the artifact.
	*/

	signatureDetectionComponentResult := SignatureDetector(
		Rules,
		PolicyConfig,
		targetString,
		scanContext,
	)

	/*
		Check for resource abuse, including hard policy constraints.
	*/

	resourceAbuseDetectionComponentResult := DetectResourceAbuse(
		PolicyConfig,
		targetString,
		scanContext,
	)

	/*
		Send the artifact to the Python Semantic Detector service.

		The semantic detector applies the configured observation or enforcement
		mode. A service failure is returned as an error and must not be treated
		as a negative detection.
	*/

	semanticDetectionComponentResult, err := SemanticDetector(
		ctx,
		requestID,
		targetString,
		scanContext,
		PolicyConfig,
		semanticClient,
	)

	if err != nil {
		return types.AnalysisResult{}, fmt.Errorf(
			"content analysis: semantic detector failed: %w",
			err,
		)
	}

	/*
		Merge findings from all detection components.
	*/

	eventFindings := make([]types.EventFinding, 0)

	eventFindings = append(
		eventFindings,
		signatureDetectionComponentResult.Findings...,
	)

	eventFindings = append(
		eventFindings,
		resourceAbuseDetectionComponentResult.Findings...,
	)

	eventFindings = append(
		eventFindings,
		semanticDetectionComponentResult.Findings...,
	)

	/*
		Assign finding IDs only after findings from all detectors
		have been combined.

		This prevents duplicate IDs between the different detectors.
	*/

	for index := range eventFindings {
		eventFindings[index].FindingID = fmt.Sprintf(
			"finding-%d",
			index+1,
		)
	}

	/*
		Create component scores.

		In observation mode, semantic detection contributes zero to
		the enforced risk score even when a semantic finding is present.
	*/

	componentScores := types.ComponentScores{
		"signature_detection": signatureDetectionComponentResult.Score,
		"resource_abuse":      resourceAbuseDetectionComponentResult.Score,
		"semantic_detection":  semanticDetectionComponentResult.Score,
	}

	/*
		Calculate and normalize the final risk score using the scores
		from all three detection components.
	*/

	finalRiskScore := scoring.NormalizeScores(
		signatureDetectionComponentResult.Score +
			resourceAbuseDetectionComponentResult.Score +
			semanticDetectionComponentResult.Score,
	)

	/*
		Apply the normal score-to-severity and action policy.
	*/

	effectiveSeverity, effectiveAction :=
		policy.GetSeverityAndActionFromWeight(
			PolicyConfig,
			finalRiskScore,
		)

	/*
		The risk-score policy is always evaluated, even when the
		final score is zero and the resulting action is ALLOW.
	*/

	decisionBasis := []string{
		"risk_score",
	}

	/*
		A hard resource constraint must be preserved separately
		from the numerical risk score.

		For now, a hard constraint forces CRITICAL and BLOCK.
		Semantic detection is a scored signal, not a hard constraint.
	*/

	constraintViolated :=
		resourceAbuseDetectionComponentResult.ConstraintViolated

	if constraintViolated {
		effectiveSeverity = "CRITICAL"
		effectiveAction = "BLOCK"

		decisionBasis = append(
			decisionBasis,
			"policy_constraint",
		)
	}

	/*
		Calculate artifact measurements.
	*/

	byteCount := len(targetString)

	characterCount :=
		utf8.RuneCountInString(targetString)

	estimatedTokens := int(
		math.Ceil(float64(byteCount) / 4.0),
	)

	/*
		Build and return the complete analysis result.
	*/

	analysisResult := types.AnalysisResult{
		HasFindings: len(eventFindings) > 0,

		Findings: eventFindings,

		ComponentScores: componentScores,

		FinalRiskScore: finalRiskScore,

		ConstraintViolated: constraintViolated,

		Severity: effectiveSeverity,

		Action: effectiveAction,

		DecisionBasis: decisionBasis,

		ByteCount: byteCount,

		CharacterCount: characterCount,

		EstimatedTokens: estimatedTokens,
	}

	return analysisResult, nil
}
