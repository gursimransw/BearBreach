package detector

import (
	"fmt"
	"math"
	"unicode/utf8"

	"github.com/gursimransw/BearBreach/services/trust-guard/internal/policy"
	"github.com/gursimransw/BearBreach/services/trust-guard/internal/scoring"
	"github.com/gursimransw/BearBreach/services/trust-guard/internal/types"
)

func AnalyzeContent(
	Rules *[]types.DetectionRule,
	PolicyConfig *types.PolicyConfig,
	targetString string,
	scanContext types.ScanContext,
) types.AnalysisResult {

	signatureDetectionComponentResult := SignatureDetector(
		Rules,
		PolicyConfig,
		targetString,
		scanContext,
	)

	// DetectResourceAbuse currently accepts PolicyConfig as a value,
	// so the pointer is dereferenced here.
	resourceAbuseDetectionComponentResult := DetectResourceAbuse(
		PolicyConfig,
		targetString,
		scanContext,
	)

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

	/*
		Assign finding IDs only after findings from all detectors
		have been combined.

		This prevents duplicate IDs such as:
		Signature Detector: finding-1
		Resource Abuse Detector: finding-1
	*/

	for index := range eventFindings {
		eventFindings[index].FindingID = fmt.Sprintf(
			"finding-%d",
			index+1,
		)
	}

	/*
		Create component scores.
	*/

	componentScores := types.ComponentScores{
		"signature_detection": signatureDetectionComponentResult.Score,
		"resource_abuse":      resourceAbuseDetectionComponentResult.Score,
	}

	/*
		Calculate and normalize the final risk score.
	*/

	finalRiskScore := scoring.NormalizeScores(
		signatureDetectionComponentResult.Score +
			resourceAbuseDetectionComponentResult.Score,
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
		This override can later be moved into the policy package.
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

	return analysisResult
}
