package detector

import (
	"regexp"

	"github.com/gursimransw/BearBreach/services/trust-guard/internal/scoring"
	"github.com/gursimransw/BearBreach/services/trust-guard/internal/types"
)

func SignatureDetector(
	Rules *[]types.DetectionRule,
	PolicyConfig *types.PolicyConfig,
	targetString string,
	scanContext types.ScanContext,
) types.DetectionComponentResult {

	totalRiskScore := 0.00

	detectionComponentResult := types.DetectionComponentResult{
		ComponentName:      "Signature Detector",
		Score:              totalRiskScore,
		ConstraintViolated: false,
	}

	var eventFindingsSlice types.EventFindingSlice

	for _, rule := range *Rules {
		for _, artifactType := range rule.AppliesTo {
			if string(scanContext.ArtifactType) != artifactType {
				continue
			}

			ruleRegexPattern := regexp.MustCompile(rule.Pattern)
			matchedIndexSlices := ruleRegexPattern.FindAllStringIndex(targetString, -1)

			if len(matchedIndexSlices) == 0 {
				continue
			}

			var evidences types.EvidenceSlice

			for _, indexSlice := range matchedIndexSlices {
				startIndex := indexSlice[0]
				endIndex := indexSlice[1]
				matchedValue := targetString[startIndex:endIndex]

				evidence := types.Evidence{
					EvidenceType: "signature_match",
					StartOffset:  startIndex,
					EndOffset:    endIndex,
				}

				if rule.Category == "sensitive_data" {
					evidence.RedactedValue =
						MaskRedactedValues(matchedValue)
				}

				evidences.AppendEvidenceSlice(evidence)
			}

			eventFinding := types.EventFinding{
				FindingType:      rule.FindingType,
				Category:         rule.Category,
				Title:            rule.Reason,
				RiskContribution: scoring.NormalizeScores(rule.Weight),
				RuleID:           rule.ID,
				Detector: types.Detector{
					Service:    "trust_guard",
					DetectorID: "signature_detector",
					Version:    "1.0.0",
				},
				Evidence: evidences.EvidenceSlice,
			}

			eventFindingsSlice.AppendEventFindingSlice(eventFinding)
			totalRiskScore += rule.Weight

			break
		}
	}

	detectionComponentResult.Score = scoring.NormalizeScores(totalRiskScore)
	detectionComponentResult.Findings =
		eventFindingsSlice.EventFindingSlice

	return detectionComponentResult
}
