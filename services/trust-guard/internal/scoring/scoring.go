package scoring

import (
	"github.com/gursimransw/BearBreach/services/trust-guard/internal/types"
)

func GetEffectiveRiskScoreByMatchedRules(matchedRules types.DetectionRuleList) float64 {

	effectiveRiskScore := 0.00

	//Here we are looping over the matched rules array and get the sum of their weights in order to calculate net effective weight (Risk Score)

	for _, rule := range matchedRules.RuleList {

		effectiveRiskScore = effectiveRiskScore + rule.Weight
		if effectiveRiskScore > 1.00 {
			effectiveRiskScore = 1.00
		}

	}
	return effectiveRiskScore //return effective risk score
}

func NormalizeScores(totalRiskScore float64) float64 {

	if totalRiskScore > 1.00 {
		totalRiskScore = 1.00
	}

	return totalRiskScore //return effective risk score
}
