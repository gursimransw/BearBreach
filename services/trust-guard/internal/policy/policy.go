package policy

import (
	"math"
	"sort"

	"github.com/gursimransw/BearBreach/services/trust-guard/internal/types"
)

/*
GetSeverityAndActionFromWeight takes the final aggregated risk score
and determines its severity and corresponding action.

The score already includes applicable signature, resource abuse,
and semantic detection weights.

This function is responsible only for mapping the final score
to a severity and action using the policy configuration.
*/
func GetSeverityAndActionFromWeight(
	PolicyConfig *types.PolicyConfig,
	weight float64,
) (string, string) {

	/*
		Reject invalid policy configurations and non-finite scores.
	*/
	if PolicyConfig == nil || len(PolicyConfig.SeverityConfig) == 0 {
		return "UNDEFINED", "LOG"
	}

	if math.IsNaN(weight) || math.IsInf(weight, 0) {
		return "UNDEFINED", "LOG"
	}

	/*
		Normalize the final weight to the supported range of 0 to 1.
	*/
	weight = math.Max(0, math.Min(1, weight))

	/*
		Create a copy of the severity thresholds and sort them
		by their minimum scores.

		This prevents incorrect classification if the thresholds
		are listed in a different order in policy.json.
	*/
	thresholds := append(
		[]types.SeverityConfig(nil),
		PolicyConfig.SeverityConfig...,
	)

	sort.Slice(thresholds, func(i, j int) bool {
		return thresholds[i].MinScore < thresholds[j].MinScore
	})

	/*
		Find the first severity threshold whose upper bound
		includes the calculated score.

		This also handles small gaps between configured ranges.
		For example, 0.245 will map to MEDIUM rather than
		returning UNDEFINED.
	*/
	for _, threshold := range thresholds {
		if weight <= threshold.MaxScore {
			severity := threshold.Severity
			action, exists := PolicyConfig.DefaultActionsConfig[severity]

			if !exists || action == "" {
				return "UNDEFINED", "LOG"
			}

			return severity, action
		}
	}

	/*
		If the score exceeds all configured thresholds,
		return a fallback instead of assigning an unknown action.
	*/
	return "UNDEFINED", "LOG"
}
