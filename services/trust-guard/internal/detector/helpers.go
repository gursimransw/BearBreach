package detector

import (
	"math"

	"github.com/gursimransw/BearBreach/services/trust-guard/internal/types"
)

func MaskRedactedValues(inputString string) string {
	runes := []rune(inputString)
	maskedRune := make([]rune, len(runes))

	for k, v := range runes {
		if k == 0 || k == len(runes)-1 {
			maskedRune[k] = v

		} else {

			maskedRune[k] = '*'

		}
	}
	return string(maskedRune)
}

func GetLongestConsecutiveCharacterRun(s string) int {
	if len(s) == 0 {
		return 0
	}

	runes := []rune(s)

	maxRun := 1
	currentRun := 1

	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1] {
			currentRun++

			if currentRun > maxRun {
				maxRun = currentRun
			}
		} else {
			currentRun = 1
		}
	}

	return maxRun
}

func DetectMaxBytes(content string, PolicyConfig types.PolicyConfig, Scancontext types.ScanContext) float64 {

	weight := 0.00
	artifactType := Scancontext.ArtifactType
	effectiveArtifactPolicy := PolicyConfig.ResourceAbusePolicy.ArtifactPolicies[artifactType]

	maxBytes := effectiveArtifactPolicy.MaxBytes.Limit
	contentBytes := len(content)
	if contentBytes > maxBytes {
		if effectiveArtifactPolicy.MaxBytes.Enforcement == "hard" {
			return 1.00

		} else {
			weight = effectiveArtifactPolicy.MaxBytes.Weight
			return weight

		}

	} else if contentBytes <= maxBytes {
		return weight

	}

	return weight
}

func DetectMaxTokens(content string, PolicyConfig types.PolicyConfig, Scancontext types.ScanContext) float64 {

	weight := 0.00
	artifactType := Scancontext.ArtifactType
	effectiveArtifactPolicy := PolicyConfig.ResourceAbusePolicy.ArtifactPolicies[artifactType]

	maxTokens := effectiveArtifactPolicy.MaxEstimatedTokens.Limit
	contentEstimatedTokens := math.Ceil(float64(len(content)) / 4.00) //This is a temporary logic, we will eventually bring proper token calculation logic later
	if contentEstimatedTokens > float64(maxTokens) {
		if effectiveArtifactPolicy.MaxEstimatedTokens.Enforcement == "hard" {
			return 1.00

		} else {
			weight = effectiveArtifactPolicy.MaxEstimatedTokens.Weight
			return weight

		}

	} else if contentEstimatedTokens <= float64(maxTokens) {
		return weight

	}

	return weight
}

func DetectRepeatedCharacters(content string, policyConfig types.PolicyConfig, scanContext types.ScanContext) float64 {

	artifactType := scanContext.ArtifactType
	effectiveArtifactPolicy := policyConfig.ResourceAbusePolicy.ArtifactPolicies[artifactType]

	repeatedCharactersPolicy := effectiveArtifactPolicy.RepeatedCharacters

	contentRunes := []rune(content)
	contentLength := len(contentRunes)

	if contentLength == 0 {
		return 0.00
	}

	// Only evaluate repetition when the content is large enough
	// for the ratio to be meaningful.
	if contentLength < repeatedCharactersPolicy.MinimumCharacters {
		return 0.00
	}

	longestRun := GetLongestConsecutiveCharacterRun(content)

	consecutiveRatio := float64(longestRun) / float64(contentLength)

	runExceeded := longestRun > repeatedCharactersPolicy.MaxConsecutiveRun

	ratioExceeded := consecutiveRatio > repeatedCharactersPolicy.MaxConsecutiveRatio

	if !runExceeded && !ratioExceeded {
		return 0.0
	}

	if repeatedCharactersPolicy.Enforcement == "hard" {
		return 1.00
	}

	if repeatedCharactersPolicy.Enforcement == "scored" {
		return repeatedCharactersPolicy.Weight
	}

	return 0.0
}
