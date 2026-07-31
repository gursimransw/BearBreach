package detector

import (
	"testing"

	"github.com/gursimransw/BearBreach/services/trust-guard/internal/types"
)

func TestMaskRedactedValues(t *testing.T) {
	inputString := "api_key"
	expectedMaskedString := "a*****y"

	maskedString := MaskRedactedValues(inputString)

	if maskedString != expectedMaskedString {
		t.Fatalf(
			"expected masked string %s, got %s",
			expectedMaskedString,
			maskedString,
		)
	}

	singleCharacterString := "A"

	maskedString = MaskRedactedValues(singleCharacterString)

	if maskedString != "A" {
		t.Fatalf(
			"expected single character string A, got %s",
			maskedString,
		)
	}

	twoCharacterString := "AB"

	maskedString = MaskRedactedValues(twoCharacterString)

	if maskedString != "AB" {
		t.Fatalf(
			"expected two character string AB, got %s",
			maskedString,
		)
	}

	emptyString := ""

	maskedString = MaskRedactedValues(emptyString)

	if maskedString != "" {
		t.Fatalf(
			"expected empty string, got %s",
			maskedString,
		)
	}

	unicodeString := "秘密値"

	maskedString = MaskRedactedValues(unicodeString)

	if maskedString != "秘*値" {
		t.Fatalf(
			"expected unicode string 秘*値, got %s",
			maskedString,
		)
	}
}

func TestGetLongestConsecutiveCharacterRun(t *testing.T) {
	emptyString := ""

	longestRun := GetLongestConsecutiveCharacterRun(emptyString)

	if longestRun != 0 {
		t.Fatalf(
			"expected longest run 0 for empty string, got %d",
			longestRun,
		)
	}

	singleCharacterString := "A"

	longestRun = GetLongestConsecutiveCharacterRun(
		singleCharacterString,
	)

	if longestRun != 1 {
		t.Fatalf(
			"expected longest run 1 for single character, got %d",
			longestRun,
		)
	}

	contentWithoutRepetition := "abcdef"

	longestRun = GetLongestConsecutiveCharacterRun(
		contentWithoutRepetition,
	)

	if longestRun != 1 {
		t.Fatalf(
			"expected longest run 1, got %d",
			longestRun,
		)
	}

	contentWithRepetition := "aaabbbbbcc"

	longestRun = GetLongestConsecutiveCharacterRun(
		contentWithRepetition,
	)

	if longestRun != 5 {
		t.Fatalf(
			"expected longest run 5, got %d",
			longestRun,
		)
	}

	contentEndingWithRepetition := "abcdddddd"

	longestRun = GetLongestConsecutiveCharacterRun(
		contentEndingWithRepetition,
	)

	if longestRun != 6 {
		t.Fatalf(
			"expected longest run 6, got %d",
			longestRun,
		)
	}

	unicodeContent := "你你你好吗"

	longestRun = GetLongestConsecutiveCharacterRun(
		unicodeContent,
	)

	if longestRun != 3 {
		t.Fatalf(
			"expected unicode longest run 3, got %d",
			longestRun,
		)
	}
}

func TestDetectMaxBytes(t *testing.T) {
	testPolicyConfig := types.PolicyConfig{
		ResourceAbusePolicy: types.ResourceAbusePolicy{
			Enabled: true,
			ArtifactPolicies: map[types.ArtifactType]types.ArtifactResourcePolicy{
				types.ArtifactUserInput: {
					MaxBytes: types.MaxBytesPolicy{
						Limit:       10,
						Enforcement: types.EnforcementScored,
						Weight:      0.25,
					},
				},
				types.ArtifactModelOutput: {
					MaxBytes: types.MaxBytesPolicy{
						Limit:       5,
						Enforcement: types.EnforcementHard,
					},
				},
			},
		},
	}

	userInputScanContext := types.ScanContext{
		ArtifactType:  types.ArtifactUserInput,
		TenantID:      "Test-001",
		ApplicationID: "Application-001",
	}

	contentBelowLimit := "12345"

	weight := DetectMaxBytes(
		contentBelowLimit,
		testPolicyConfig,
		userInputScanContext,
	)

	if weight != 0 {
		t.Fatalf(
			"expected weight 0 for content below byte limit, got %f",
			weight,
		)
	}

	contentEqualToLimit := "1234567890"

	weight = DetectMaxBytes(
		contentEqualToLimit,
		testPolicyConfig,
		userInputScanContext,
	)

	if weight != 0 {
		t.Fatalf(
			"expected weight 0 for content equal to byte limit, got %f",
			weight,
		)
	}

	contentAboveLimit := "12345678901"

	weight = DetectMaxBytes(
		contentAboveLimit,
		testPolicyConfig,
		userInputScanContext,
	)

	if weight != 0.25 {
		t.Fatalf(
			"expected scored weight 0.25 for content above byte limit, got %f",
			weight,
		)
	}

	modelOutputScanContext := types.ScanContext{
		ArtifactType:  types.ArtifactModelOutput,
		TenantID:      "Test-001",
		ApplicationID: "Application-001",
	}

	hardLimitContent := "123456"

	weight = DetectMaxBytes(
		hardLimitContent,
		testPolicyConfig,
		modelOutputScanContext,
	)

	if weight != 1 {
		t.Fatalf(
			"expected hard enforcement weight 1, got %f",
			weight,
		)
	}

	unicodeContent := "ééé"

	weight = DetectMaxBytes(
		unicodeContent,
		testPolicyConfig,
		modelOutputScanContext,
	)

	if weight != 1 {
		t.Fatalf(
			"expected unicode content to exceed 5 bytes and return 1, got %f",
			weight,
		)
	}
}

func TestDetectMaxTokens(t *testing.T) {
	testPolicyConfig := types.PolicyConfig{
		ResourceAbusePolicy: types.ResourceAbusePolicy{
			Enabled: true,
			ArtifactPolicies: map[types.ArtifactType]types.ArtifactResourcePolicy{
				types.ArtifactUserInput: {
					MaxEstimatedTokens: types.MaxEstimatedTokensPolicy{
						Limit:       2,
						Enforcement: types.EnforcementScored,
						Weight:      0.35,
					},
				},
				types.ArtifactModelOutput: {
					MaxEstimatedTokens: types.MaxEstimatedTokensPolicy{
						Limit:       2,
						Enforcement: types.EnforcementHard,
					},
				},
			},
		},
	}

	userInputScanContext := types.ScanContext{
		ArtifactType:  types.ArtifactUserInput,
		TenantID:      "Test-001",
		ApplicationID: "Application-001",
	}

	emptyContent := ""

	weight := DetectMaxTokens(
		emptyContent,
		testPolicyConfig,
		userInputScanContext,
	)

	if weight != 0 {
		t.Fatalf(
			"expected weight 0 for empty content, got %f",
			weight,
		)
	}

	contentBelowLimit := "1234"

	weight = DetectMaxTokens(
		contentBelowLimit,
		testPolicyConfig,
		userInputScanContext,
	)

	if weight != 0 {
		t.Fatalf(
			"expected weight 0 for content below token limit, got %f",
			weight,
		)
	}

	contentEqualToLimit := "12345678"

	weight = DetectMaxTokens(
		contentEqualToLimit,
		testPolicyConfig,
		userInputScanContext,
	)

	if weight != 0 {
		t.Fatalf(
			"expected weight 0 for content equal to token limit, got %f",
			weight,
		)
	}

	contentAboveLimit := "123456789"

	weight = DetectMaxTokens(
		contentAboveLimit,
		testPolicyConfig,
		userInputScanContext,
	)

	if weight != 0.35 {
		t.Fatalf(
			"expected scored weight 0.35 for content above token limit, got %f",
			weight,
		)
	}

	modelOutputScanContext := types.ScanContext{
		ArtifactType:  types.ArtifactModelOutput,
		TenantID:      "Test-001",
		ApplicationID: "Application-001",
	}

	weight = DetectMaxTokens(
		contentAboveLimit,
		testPolicyConfig,
		modelOutputScanContext,
	)

	if weight != 1 {
		t.Fatalf(
			"expected hard enforcement weight 1, got %f",
			weight,
		)
	}
}

func TestDetectRepeatedCharacters(t *testing.T) {
	testPolicyConfig := types.PolicyConfig{
		ResourceAbusePolicy: types.ResourceAbusePolicy{
			Enabled: true,
			ArtifactPolicies: map[types.ArtifactType]types.ArtifactResourcePolicy{
				types.ArtifactUserInput: {
					RepeatedCharacters: types.RepeatedCharactersPolicy{
						MaxConsecutiveRun:   4,
						MaxConsecutiveRatio: 0.50,
						MinimumCharacters:   10,
						Enforcement:         types.EnforcementScored,
						Weight:              0.20,
					},
				},
				types.ArtifactModelOutput: {
					RepeatedCharacters: types.RepeatedCharactersPolicy{
						MaxConsecutiveRun:   4,
						MaxConsecutiveRatio: 0.50,
						MinimumCharacters:   10,
						Enforcement:         types.EnforcementHard,
					},
				},
			},
		},
	}

	userInputScanContext := types.ScanContext{
		ArtifactType:  types.ArtifactUserInput,
		TenantID:      "Test-001",
		ApplicationID: "Application-001",
	}

	emptyContent := ""

	weight := DetectRepeatedCharacters(
		emptyContent,
		testPolicyConfig,
		userInputScanContext,
	)

	if weight != 0 {
		t.Fatalf(
			"expected weight 0 for empty content, got %f",
			weight,
		)
	}

	contentBelowMinimumCharacters := "AAAAAAAAA"

	weight = DetectRepeatedCharacters(
		contentBelowMinimumCharacters,
		testPolicyConfig,
		userInputScanContext,
	)

	if weight != 0 {
		t.Fatalf(
			"expected weight 0 for content below minimum characters, got %f",
			weight,
		)
	}

	contentWithinLimits := "AAAABBBBCC"

	weight = DetectRepeatedCharacters(
		contentWithinLimits,
		testPolicyConfig,
		userInputScanContext,
	)

	if weight != 0 {
		t.Fatalf(
			"expected weight 0 for content within limits, got %f",
			weight,
		)
	}

	contentExceedingRunLimit := "AAAAABBBCC"

	weight = DetectRepeatedCharacters(
		contentExceedingRunLimit,
		testPolicyConfig,
		userInputScanContext,
	)

	if weight != 0.20 {
		t.Fatalf(
			"expected scored weight 0.20 when run limit is exceeded, got %f",
			weight,
		)
	}

	testPolicyConfig.ResourceAbusePolicy.ArtifactPolicies[types.ArtifactUserInput] = types.ArtifactResourcePolicy{
		RepeatedCharacters: types.RepeatedCharactersPolicy{
			MaxConsecutiveRun:   6,
			MaxConsecutiveRatio: 0.40,
			MinimumCharacters:   10,
			Enforcement:         types.EnforcementScored,
			Weight:              0.25,
		},
	}

	contentExceedingRatioLimit := "AAAAABBBCC"

	weight = DetectRepeatedCharacters(
		contentExceedingRatioLimit,
		testPolicyConfig,
		userInputScanContext,
	)

	if weight != 0.25 {
		t.Fatalf(
			"expected scored weight 0.25 when ratio limit is exceeded, got %f",
			weight,
		)
	}

	modelOutputScanContext := types.ScanContext{
		ArtifactType:  types.ArtifactModelOutput,
		TenantID:      "Test-001",
		ApplicationID: "Application-001",
	}

	hardEnforcementContent := "AAAAABBBCC"

	weight = DetectRepeatedCharacters(
		hardEnforcementContent,
		testPolicyConfig,
		modelOutputScanContext,
	)

	if weight != 1 {
		t.Fatalf(
			"expected hard enforcement weight 1, got %f",
			weight,
		)
	}
}

func TestDetectRepeatedCharactersUnknownEnforcement(t *testing.T) {
	testPolicyConfig := types.PolicyConfig{
		ResourceAbusePolicy: types.ResourceAbusePolicy{
			Enabled: true,
			ArtifactPolicies: map[types.ArtifactType]types.ArtifactResourcePolicy{
				types.ArtifactUserInput: {
					RepeatedCharacters: types.RepeatedCharactersPolicy{
						MaxConsecutiveRun:   4,
						MaxConsecutiveRatio: 0.50,
						MinimumCharacters:   10,
						Enforcement:         types.EnforcementMode("unknown"),
						Weight:              0.20,
					},
				},
			},
		},
	}

	testScanContext := types.ScanContext{
		ArtifactType:  types.ArtifactUserInput,
		TenantID:      "Test-001",
		ApplicationID: "Application-001",
	}

	content := "AAAAABBBCC"

	weight := DetectRepeatedCharacters(
		content,
		testPolicyConfig,
		testScanContext,
	)

	if weight != 0 {
		t.Fatalf(
			"expected weight 0 for unknown enforcement mode, got %f",
			weight,
		)
	}
}
