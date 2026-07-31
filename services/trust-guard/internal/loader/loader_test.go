package loader

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoaderFunctions(t *testing.T) {

	policyConfigFilePath := "../../config/policy/policy.json"
	detectionRuleLibraryPath := "../../config/rules/rules.json"

	policyConfig, err := LoadPolicyConfig(policyConfigFilePath)

	if err != nil {
		t.Fatalf("Failed to load policy confgurations from path %s , ERROR - %v. **TEST FAILED**", policyConfigFilePath, err)
	} else {
		t.Logf("Policy Loaded from path %s successfully. **TEST PASSED**", policyConfigFilePath)
	}

	policyConfigActions := policyConfig.DefaultActionsConfig
	policyConfigSeverityMapping := policyConfig.SeverityConfig

	if len(policyConfigActions) > 0 {
		t.Logf("Successfully loaded policy action contents - %+v **TEST PASSED** ", policyConfigActions)
	} else {
		t.Fatalf("Failed to load policy action contents. **TEST FAILED**")

	}

	if len(policyConfigSeverityMapping) > 0 {
		t.Logf("Successfully loaded policy severity mapping contents - %+v **TEST PASSED** ", policyConfigSeverityMapping)
	} else {
		t.Fatalf("Failed to load policy severity mapping contents. **TEST FAILED**")

	}

	detectionRulesLibrary, err := LoadDetectionRules(detectionRuleLibraryPath)
	if err != nil {
		t.Fatalf("Failed to load detection rules from path %s , ERROR - %v. **TEST FAILED**", detectionRuleLibraryPath, err)
	} else {
		t.Logf("Detection Rules loaded from path %s successfully. **TEST PASSED**", detectionRuleLibraryPath)
	}

	if len(*detectionRulesLibrary) > 0 {

		rules := *detectionRulesLibrary
		rule := rules[0]
		t.Logf("Successfully loaded rules, EXAMPLE RULE => %+v **TEST PASSED**", rule)

	} else {
		t.Fatalf("Failed to load detection rules. **TEST FAILED**")

	}

}

func TestYamlConfigLoader(t *testing.T) {
	tempDir := t.TempDir()

	configPath := filepath.Join(tempDir, "config.yaml")

	configContent := `
env: dev
detection_rule_library: configs/rules/rules.json
policy_config: configs/policy/policy.json
http_server:
  address: localhost:8000
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("failed to create test config file: %v", err)
	}

	t.Setenv("CONFIG_PATH", configPath)

	configuration := MustLoad()

	if configuration.HTTPServer.Addr != "localhost:8000" {
		t.Fatalf("expected server address localhost:8000, got %s", configuration.HTTPServer.Addr)
	}

	if configuration.Env != "dev" {
		t.Fatalf("expected env dev, got %s", configuration.Env)
	}

	if configuration.DetectionRuleLibrary != "configs/rules/rules.json" {
		t.Fatalf("expected detection rule library path configs/rules/rules.json, got %s", configuration.DetectionRuleLibrary)
	}

	if configuration.PolicyConfig != "configs/policy/policy.json" {
		t.Fatalf("expected policy config path configs/policy/policy.json, got %s", configuration.PolicyConfig)
	}
}
