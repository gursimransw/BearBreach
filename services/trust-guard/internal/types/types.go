package types

import (
	"fmt"
	"net/http"
	"time"
)

type Content struct {
	Content string `json:"content" validate:"required"`
}

//This is a struct for the input prompt that we recieve from our API endpoint

// This is the struct for the detection rules for analyzing prompts, here we are not creating it like a config
// Rather we are creating a struct for the rule itself as now we are gonna use the list of rules directly into our code.
type DetectionRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	FindingType string   `json:"finding_type"`
	AppliesTo   []string `json:"applies_to"`
	Pattern     string   `json:"pattern"`
	Weight      float64  `json:"weight"`
	Severity    string   `json:"severity"`
	Reason      string   `json:"reason"`
}

type DetectionRuleList struct {
	RuleList []DetectionRule
}

func (ruleList *DetectionRuleList) AppendDetectionRuleSlice(rule DetectionRule) []DetectionRule {

	ruleList.RuleList = append(ruleList.RuleList, rule)

	return ruleList.RuleList

}

// This is the struct for severity configurations mappings as described inside /config/policy/PolicyConfig.json file.
type SeverityConfig struct {
	Severity string  `json:"severity"`
	MinScore float64 `json:"min_score"`
	MaxScore float64 `json:"max_score"`
}

// PolicyConfig struct will allow us to reference the policy itself anywhere in the code and we can use both severity config and
// Default actions config wherever we need.
type PolicyConfig struct {
	SeverityConfig         []SeverityConfig       `json:"severity_thresholds"`
	DefaultActionsConfig   map[string]string      `json:"default_actions"`
	ResourceAbusePolicy    ResourceAbusePolicy    `json:"resource_abuse"`
	SemanticDetectorPolicy SemanticDetectorPolicy `json:"semantic_detection"`
}

type ArtifactType string

const (
	ArtifactUserInput   ArtifactType = "user_input"
	ArtifactModelOutput ArtifactType = "model_output"
)

type ScanContext struct {
	ArtifactType  ArtifactType
	TenantID      string
	ApplicationID string
}

type EnforcementMode string

const (
	EnforcementHard   EnforcementMode = "hard"
	EnforcementScored EnforcementMode = "scored"
)

type MaxBytesPolicy struct {
	Limit       int             `json:"limit"`
	Enforcement EnforcementMode `json:"enforcement"`
	Weight      float64         `json:"weight,omitempty"`
}

type MaxEstimatedTokensPolicy struct {
	Limit       int             `json:"limit"`
	Enforcement EnforcementMode `json:"enforcement"`
	Weight      float64         `json:"weight,omitempty"`
}

type RepeatedCharactersPolicy struct {
	MaxConsecutiveRun   int             `json:"max_consecutive_run"`
	MaxConsecutiveRatio float64         `json:"max_consecutive_ratio"`
	MinimumCharacters   int             `json:"minimum_characters"`
	Enforcement         EnforcementMode `json:"enforcement"`
	Weight              float64         `json:"weight,omitempty"`
}

type ArtifactResourcePolicy struct {
	MaxBytes           MaxBytesPolicy           `json:"max_bytes"`
	MaxEstimatedTokens MaxEstimatedTokensPolicy `json:"max_estimated_tokens"`
	RepeatedCharacters RepeatedCharactersPolicy `json:"repeated_characters"`
}

type ResourceAbusePolicy struct {
	Enabled          bool                                    `json:"enabled"`
	ArtifactPolicies map[ArtifactType]ArtifactResourcePolicy `json:"artifact_policies"`
}

type BasicEventInformation struct {
	SchemaVersion string    `json:"schema_version"`
	EventID       string    `json:"event_id"`
	EventType     string    `json:"event_type"`
	Timestamp     time.Time `json:"timestamp"`
	RequestID     string    `json:"request_id"`
}

type Producer struct {
	Service        string `json:"service"`
	ServiceVersion string `json:"service_version"`
}

type EventContext struct {
	TenantID      string `json:"tenant_id"`
	ApplicationID string `json:"application_id"`
}

type TrustBoundary struct {
	Name                 string `json:"name"`
	SourceComponent      string `json:"source_component"`
	DestinationComponent string `json:"destination_component"`
	Stage                string `json:"stage"`
}

type Artifact struct {
	ArtifactType        ArtifactType `json:"artifact_type"`
	Origin              string       `json:"origin,omitempty"`
	MessageRole         string       `json:"message_role,omitempty"`
	ContentType         string       `json:"content_type"`
	ContentEncoding     string       `json:"content_encoding"`
	ByteCount           int          `json:"byte_count"`
	CharacterCount      int          `json:"character_count"`
	EstimatedTokenCount int          `json:"estimated_token_count"`
}

type ComponentScores map[string]float64

type Decision struct {
	HasFindings     bool            `json:"has_findings"`
	ComponentScores ComponentScores `json:"component_scores"`
	FinalRiskScore  float64         `json:"final_risk_score"`
	Severity        string          `json:"severity"`
	Action          string          `json:"action"`
	Basis           []string        `json:"basis"`
}

type Processing struct {
	Status     string  `json:"status"`
	DurationMS float64 `json:"duration_ms"`
}

type Detector struct {
	Service    string `json:"service"`
	DetectorID string `json:"detector_id"`
	Version    string `json:"version,omitempty"`
}

type Evidence struct {
	EvidenceType    string  `json:"evidence_type"`
	StartOffset     int     `json:"start_offset,omitempty"`
	EndOffset       int     `json:"end_offset,omitempty"`
	RedactedValue   string  `json:"redacted_value,omitempty"`
	ObservedValue   float64 `json:"observed_value,omitempty"`
	ConfiguredLimit float64 `json:"configured_limit,omitempty"`
	Unit            string  `json:"unit,omitempty"`
}

type EvidenceSlice struct {
	EvidenceSlice []Evidence
}

func (evidenceSlice *EvidenceSlice) AppendEvidenceSlice(evidence Evidence) []Evidence {

	evidenceSlice.EvidenceSlice = append(evidenceSlice.EvidenceSlice, evidence)

	return evidenceSlice.EvidenceSlice

}

type EventFinding struct {
	FindingID        string     `json:"finding_id"`
	FindingType      string     `json:"finding_type"`
	Category         string     `json:"category"`
	Title            string     `json:"title"`
	RiskContribution float64    `json:"risk_contribution"`
	RuleID           string     `json:"rule_id,omitempty"`
	Detector         Detector   `json:"detector"`
	Evidence         []Evidence `json:"evidence,omitempty"`
}

type EventFindingSlice struct {
	EventFindingSlice []EventFinding
}

func (eventFindingsSlice *EventFindingSlice) AppendEventFindingSlice(eventFinding EventFinding) []EventFinding {

	eventFindingsSlice.EventFindingSlice = append(eventFindingsSlice.EventFindingSlice, eventFinding)

	return eventFindingsSlice.EventFindingSlice

}

type AITrustBoundaryEvent struct {
	BasicEventInformation

	Producer   Producer       `json:"producer"`
	Context    EventContext   `json:"context"`
	Boundary   TrustBoundary  `json:"boundary"`
	Artifact   Artifact       `json:"artifact"`
	Findings   []EventFinding `json:"findings"`
	Decision   Decision       `json:"decision"`
	Processing Processing     `json:"processing"`
}

type AnalysisResult struct {
	HasFindings        bool
	Findings           []EventFinding
	ComponentScores    ComponentScores
	FinalRiskScore     float64
	ConstraintViolated bool
	Severity           string
	Action             string
	DecisionBasis      []string
	ByteCount          int
	CharacterCount     int
	EstimatedTokens    int
}
type DetectionComponentResult struct {
	ComponentName      string
	Score              float64
	Findings           []EventFinding
	ConstraintViolated bool
}

type SemanticDetectorPolicy struct {
	Enabled bool
	Mode    string
	Weight  float64
}

type SemanticDetectorRequest struct {
	RequestID     string       `json:"request_id"`
	TenantID      string       `json:"tenant_id"`
	ApplicationID string       `json:"application_id"`
	ArtifactType  ArtifactType `json:"artifact_type"`
	Text          string       `json:"text"`
}

type SemanticSimilarityResult struct {
	Detected            bool               `json:"detected"`
	PredictedCategory   string             `json:"predicted_category"`
	CategoryCandidate   string             `json:"category_candidate"`
	MaliciousSimilarity float64            `json:"malicious_similarity"`
	BenignSimilarity    float64            `json:"benign_similarity"`
	SemanticMargin      float64            `json:"semantic_margin"`
	ScoringStrategy     string             `json:"scoring_strategy"`
	ProcessingTimeMS    float64            `json:"processing_time_ms"`
	CategoryScores      map[string]float64 `json:"category_scores"`
	MatchedReferenceIDs []string           `json:"matched_reference_ids"`
}

type SemanticDetectorServiceResponse struct {
	RequestID       string                   `json:"request_id"`
	TenantID        string                   `json:"tenant_id"`
	ApplicationID   string                   `json:"application_id"`
	ArtifactType    ArtifactType             `json:"artifact_type"`
	DetectorVersion string                   `json:"detector_version"`
	Model           string                   `json:"model"`
	Result          SemanticSimilarityResult `json:"result"`
}

type SemanticDetectorClient struct {
	ServiceURL string
	HTTPClient http.Client
}

type SemanticClientError struct {
	Kind       string
	StatusCode int
	Err        error
}

func (e SemanticClientError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("semantic detector %s (HTTP %d): %v", e.Kind, e.StatusCode, e.Err)
	}
	return fmt.Sprintf("semantic detector %s: %v", e.Kind, e.Err)
}

func (e SemanticClientError) Unwrap() error { return e.Err }
