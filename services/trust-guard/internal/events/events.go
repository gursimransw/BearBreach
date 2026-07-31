package events

import (
	"time"

	"github.com/google/uuid"
	"github.com/gursimransw/BearBreach/services/trust-guard/internal/types"
)

func GenerateAITrustBoundaryEvent(producer types.Producer,
	context types.EventContext,
	boundary types.TrustBoundary,
	artifact types.Artifact,
	findings []types.EventFinding,
	decision types.Decision,
	processing types.Processing, requestID string) types.AITrustBoundaryEvent {

	event := types.AITrustBoundaryEvent{
		BasicEventInformation: types.BasicEventInformation{
			SchemaVersion: "1.0.0",
			EventID:       uuid.NewString(),
			EventType:     "ai_trust_boundary_event",
			Timestamp:     time.Now().UTC(),
			RequestID:     requestID,
		},
		Producer:   producer,
		Context:    context,
		Boundary:   boundary,
		Artifact:   artifact,
		Findings:   findings,
		Decision:   decision,
		Processing: processing,
	}

	return event

}
