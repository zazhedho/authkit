package serviceaudit

import (
	"encoding/json"
	"fmt"
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	"github.com/zazhedho/authkit/internal/dto"
	"github.com/zazhedho/gokit"
	"strings"
)

func toAuditResponses(items []domainaudit.AuditTrail) []dto.AuditTrailResponse {
	responses := make([]dto.AuditTrailResponse, 0, len(items))
	for _, item := range items {
		responses = append(responses, toAuditResponse(item))
	}
	return responses
}

func toAuditResponse(item domainaudit.AuditTrail) dto.AuditTrailResponse {
	actionLabel := gokit.TitleHumanized(item.Action)
	resourceLabel := gokit.TitleHumanized(item.Resource)
	statusLabel := gokit.TitleHumanized(item.Status)

	return dto.AuditTrailResponse{
		ID:            item.ID,
		OccurredAt:    item.OccurredAt,
		Actor:         dto.AuditActor{UserID: item.ActorUserID, Role: gokit.TitleHumanized(item.ActorRole)},
		Action:        item.Action,
		ActionLabel:   actionLabel,
		Resource:      item.Resource,
		ResourceLabel: resourceLabel,
		ResourceID:    item.ResourceID,
		Status:        item.Status,
		StatusLabel:   statusLabel,
		Summary:       buildAuditSummary(statusLabel, item.Message, resourceLabel),
		Message:       item.Message,
		ErrorMessage:  item.ErrorMessage,
		RequestID:     item.RequestID,
		IPAddress:     item.IPAddress,
		UserAgent:     item.UserAgent,
		BeforeData:    decodeAuditJSON(item.BeforeData),
		AfterData:     decodeAuditJSON(item.AfterData),
		Metadata:      decodeAuditJSON(item.Metadata),
		CreatedAt:     item.CreatedAt,
	}
}

func buildAuditSummary(statusLabel, message, resourceLabel string) string {
	message = strings.TrimSpace(message)
	if message != "" {
		return fmt.Sprintf("%s: %s", statusLabel, message)
	}

	resourceLabel = strings.TrimSpace(resourceLabel)
	if resourceLabel == "" {
		return statusLabel
	}
	return fmt.Sprintf("%s: %s", statusLabel, resourceLabel)
}

func decodeAuditJSON(value string) any {
	value = strings.TrimSpace(value)
	if value == "" || value == "null" {
		return nil
	}

	var decoded any
	if err := json.Unmarshal([]byte(value), &decoded); err != nil {
		return value
	}
	return decoded
}
