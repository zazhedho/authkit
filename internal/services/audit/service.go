package audit

import (
	"context"
	"errors"
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	dtoaudit "github.com/zazhedho/authkit/internal/dto/audit"
	"github.com/zazhedho/gokit"
	"strings"
	"time"
)

type Service struct {
	AuditRepo Repository
}

func NewService(auditRepo Repository) *Service {
	return &Service{
		AuditRepo: auditRepo,
	}
}

func (s *Service) Store(ctx context.Context, req domainaudit.AuditEvent) error {
	if strings.TrimSpace(req.Action) == "" {
		return errors.New("action is required")
	}
	if strings.TrimSpace(req.Resource) == "" {
		return errors.New("resource is required")
	}
	if strings.TrimSpace(req.Status) == "" {
		return errors.New("status is required")
	}

	occurredAt := req.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now()
	}

	before := gokit.RedactSensitivePayload(req.BeforeData)
	after := gokit.RedactSensitivePayload(req.AfterData)
	meta := gokit.RedactSensitivePayload(req.Metadata)

	data := domainaudit.AuditTrail{
		ID:           gokit.CreateUUID(),
		OccurredAt:   occurredAt,
		ActorUserID:  gokit.NormalizeUUIDPointer(req.ActorUserID),
		ActorRole:    strings.TrimSpace(req.ActorRole),
		Action:       gokit.HumanizeKey(req.Action),
		Resource:     strings.TrimSpace(req.Resource),
		ResourceID:   strings.TrimSpace(req.ResourceID),
		Status:       gokit.HumanizeKey(req.Status),
		Message:      strings.TrimSpace(req.Message),
		ErrorMessage: strings.TrimSpace(req.ErrorMessage),
		RequestID:    strings.TrimSpace(req.RequestID),
		IPAddress:    strings.TrimSpace(req.IPAddress),
		UserAgent:    strings.TrimSpace(req.UserAgent),
		BeforeData:   gokit.JsonEncode(before),
		AfterData:    gokit.JsonEncode(after),
		Metadata:     gokit.JsonEncode(meta),
		CreatedAt:    time.Now(),
	}

	return s.AuditRepo.Store(ctx, data)
}

func (s *Service) GetAll(ctx context.Context, params gokit.BaseParams) ([]dtoaudit.AuditTrailResponse, int64, error) {
	items, total, err := s.AuditRepo.GetAll(ctx, params)
	if err != nil {
		return nil, 0, err
	}

	return toAuditResponses(items), total, nil
}

func (s *Service) GetByID(ctx context.Context, id string) (dtoaudit.AuditTrailResponse, error) {
	item, err := s.AuditRepo.GetByID(ctx, id)
	if err != nil {
		return dtoaudit.AuditTrailResponse{}, err
	}

	return toAuditResponse(item), nil
}
