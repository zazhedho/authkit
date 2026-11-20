package audit

import (
	"context"
	"strings"
	"time"

	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	dtoaudit "github.com/zazhedho/authkit/internal/dto/audit"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	serviceshared "github.com/zazhedho/authkit/internal/services/shared"
)

type Service struct {
	AuditRepo Repository
	// NewID makes record ids; nil uses a UUID v7.
	NewID func() string
}

func NewService(auditRepo Repository) *Service {
	return &Service{
		AuditRepo: auditRepo,
		NewID:     serviceshared.NewID,
	}
}

func (s *Service) Store(ctx context.Context, req domainaudit.AuditEvent) error {
	if strings.TrimSpace(req.Action) == "" {
		return domainaudit.ErrActionRequired
	}
	if strings.TrimSpace(req.Resource) == "" {
		return domainaudit.ErrResourceRequired
	}
	if strings.TrimSpace(req.Status) == "" {
		return domainaudit.ErrStatusRequired
	}

	occurredAt := req.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now()
	}

	before := serviceshared.RedactSensitivePayload(req.BeforeData)
	after := serviceshared.RedactSensitivePayload(req.AfterData)
	meta := serviceshared.RedactSensitivePayload(req.Metadata)

	data := domainaudit.Trail{
		ID:           s.newID(),
		OccurredAt:   occurredAt,
		ActorUserID:  serviceshared.NormalizeUUIDPointer(req.ActorUserID),
		ActorRole:    strings.TrimSpace(req.ActorRole),
		Action:       serviceshared.HumanizeKey(req.Action),
		Resource:     strings.TrimSpace(req.Resource),
		ResourceID:   strings.TrimSpace(req.ResourceID),
		Status:       serviceshared.HumanizeKey(req.Status),
		Message:      strings.TrimSpace(req.Message),
		ErrorMessage: strings.TrimSpace(req.ErrorMessage),
		RequestID:    strings.TrimSpace(req.RequestID),
		IPAddress:    strings.TrimSpace(req.IPAddress),
		UserAgent:    strings.TrimSpace(req.UserAgent),
		BeforeData:   serviceshared.JSONEncode(before),
		AfterData:    serviceshared.JSONEncode(after),
		Metadata:     serviceshared.JSONEncode(meta),
		CreatedAt:    time.Now(),
	}

	return s.AuditRepo.Store(ctx, data)
}

func (s *Service) GetAll(ctx context.Context, req dtoshared.ListRequest) ([]dtoaudit.AuditTrailResponse, int64, error) {
	items, total, err := s.AuditRepo.GetAll(ctx, req)
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

func (s *Service) newID() string {
	if s.NewID != nil {
		return s.NewID()
	}
	return serviceshared.NewID()
}
