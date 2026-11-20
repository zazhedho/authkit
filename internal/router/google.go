package router

import (
	"context"
	"errors"
	"strconv"

	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	"github.com/zazhedho/authkit/internal/infrastructure/googleid"
	serviceuser "github.com/zazhedho/authkit/internal/services/user"
)

// verifyGoogle adapts the offline Google verifier to the user service's port.
func verifyGoogle(ctx context.Context, idToken string, clientIDs []string) (serviceuser.GoogleIdentity, error) {
	id, err := googleid.Verify(ctx, idToken, clientIDs)
	switch {
	case errors.Is(err, googleid.ErrNotConfigured):
		return serviceuser.GoogleIdentity{}, domainuser.ErrGoogleNotConfigured
	case errors.Is(err, googleid.ErrInvalidToken):
		return serviceuser.GoogleIdentity{}, domainuser.ErrGoogleTokenInvalid
	case errors.Is(err, googleid.ErrNoEmail):
		return serviceuser.GoogleIdentity{}, domainuser.ErrGoogleEmailMissing
	case err != nil:
		return serviceuser.GoogleIdentity{}, err
	}
	return serviceuser.GoogleIdentity{
		Audience: id.Audience, Email: id.Email, EmailVerified: strconv.FormatBool(id.EmailVerified),
		Name: id.Name, Picture: id.Picture, Subject: id.Subject,
	}, nil
}
