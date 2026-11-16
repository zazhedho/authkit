package authutil

import (
	"context"
	"strings"

	"github.com/zazhedho/gokit/utils"
)

func GetImpersonationMetadata(ctx context.Context) map[string]any {
	authData := GetAuthData(ctx)
	if authData == nil {
		return nil
	}

	isImpersonated, ok := authData["is_impersonated"].(bool)
	if !ok || !isImpersonated {
		return nil
	}

	return map[string]any{
		"is_impersonated":      true,
		"original_user_id":     strings.TrimSpace(utils.InterfaceString(authData["original_user_id"])),
		"original_username":    strings.TrimSpace(utils.InterfaceString(authData["original_username"])),
		"original_role":        strings.TrimSpace(utils.InterfaceString(authData["original_role"])),
		"impersonated_user_id": strings.TrimSpace(utils.InterfaceString(authData["user_id"])),
		"impersonated_user":    strings.TrimSpace(utils.InterfaceString(authData["username"])),
		"impersonated_role":    strings.TrimSpace(utils.InterfaceString(authData["role"])),
	}
}
