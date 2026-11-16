package authutil

import (
	"context"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestGetAuthDataReadsRealGinContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(nil)
	want := map[string]any{"user_id": "user-1", "role": "admin"}
	ctx.Set(CtxKeyAuthData, want)

	got := GetAuthData(ctx)
	if got["user_id"] != "user-1" || got["role"] != "admin" {
		t.Fatalf("expected auth data from gin context, got %v", got)
	}
}

func TestGetAuthDataPrefersTypedContextValue(t *testing.T) {
	ctx := WithAuthData(context.Background(), map[string]any{"user_id": "typed"})
	if got := GetAuthData(ctx); got["user_id"] != "typed" {
		t.Fatalf("expected typed auth data, got %v", got)
	}
}

func TestGetAuthDataReturnsNilWhenMissing(t *testing.T) {
	if got := GetAuthData(context.Background()); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
	if got := GetAuthData(nil); got != nil { //nolint:staticcheck // nil context is handled deliberately
		t.Fatalf("expected nil for nil context, got %v", got)
	}
}

type stringKeyCtx struct {
	context.Context
	data map[string]any
}

func (c stringKeyCtx) Get(key string) (any, bool) {
	v, ok := c.data[key]
	return v, ok
}

func TestGetAuthDataReadsStringKeyGetter(t *testing.T) {
	ctx := stringKeyCtx{Context: context.Background(), data: map[string]any{CtxKeyAuthData: map[string]any{"user_id": "legacy"}}}
	if got := GetAuthData(ctx); got["user_id"] != "legacy" {
		t.Fatalf("expected auth data from string-keyed getter, got %v", got)
	}
}

type anyKeyCtx struct {
	context.Context
	data map[any]any
}

func (c anyKeyCtx) Get(key any) (any, bool) {
	v, ok := c.data[key]
	return v, ok
}

func TestGetAuthDataReadsAnyKeyGetterContext(t *testing.T) {
	ctx := anyKeyCtx{Context: context.Background(), data: map[any]any{CtxKeyAuthData: map[string]any{"user_id": "any-key"}}}
	if got := GetAuthData(ctx); got["user_id"] != "any-key" {
		t.Fatalf("expected auth data from any-keyed getter, got %v", got)
	}
}
