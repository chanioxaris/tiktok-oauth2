package tiktok_test

import (
	"strings"
	"testing"

	"github.com/chanioxaris/tiktok-oauth2"
	"golang.org/x/oauth2"
)

func TestOpenIDFromTokenSuccess(t *testing.T) {
	token := testNewOauthToken(t).WithExtra(map[string]interface{}{"open_id": "test-open-id"})

	openID, err := tiktok.OpenIDFromToken(token)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	if openID != "test-open-id" {
		t.Fatalf("expected open_id 'test-open-id', but got '%s'", openID)
	}
}

func TestOpenIDFromTokenError(t *testing.T) {
	tests := []struct {
		name          string
		token         *oauth2.Token
		errorContains string
	}{
		{
			name:          "nil token",
			token:         nil,
			errorContains: "OpenIDFromToken: token cannot be nil",
		},
		{
			name:          "nil token",
			token:         testNewOauthToken(t),
			errorContains: "OpenIDFromToken: token missing open id",
		},
		{
			name:          "nil token",
			token:         testNewOauthToken(t).WithExtra(map[string]interface{}{"open_id": 1}),
			errorContains: "OpenIDFromToken: expected token open id to be a string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tiktok.OpenIDFromToken(tt.token)
			if err == nil {
				t.Fatal("expected error but got nil")
			}

			if !strings.Contains(err.Error(), tt.errorContains) {
				t.Fatalf("expected error to contain '%s', but got '%v'", tt.errorContains, err)
			}
		})
	}
}

func TestScopeFromTokenSuccess(t *testing.T) {
	token := testNewOauthToken(t).WithExtra(map[string]interface{}{"scope": "test-scope-1,test-scope-2"})

	scope, err := tiktok.ScopeFromToken(token)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	if scope != "test-scope-1,test-scope-2" {
		t.Fatalf("expected scope 'test-scope-1,test-scope-2', but got '%s'", scope)
	}
}

func TestScopeFromTokenError(t *testing.T) {
	tests := []struct {
		name          string
		token         *oauth2.Token
		errorContains string
	}{
		{
			name:          "nil token",
			token:         nil,
			errorContains: "ScopeFromToken: token cannot be nil",
		},
		{
			name:          "nil token",
			token:         testNewOauthToken(t),
			errorContains: "ScopeFromToken: token missing scope",
		},
		{
			name:          "nil token",
			token:         testNewOauthToken(t).WithExtra(map[string]interface{}{"scope": 1}),
			errorContains: "ScopeFromToken: expected token scope to be a string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tiktok.ScopeFromToken(tt.token)
			if err == nil {
				t.Fatal("expected error but got nil")
			}

			if !strings.Contains(err.Error(), tt.errorContains) {
				t.Fatalf("expected error to contain '%s', but got '%v'", tt.errorContains, err)
			}
		})
	}
}

func TestRefreshExpiresInFromTokenSuccess(t *testing.T) {
	token := testNewOauthToken(t).WithExtra(map[string]interface{}{"refresh_expires_in": int64(10000)})

	refreshExpiresIn, err := tiktok.RefreshExpiresInFromToken(token)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	if refreshExpiresIn != 10000 {
		t.Fatalf("expected refresh_expires_in '1000', but got '%d'", refreshExpiresIn)
	}
}

func TestRefreshExpiresInFromTokenError(t *testing.T) {
	tests := []struct {
		name          string
		token         *oauth2.Token
		errorContains string
	}{
		{
			name:          "nil token",
			token:         nil,
			errorContains: "RefreshExpiresInFromToken: token cannot be nil",
		},
		{
			name:          "nil token",
			token:         testNewOauthToken(t),
			errorContains: "RefreshExpiresInFromToken: token missing refresh_expires_in",
		},
		{
			name:          "nil token",
			token:         testNewOauthToken(t).WithExtra(map[string]interface{}{"refresh_expires_in": "1000"}),
			errorContains: "RefreshExpiresInFromToken: expected token refresh_expires_in to be a int64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tiktok.RefreshExpiresInFromToken(tt.token)
			if err == nil {
				t.Fatal("expected error but got nil")
			}

			if !strings.Contains(err.Error(), tt.errorContains) {
				t.Fatalf("expected error to contain '%s', but got '%v'", tt.errorContains, err)
			}
		})
	}
}
