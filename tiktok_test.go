package tiktok_test

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/chanioxaris/tiktok-oauth2"
	"github.com/jarcoal/httpmock"
	"golang.org/x/oauth2"
)

func TestNewConfigInvalidArguments(t *testing.T) {
	tests := []struct {
		name          string
		clientID      string
		clientSecret  string
		redirectURL   string
		errorContains string
	}{
		{
			name:          "empty client id",
			clientID:      "",
			errorContains: "client id cannot be empty",
		},
		{
			name:          "empty client secret",
			clientID:      "test-client-id",
			clientSecret:  "",
			errorContains: "client secret cannot be empty",
		},
		{
			name:          "empty redirect url",
			clientID:      "test-client-id",
			clientSecret:  "test-client-secret",
			redirectURL:   "",
			errorContains: "redirect url cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tiktok.NewConfig(tt.clientID, tt.clientSecret, tt.redirectURL)
			if err == nil {
				t.Fatal("expected error but got nil")
			}

			if !strings.Contains(err.Error(), tt.errorContains) {
				t.Fatalf("expected error to contain '%s', but got '%v'", tt.errorContains, err)
			}
		})
	}
}

func TestNewConfigSuccess(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		redirectURL  string
		scopes       []string
	}{
		{
			name:         "all arguments provided",
			clientID:     "test-client-id",
			clientSecret: "test-client-secret",
			redirectURL:  "test-redirect-ul",
			scopes:       []string{"test-scope-1", "test-scope-2"},
		},
		{
			name:         "default scope",
			clientID:     "test-client-id",
			clientSecret: "test-client-secret",
			redirectURL:  "test-redirect-ul",
			scopes:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tiktok.NewConfig(tt.clientID, tt.clientSecret, tt.redirectURL, tt.scopes...)
			if err != nil {
				t.Fatalf("unexpected error %v", err)
			}

			if got.ClientID != tt.clientID {
				t.Fatalf("expected client id '%s', but got %s", tt.clientID, got.ClientID)
			}

			if got.ClientSecret != tt.clientSecret {
				t.Fatalf("expected client secret '%s', but got %s", tt.clientSecret, got.ClientSecret)
			}

			if got.RedirectURL != tt.redirectURL {
				t.Fatalf("expected redirect url '%s', but got %s", tt.redirectURL, got.RedirectURL)
			}

			if tt.scopes != nil {
				if len(got.Scopes) != len(tt.scopes) {
					t.Fatalf("expected scopes lenght '%d', but got %d", len(tt.scopes), len(got.Scopes))
				}

				if !reflect.DeepEqual(got.Scopes, tt.scopes) {
					t.Fatalf("expected scopes '%v', but got %v", tt.scopes, got.Scopes)
				}
			} else {
				if len(got.Scopes) != 1 {
					t.Fatalf("expected scopes lenght '1', but got %d", len(got.Scopes))
				}

				if got.Scopes[0] != "user.info.basic" {
					t.Fatalf("expected default scope 'user.info.basic', but got %s", got.Scopes[0])
				}
			}
		})
	}
}

func TestConfigExchangeInvalidArguments(t *testing.T) {
	tests := []struct {
		name          string
		config        *oauth2.Config
		code          string
		errorContains string
	}{
		{
			name:          "nil config",
			config:        nil,
			code:          "test-code",
			errorContains: "config cannot be nil",
		},
		{
			name:          "empty code",
			config:        testNewOauthConfig(t),
			code:          "",
			errorContains: "code cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tiktok.ConfigExchange(context.Background(), tt.config, tt.code)
			if err == nil {
				t.Fatal("expected error but got nil")
			}

			if !strings.Contains(err.Error(), tt.errorContains) {
				t.Fatalf("expected error to contain '%s', but got '%v'", tt.errorContains, err)
			}
		})
	}
}

func TestConfigExchangeSuccess(t *testing.T) {
	cfg := testNewOauthConfig(t)

	httpmock.Activate()
	t.Cleanup(httpmock.Deactivate)

	httpmock.RegisterResponderWithQuery(
		http.MethodPost,
		cfg.Endpoint.TokenURL,
		accessTokenParameters,
		httpmock.NewStringResponder(http.StatusOK, responseSuccessToken),
	)

	token, err := tiktok.ConfigExchange(context.Background(), testNewOauthConfig(t), "test-code")
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	if token.AccessToken != "test-access-token" {
		t.Fatalf("expected access token 'test-access-token', but got %s", token.AccessToken)
	}

	if token.TokenType != "Bearer" {
		t.Fatalf("expected token type 'Bearer', but got %s", token.TokenType)
	}

	if token.RefreshToken != "test-refresh-token" {
		t.Fatalf("expected refresh token 'test-refresh-token', but got %s", token.RefreshToken)
	}

	if extraOpenID := token.Extra("open_id"); extraOpenID != "test-open-id" {
		t.Fatalf("expected extra field open_id 'test-open-id', but got %s", extraOpenID)
	}
}

func TestConfigExchangeError(t *testing.T) {
	cfg := testNewOauthConfig(t)

	httpmock.Activate()
	t.Cleanup(httpmock.Deactivate)

	httpmock.RegisterResponderWithQuery(
		http.MethodPost,
		cfg.Endpoint.TokenURL,
		accessTokenParameters,
		httpmock.NewStringResponder(http.StatusOK, responseError),
	)

	_, err := tiktok.ConfigExchange(context.Background(), testNewOauthConfig(t), "test-code")
	if err == nil {
		t.Fatal("expected error but got nil")
	}

	if !strings.Contains(err.Error(), "Request error [1000]") {
		t.Fatalf("expected error to contain 'Request error [1000]', but got '%v'", err)
	}
}

func TestConfigExchangeEmptyAccessToken(t *testing.T) {
	cfg := testNewOauthConfig(t)

	httpmock.Activate()
	t.Cleanup(httpmock.Deactivate)

	httpmock.RegisterResponderWithQuery(
		http.MethodPost,
		cfg.Endpoint.TokenURL,
		accessTokenParameters,
		httpmock.NewStringResponder(http.StatusOK, responseEmptyAccessToken),
	)

	_, err := tiktok.ConfigExchange(context.Background(), testNewOauthConfig(t), "test-code")
	if err == nil {
		t.Fatal("expected error but got nil")
	}

	if !strings.Contains(err.Error(), "server response missing access_token") {
		t.Fatalf("expected error to contain 'server response missing access_token', but got '%v'", err)
	}
}

func TestRefreshTokenInvalidArguments(t *testing.T) {
	tests := []struct {
		name          string
		clientKey     string
		refreshToken  string
		errorContains string
	}{
		{
			name:          "empty client key",
			clientKey:     "",
			errorContains: "client key cannot be empty",
		},
		{
			name:          "empty refresh token",
			clientKey:     "test-client-key",
			refreshToken:  "",
			errorContains: "refresh token cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tiktok.RefreshToken(context.Background(), tt.clientKey, tt.refreshToken)
			if err == nil {
				t.Fatal("expected error but got nil")
			}

			if !strings.Contains(err.Error(), tt.errorContains) {
				t.Fatalf("expected error to contain '%s', but got '%v'", tt.errorContains, err)
			}
		})
	}
}

func TestRefreshTokenSuccess(t *testing.T) {
	httpmock.Activate()
	t.Cleanup(httpmock.Deactivate)

	httpmock.RegisterResponderWithQuery(
		http.MethodPost,
		"https://open-api.tiktok.com/oauth/refresh_token/",
		refreshTokenParameters,
		httpmock.NewStringResponder(http.StatusOK, responseSuccessToken),
	)

	token, err := tiktok.RefreshToken(context.Background(), "test-client-key", "test-refresh-token")
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	if token.AccessToken != "test-access-token" {
		t.Fatalf("expected access token 'test-access-token', but got %s", token.AccessToken)
	}

	if token.TokenType != "Bearer" {
		t.Fatalf("expected token type 'Bearer', but got %s", token.TokenType)
	}

	if token.RefreshToken != "test-refresh-token" {
		t.Fatalf("expected refresh token 'test-refresh-token', but got %s", token.RefreshToken)
	}

	if extraOpenID := token.Extra("open_id"); extraOpenID != "test-open-id" {
		t.Fatalf("expected extra field open_id 'test-open-id', but got %s", extraOpenID)
	}
}

func TestRefreshTokenError(t *testing.T) {
	httpmock.Activate()
	t.Cleanup(httpmock.Deactivate)

	httpmock.RegisterResponderWithQuery(
		http.MethodPost,
		"https://open-api.tiktok.com/oauth/refresh_token/",
		refreshTokenParameters,
		httpmock.NewStringResponder(http.StatusOK, responseError),
	)

	_, err := tiktok.RefreshToken(context.Background(), "test-client-key", "test-refresh-token")
	if err == nil {
		t.Fatal("expected error but got nil")
	}

	if !strings.Contains(err.Error(), "Request error [1000]") {
		t.Fatalf("expected error to contain 'Request error [1000]', but got '%v'", err)
	}
}

func TestRefreshTokenEmptyAccessToken(t *testing.T) {
	httpmock.Activate()
	t.Cleanup(httpmock.Deactivate)

	httpmock.RegisterResponderWithQuery(
		http.MethodPost,
		"https://open-api.tiktok.com/oauth/refresh_token/",
		refreshTokenParameters,
		httpmock.NewStringResponder(http.StatusOK, responseEmptyAccessToken),
	)

	_, err := tiktok.RefreshToken(context.Background(), "test-client-key", "test-refresh-token")
	if err == nil {
		t.Fatal("expected error but got nil")
	}

	if !strings.Contains(err.Error(), "server response missing access_token") {
		t.Fatalf("expected error to contain 'server response missing access_token', but got '%v'", err)
	}
}

func TestRevokeAccessInvalidArguments(t *testing.T) {
	tests := []struct {
		name          string
		token         *oauth2.Token
		errorContains string
	}{
		{
			name:          "nil token",
			token:         nil,
			errorContains: "token cannot be nil",
		},
		{
			name:          "token without open_id",
			token:         testNewOauthToken(t),
			errorContains: "token missing open id",
		},
		{
			name:          "token with invalid open_id type",
			token:         testNewOauthToken(t).WithExtra(map[string]interface{}{"open_id": 1}),
			errorContains: "expected token open id to be a string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tiktok.RevokeAccess(context.Background(), tt.token)
			if err == nil {
				t.Fatal("expected error but got nil")
			}

			if !strings.Contains(err.Error(), tt.errorContains) {
				t.Fatalf("expected error to contain '%s', but got '%v'", tt.errorContains, err)
			}
		})
	}
}

func TestRevokeAccessSuccess(t *testing.T) {
	token := testNewOauthToken(t).WithExtra(map[string]interface{}{"open_id": "test-open-id"})

	httpmock.Activate()
	t.Cleanup(httpmock.Deactivate)

	httpmock.RegisterResponderWithQuery(
		http.MethodPost,
		"https://open-api.tiktok.com/oauth/revoke/",
		revokeParameters,
		httpmock.NewStringResponder(http.StatusOK, ""),
	)

	err := tiktok.RevokeAccess(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestRevokeAccessError(t *testing.T) {
	token := testNewOauthToken(t).WithExtra(map[string]interface{}{"open_id": "test-open-id"})

	httpmock.Activate()
	t.Cleanup(httpmock.Deactivate)

	httpmock.RegisterResponderWithQuery(
		http.MethodPost,
		"https://open-api.tiktok.com/oauth/revoke/",
		revokeParameters,
		httpmock.NewStringResponder(http.StatusOK, responseError),
	)

	err := tiktok.RevokeAccess(context.Background(), token)
	if err == nil {
		t.Fatal("expected error but got nil")
	}

	if !strings.Contains(err.Error(), "Request error [1000]") {
		t.Fatalf("expected error to contain 'Request error [1000]', but got '%v'", err)
	}
}

func TestRetrieveUserInfoInvalidArguments(t *testing.T) {
	tests := []struct {
		name          string
		token         *oauth2.Token
		errorContains string
	}{
		{
			name:          "nil token",
			token:         nil,
			errorContains: "token cannot be nil",
		},
		{
			name:          "token without open_id",
			token:         testNewOauthToken(t),
			errorContains: "token missing open id",
		},
		{
			name:          "token with invalid open_id type",
			token:         testNewOauthToken(t).WithExtra(map[string]interface{}{"open_id": 1}),
			errorContains: "expected token open id to be a string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tiktok.RetrieveUserInfo(context.Background(), tt.token)
			if err == nil {
				t.Fatal("expected error but got nil")
			}

			if !strings.Contains(err.Error(), tt.errorContains) {
				t.Fatalf("expected error to contain '%s', but got '%v'", tt.errorContains, err)
			}
		})
	}
}

func TestRetrieveUserInfoSuccess(t *testing.T) {
	token := testNewOauthToken(t).WithExtra(map[string]interface{}{"open_id": "test-open-id"})

	httpmock.Activate()
	t.Cleanup(httpmock.Deactivate)

	httpmock.RegisterResponderWithQuery(
		http.MethodGet,
		"https://open-api.tiktok.com/oauth/userinfo/",
		userInfoParameters,
		httpmock.NewStringResponder(http.StatusOK, responseSuccessUserInfo),
	)

	user, err := tiktok.RetrieveUserInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	if user.OpenID != "test-open-id" {
		t.Fatalf("expected open id 'test-open-id', but got %s", user.OpenID)
	}

	if user.UnionID != "test-union-id" {
		t.Fatalf("expected union id 'test-union-id', but got %s", user.UnionID)
	}

	if user.Avatar != "test-avatar" {
		t.Fatalf("expected avatar 'test-avatar', but got %s", user.Avatar)
	}

	if user.AvatarLarger != "test-avatar-larger" {
		t.Fatalf("expected avatar large 'test-avatar-larger', but got %s", user.AvatarLarger)
	}

	if user.DisplayName != "test-display-name" {
		t.Fatalf("expected display name 'test-display-name', but got %s", user.DisplayName)
	}
}

func TestRetrieveUserInfoError(t *testing.T) {
	token := testNewOauthToken(t).WithExtra(map[string]interface{}{"open_id": "test-open-id"})

	httpmock.Activate()
	t.Cleanup(httpmock.Deactivate)

	httpmock.RegisterResponderWithQuery(
		http.MethodGet,
		"https://open-api.tiktok.com/oauth/userinfo/",
		userInfoParameters,
		httpmock.NewStringResponder(http.StatusOK, responseError),
	)

	_, err := tiktok.RetrieveUserInfo(context.Background(), token)
	if err == nil {
		t.Fatal("expected error but got nil")
	}

	if !strings.Contains(err.Error(), "Request error [1000]") {
		t.Fatalf("expected error to contain 'Request error [1000]', but got '%v'", err)
	}
}
