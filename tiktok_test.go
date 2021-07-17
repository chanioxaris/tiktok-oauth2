package tiktok_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/chanioxaris/tiktok-oauth2"
	"github.com/jarcoal/httpmock"
	"golang.org/x/oauth2"
)

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
			config:        &oauth2.Config{},
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
	httpmock.Activate()
	t.Cleanup(httpmock.Deactivate)

	httpmock.RegisterResponderWithQuery(
		http.MethodPost,
		endpointToken,
		accessTokenParameters,
		httpmock.NewStringResponder(http.StatusOK, responseAccessTokenSuccess),
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
	httpmock.Activate()
	t.Cleanup(httpmock.Deactivate)

	httpmock.RegisterResponderWithQuery(
		http.MethodPost,
		endpointToken,
		accessTokenParameters,
		httpmock.NewStringResponder(http.StatusOK, responseAccessTokenError),
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
	httpmock.Activate()
	t.Cleanup(httpmock.Deactivate)

	httpmock.RegisterResponderWithQuery(
		http.MethodPost,
		endpointToken,
		accessTokenParameters,
		httpmock.NewStringResponder(http.StatusOK, responseAccessTokenEmpty),
	)

	_, err := tiktok.ConfigExchange(context.Background(), testNewOauthConfig(t), "test-code")
	if err == nil {
		t.Fatal("expected error but got nil")
	}

	if !strings.Contains(err.Error(), "server response missing access_token") {
		t.Fatalf("expected error to contain 'server response missing access_token', but got '%v'", err)
	}
}
