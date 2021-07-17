// Package tiktok provides support for making OAuth2 authorized and authenticated
// HTTP requests on TikTok platform.
package tiktok

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

var (
	httpClient = &http.Client{Timeout: time.Second * 10}
)

// NewConfig returns a new TikTok oauth2 config based on provided arguments.
func NewConfig(clientID, clientSecret, redirectURL string, scopes ...string) (*oauth2.Config, error) {
	if clientID == "" {
		return nil, fmt.Errorf("tiktok-oauth2: client id cannot be empty")
	}

	if clientSecret == "" {
		return nil, fmt.Errorf("tiktok-oauth2: client secret cannot be empty")
	}

	if redirectURL == "" {
		return nil, fmt.Errorf("tiktok-oauth2: redirect url cannot be empty")
	}

	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   endpointAuth,
			TokenURL:  endpointToken,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"user.info.basic"}
	}

	return cfg, nil
}

// ConfigExchange converts an oauth2 config and authorization code into an oauth2 token.
func ConfigExchange(ctx context.Context, config *oauth2.Config, code string) (*oauth2.Token, error) {
	if config == nil {
		return nil, fmt.Errorf("tiktok-oauth2: config cannot be nil")
	}

	if code == "" {
		return nil, fmt.Errorf("tiktok-oauth2: code cannot be empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointToken, nil)
	if err != nil {
		return nil, fmt.Errorf("tiktok-oauth2: %w", err)
	}

	q := req.URL.Query()
	q.Add("client_key", config.ClientID)
	q.Add("client_secret", config.ClientSecret)
	q.Add("code", code)
	q.Add("grant_type", "authorization_code")
	req.URL.RawQuery = q.Encode()

	response, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tiktok-oauth2: %w", err)
	}

	defer response.Body.Close()

	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("tiktok-oauth2: %w", err)
	}

	var body configExchangeResponse
	if err = json.Unmarshal(bodyBytes, &body); err != nil {
		return nil, fmt.Errorf("tiktok-oauth2: %w", err)
	}

	if body == (configExchangeResponse{}) {
		return nil, handleErrorResponse(bodyBytes)
	}

	token := &oauth2.Token{
		AccessToken:  body.Data.AccessToken,
		TokenType:    "Bearer",
		RefreshToken: body.Data.RefreshToken,
		Expiry:       time.Now().Add(time.Second * time.Duration(body.Data.ExpiresIn)),
	}

	if token.AccessToken == "" {
		return nil, fmt.Errorf("tiktok-oauth2: server response missing access_token")
	}

	tokenExtra := map[string]interface{}{
		"open_id": body.Data.OpenID,
	}

	return token.WithExtra(tokenExtra), nil
}

// RetrieveUserInfo returns some basic information of a given TikTok user based on the open id.
func RetrieveUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	if token == nil {
		return nil, fmt.Errorf("tiktok-oauth2: token cannot be nil")
	}

	extraOpenID := token.Extra("open_id")
	if extraOpenID == nil {
		return nil, fmt.Errorf("tiktok-oauth2: token missing open id")
	}

	openID, ok := extraOpenID.(string)
	if !ok {
		return nil, fmt.Errorf("tiktok-oauth2: expected token open id to be a string")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointUserInfo, nil)
	if err != nil {
		return nil, fmt.Errorf("tiktok-oauth2: %w", err)
	}

	q := req.URL.Query()
	q.Add("access_token", token.AccessToken)
	q.Add("open_id", openID)
	req.URL.RawQuery = q.Encode()

	response, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tiktok-oauth2: %w", err)
	}

	defer response.Body.Close()

	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("tiktok-oauth2: %w", err)
	}

	var body userInfoResponse
	if err = json.Unmarshal(bodyBytes, &body); err != nil {
		return nil, fmt.Errorf("tiktok-oauth2: %w", err)
	}

	if body == (userInfoResponse{}) {
		return nil, handleErrorResponse(bodyBytes)
	}

	return &UserInfo{
		OpenID:       body.Data.OpenID,
		UnionID:      body.Data.UnionID,
		Avatar:       body.Data.Avatar,
		AvatarLarger: body.Data.AvatarLarger,
		DisplayName:  body.Data.DisplayName,
	}, nil
}

func handleErrorResponse(data []byte) error {
	var errBody errorResponse
	if err := json.Unmarshal(data, &errBody); err != nil {
		return fmt.Errorf("tiktok-oauth2: %w", err)
	}

	return fmt.Errorf("tiktok-oauth2: %s [%d]", errBody.Data.Description, errBody.Data.ErrorCode)
}
