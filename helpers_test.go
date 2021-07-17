package tiktok_test

import (
	"testing"
	"time"

	"github.com/chanioxaris/tiktok-oauth2"
	"golang.org/x/oauth2"
)

var (
	responseSuccessToken     = `{"data":{"open_id":"test-open-id","scope":"test-scope-1,test-scope-2","access_token":"test-access-token","expires_in":86400,"refresh_token":"test-refresh-token","refresh_expires_in":31536000}}`
	responseError            = `{"data":{"captcha":"","desc_url":"","description":"Request error","error_code":1000},"message":""}`
	responseEmptyAccessToken = `{"data":{"open_id":"test-open-id","scope":"test-scope-1,test-scope-2","expires_in":86400,"refresh_token":"test-refresh-token","refresh_expires_in":31536000}}`
	responseSuccessUserInfo  = `{"data":{"open_id":"test-open-id","union_id":"test-union-id","avatar":"test-avatar","avatar_larger":"test-avatar-larger","display_name":"test-display-name"}}`
)

var (
	accessTokenParameters = map[string]string{
		"client_key":    "test-client-key",
		"client_secret": "test-client-secret",
		"code":          "test-code",
		"grant_type":    "authorization_code",
	}

	refreshTokenParameters = map[string]string{
		"client_key":    "test-client-key",
		"refresh_token": "test-refresh-token",
		"grant_type":    "refresh_token",
	}

	revokeParameters = map[string]string{
		"access_token": "test-access-token",
		"open_id":      "test-open-id",
	}

	userInfoParameters = map[string]string{
		"access_token": "test-access-token",
		"open_id":      "test-open-id",
	}
)

func testNewOauthConfig(t *testing.T) *oauth2.Config {
	t.Helper()

	cfg, err := tiktok.NewConfig(
		"test-client-key",
		"test-client-secret",
		"test-redirect-url",
		"test-scope-1", "test-scope-2",
	)
	if err != nil {
		t.Fatal(err)
	}

	return cfg
}

func testNewOauthToken(t *testing.T) *oauth2.Token {
	t.Helper()

	return &oauth2.Token{
		AccessToken:  "test-access-token",
		TokenType:    "test-token-type",
		RefreshToken: "test-refresh-token",
		Expiry:       time.Now().Add(time.Second * 86400),
	}
}
