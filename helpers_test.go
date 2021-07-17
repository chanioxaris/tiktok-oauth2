package tiktok_test

import (
	"testing"

	"github.com/chanioxaris/tiktok-oauth2"
	"golang.org/x/oauth2"
)

var (
	responseAccessTokenSuccess = `{"data":{"open_id":"test-open-id","scope":"test-scope-1,test-scope-2","access_token":"test-access-token","expires_in":86400,"refresh_token":"test-refresh-token","refresh_expires_in":31536000}}`
	responseAccessTokenError   = `{"data":{"captcha":"","desc_url":"","description":"Request error","error_code":1000},"message":""}`
	responseAccessTokenEmpty   = `{"data":{"open_id":"test-open-id","scope":"test-scope-1,test-scope-2","expires_in":86400,"refresh_token":"test-refresh-token","refresh_expires_in":31536000}}`
)

var (
	accessTokenParameters = map[string]string{
		"client_key":    "test-client-key",
		"client_secret": "test-client-secret",
		"code":          "test-code",
		"grant_type":    "authorization_code",
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
