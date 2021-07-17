package tiktok_test

import (
	"testing"

	"golang.org/x/oauth2"
)

const (
	endpointAuth  = "https://open-api.tiktok.com/platform/oauth/connect/"
	endpointToken = "https://open-api.tiktok.com/oauth/access_token/"
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

	return &oauth2.Config{
		ClientID:     "test-client-key",
		ClientSecret: "test-client-secret",
		RedirectURL:  "test-redirect-url",
		Scopes:       []string{"test-scope-1", "test-scope-2"},
		Endpoint: oauth2.Endpoint{
			AuthURL:   endpointAuth,
			TokenURL:  endpointToken,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
}
