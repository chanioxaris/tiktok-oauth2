package tiktok

const (
	endpointAuth     = "https://open-api.tiktok.com/platform/oauth/connect/"
	endpointToken    = "https://open-api.tiktok.com/oauth/access_token/"
	endpointRefresh  = "https://open-api.tiktok.com/oauth/refresh_token/"
	endpointRevoke   = "https://open-api.tiktok.com/oauth/revoke/"
	endpointUserInfo = "https://open-api.tiktok.com/oauth/userinfo/"
)

type UserInfo struct {
	OpenID       string
	UnionID      string
	Avatar       string
	AvatarLarger string
	DisplayName  string
}

type userInfoResponse struct {
	Data struct {
		OpenID       string `json:"open_id"`
		UnionID      string `json:"union_id"`
		Avatar       string `json:"avatar"`
		AvatarLarger string `json:"avatar_larger"`
		DisplayName  string `json:"display_name"`
	}
}

type tokenResponse struct {
	Data struct {
		OpenID           string `json:"open_id"`
		Scope            string `json:"scope"`
		AccessToken      string `json:"access_token"`
		ExpiresIn        int64  `json:"expires_in"`
		RefreshToken     string `json:"refresh_token"`
		RefreshExpiresIn int64  `json:"refresh_expires_in"`
	} `json:"data"`
}

type errorResponse struct {
	Data struct {
		Captcha     string `json:"captcha"`
		DescURL     string `json:"desc_url"`
		Description string `json:"description"`
		ErrorCode   int    `json:"error_code"`
	} `json:"data"`
	Message string `json:"message"`
}
