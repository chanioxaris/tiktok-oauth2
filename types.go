package tiktok

type configExchangeResponse struct {
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
