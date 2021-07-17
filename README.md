# tiktok-oauth2
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://raw.githubusercontent.com/chanioxaris/tiktok-oauth2/master/LICENSE)
[![GoDoc](https://godoc.org/github.com/chanioxaris/json-server?status.svg)](https://pkg.go.dev/github.com/chanioxaris/tiktok-oauth2)
[![codecov](https://codecov.io/gh/chanioxaris/tiktok-oauth2/branch/master/graph/badge.svg?token=FcdhuSfrfA)](https://codecov.io/gh/chanioxaris/tiktok-oauth2)
[![goreportcard](https://goreportcard.com/badge/github.com/chanioxaris/json-server)](https://goreportcard.com/report/github.com/chanioxaris/tiktok-oauth2)

A package to add support for TikTok OAuth 2.0 on top of the Golang's package ([https://github.com/golang/oauth2](https://github.com/golang/oauth2))

You can find the official TikTok documentation [here](https://developers.tiktok.com/doc)

### Install 
`$ go get github.com/chanioxaris/tiktok-oauth2`

### Available functions
- `NewConfig()` Create a new TikTok oauth2 config
- `ConfigExchange()` Convert an oauth2 config into an oauth2 token
- `RefreshToken()` Refresh the access token
- `RevokeAccess()` Revoke the access token
- `RetrieveUserInfo()` Retrieve basic information of a TikTok user

### Helper functions
- `OpenIDFromToken()` Retrieve the extra field `open_id` from an oauth2 token.
- `ScopeFromToken()` Retrieve the extra field `scope` from an oauth2 token.
- `RefreshExpiresInFromToken()` Retrieve the extra field `refresh_expires_in` from an oauth2 token.

### License
tiktok-oauth2 is [MIT licensed](LICENSE).