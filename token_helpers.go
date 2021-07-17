package tiktok

import (
	"fmt"

	"golang.org/x/oauth2"
)

func OpenIDFromToken(token *oauth2.Token) (string, error) {
	if token == nil {
		return "", fmt.Errorf("tiktok-oauth2: OpenIDFromToken: token cannot be nil")
	}

	extraOpenID := token.Extra("open_id")
	if extraOpenID == nil {
		return "", fmt.Errorf("tiktok-oauth2: OpenIDFromToken: token missing open id")
	}

	openID, ok := extraOpenID.(string)
	if !ok {
		return "", fmt.Errorf("tiktok-oauth2: OpenIDFromToken: expected token open id to be a string")
	}

	return openID, nil
}

func ScopeFromToken(token *oauth2.Token) (string, error) {
	if token == nil {
		return "", fmt.Errorf("tiktok-oauth2: ScopeFromToken: token cannot be nil")
	}

	extraScope := token.Extra("scope")
	if extraScope == nil {
		return "", fmt.Errorf("tiktok-oauth2: ScopeFromToken: token missing scope")
	}

	scope, ok := extraScope.(string)
	if !ok {
		return "", fmt.Errorf("tiktok-oauth2: ScopeFromToken: expected token scope to be a string")
	}

	return scope, nil
}

func RefreshExpiresInFromToken(token *oauth2.Token) (int64, error) {
	if token == nil {
		return 0, fmt.Errorf("tiktok-oauth2: RefreshExpiresInFromToken: token cannot be nil")
	}

	extraRefreshExpiresIn := token.Extra("refresh_expires_in")
	if extraRefreshExpiresIn == nil {
		return 0, fmt.Errorf("tiktok-oauth2: RefreshExpiresInFromToken: token missing refresh_expires_in")
	}

	refreshExpiresIn, ok := extraRefreshExpiresIn.(int64)
	if !ok {
		return 0, fmt.Errorf("tiktok-oauth2: RefreshExpiresInFromToken: expected token refresh_expires_in to be a int64")
	}

	return refreshExpiresIn, nil
}
