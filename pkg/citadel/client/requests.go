package client

type SessionRevokeRequest struct {
	CookieHeader string   `json:"cookieHeader"`
	ClientId     string   `json:"clientId"`
	ClientSecret []string `json:"clientSecret"`
}

type SessionResolveRequest struct {
	CookieHeader string `json:"cookieHeader"`
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

type BearerSessionRequest struct {
	Token string `json:"token"`
}
