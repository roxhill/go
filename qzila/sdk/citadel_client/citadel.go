package citadel_client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	sessionStartAction   = "/sessions.start"
	sessionResolveAction = "/sessions.resolve"
	sessionRevokeAction  = "/sessions.revoke"
)

type ResolvedValue struct {
	Name  string      `json:"name"`
	Type  string      `json:"type"`
	Value interface{} `json:"value"`
}

type ResolvedSession struct {
	Id          string          `json:"id"`
	Sid         string          `json:"sid"`
	User        string          `json:"user"`
	Audience    string          `json:"audience"`
	IssuedAt    string          `json:"issuedAt"`
	RefreshedAt string          `json:"refreshedAt"`
	ExpiresAt   string          `json:"expiresAt"`
	ResolvedAt  string          `json:"resolvedAt"`
	Data        []ResolvedValue `json:"data"`
}

type SessionStartRequest struct {
	Token        string `json:"token"`
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

type SessionStartResponse struct {
	Session         ResolvedSession   `json:"session"`
	ResponseHeaders map[string]string `json:"responseHeaders"`
}

func (c *client) SessionStart(request *SessionStartRequest) (*SessionStartResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(sessionStartAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch response: %v", err)
	}

	defer responseBody.Close()

	response := &SessionStartResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type SessionResolveRequest struct {
	CookieHeader string `json:"cookieHeader"`
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

type Recommended struct {
	Action          string            `json:"action"`
	ResponseHeaders map[string]string `json:"responseHeaders"`
	Reason          string            `json:"reason"`
}

type SessionResolveResponse struct {
	Session     ResolvedSession `json:"session,omitempty"`
	Recommended Recommended     `json:"recommended"`
}

func (c *client) SessionResolve(request *SessionResolveRequest) (*SessionResolveResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(sessionResolveAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch response: %v", err)
	}

	defer responseBody.Close()

	response := &SessionResolveResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type SessionRevokeRequest struct {
	Sid          string   `json:"sid"`
	ClientId     string   `json:"clientId"`
	ClientSecret []string `json:"clientSecret"`
}

type SessionRevokeResponse struct {
	ResponseHeaders map[string]string `json:"responseHeaders"`
}

func (c *client) SessionRevoke(request *SessionRevokeRequest) (*SessionRevokeResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(sessionRevokeAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch response: %v", err)
	}

	defer responseBody.Close()

	response := &SessionRevokeResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type Client interface {
	SessionStart(request *SessionStartRequest) (*SessionStartResponse, error)
	SessionResolve(request *SessionResolveRequest) (*SessionResolveResponse, error)
	SessionRevoke(request *SessionRevokeRequest) (*SessionRevokeResponse, error)
}

type client struct {
	baseUrl      string
	client       *http.Client
	preSharedKey string
}

type ClientConfig struct {
	BaseUrl      string
	PreSharedKey string
}

func NewClient(config *ClientConfig) Client {
	return &client{
		baseUrl:      config.BaseUrl,
		client:       &http.Client{},
		preSharedKey: config.PreSharedKey,
	}
}

func (c *client) request(action string, body io.Reader) (io.ReadCloser, error) {
	req, err := http.NewRequest("POST", c.baseUrl+action, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create POST request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send POST request: %v", err)
	}

	return resp.Body, nil
}
