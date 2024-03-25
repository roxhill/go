package citadel_client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	sessionResolveAction       = "/sessions.resolve"
	sessionRevokeAction        = "/sessions.revoke"
	sessionResolveBearerAction = "/sessions.bearerResolve"
	sessionRevokeBearerAction  = "/sessions.bearerRevoke"
)

type ResolvedIdentity struct {
	Id         string          `json:"id"`
	AssignedAt string          `json:"assignedAt"`
	User       string          `json:"user"`
	Data       []ResolvedValue `json:"data"`
	Status     string          `json:"status"`
}

type ResolvedValue struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
	From  string      `json:"from"`
}

type ResolvedSession struct {
	Id          string             `json:"id"`
	Sid         string             `json:"sid"`
	Identities  []ResolvedIdentity `json:"identities"`
	Audience    string             `json:"audience"`
	IssuedAt    string             `json:"issuedAt"`
	RefreshedAt string             `json:"refreshedAt"`
	ExpiresAt   string             `json:"expiresAt"`
	ResolvedAt  string             `json:"resolvedAt"`
}

type SessionResolveRequest struct {
	CookieHeader string `json:"cookieHeader"`
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

type Recommended struct {
	Action          string      `json:"action"`
	ResponseHeaders interface{} `json:"responseHeaders"`
	Reason          string      `json:"reason"`
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
		return nil, fmt.Errorf("%v", err)
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
	CookieHeader string   `json:"cookieHeader"`
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
		return nil, fmt.Errorf("%v", err)
	}

	defer responseBody.Close()

	response := &SessionRevokeResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type SessionResolveBearerRequest struct {
	Token string `json:"token"`
}

type SessionResolveBearerResponse struct {
	Session ResolvedSession `json:"session,omitempty"`
}

func (c *client) SessionResolveBearer(request *SessionResolveBearerRequest) (*SessionResolveBearerResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(sessionResolveBearerAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer responseBody.Close()

	response := &SessionResolveBearerResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type SessionRevokeBearerRequest struct {
	Token string `json:"token"`
}

type SessionRevokeBearerResponse struct {
	Status string `json:"status"`
}

func (c *client) SessionRevokeBearer(request *SessionRevokeBearerRequest) (*SessionRevokeBearerResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(sessionRevokeBearerAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer responseBody.Close()

	response := &SessionRevokeBearerResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type Client interface {
	SessionResolve(request *SessionResolveRequest) (*SessionResolveResponse, error)
	SessionRevoke(request *SessionRevokeRequest) (*SessionRevokeResponse, error)
	SessionResolveBearer(request *SessionResolveBearerRequest) (*SessionResolveBearerResponse, error)
	SessionRevokeBearer(request *SessionRevokeBearerRequest) (*SessionRevokeBearerResponse, error)
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

type ErrorResponse struct {
	Id      string `json:"errorId"`
	Message string `json:"error"`
}

func (c *client) request(action string, body io.Reader) (io.ReadCloser, error) {
	req, err := http.NewRequest("POST", c.baseUrl+action, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create POST request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-sdk-version", "0.8.0-go")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send POST request: %v", err)
	}

	if resp.StatusCode == http.StatusBadRequest {
		errorResponse := &ErrorResponse{}
		err = json.NewDecoder(resp.Body).Decode(errorResponse)
		if err == nil {
			return nil, fmt.Errorf("API error (%v): %v", errorResponse.Id, errorResponse.Message)
		}

		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if resp.StatusCode == http.StatusInternalServerError {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			return nil, fmt.Errorf("API error: %v", string(bodyBytes))
		}

		return nil, fmt.Errorf("failed to parse body: %v", err)

	}

	return resp.Body, nil
}
