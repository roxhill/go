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

type CitadelError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type ErrorResponse struct {
	Id      string       `json:"errorId,omitempty"`
	Message CitadelError `json:"error"`
}

func (c *client) request(action string, body io.Reader) (io.ReadCloser, error) {
	req, err := http.NewRequest("POST", c.baseUrl+action, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-sdk-version", "0.10.0-go")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusInternalServerError {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			error := &UnexpectedError{
				Message: fmt.Sprintf("HTTP %d - API error: %v", 500, string(bodyBytes)),
			}

			return nil, error
		}

		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		errorResponse := &ErrorResponse{}
		err = json.NewDecoder(resp.Body).Decode(errorResponse)
		if err == nil {
			if errorResponse.Message.Type == "configError" {
				return nil, &ConfigError{Message: errorResponse.Message.Message}
			}
			if errorResponse.Message.Type == "bearerMalformed" {
				return nil, &BearerMalformedError{Message: errorResponse.Message.Message}
			}
			if errorResponse.Message.Type == "userDeleteFailed" {
				return nil, &UserDeleteFailedError{Message: errorResponse.Message.Message}
			}
			if errorResponse.Message.Type == "passwordInvalid" {
				return nil, &PasswordInvalidError{Message: errorResponse.Message.Message}
			}
			if errorResponse.Message.Type == "userAlreadyImpersonated" {
				return nil, &UserAlreadyImpersonatedError{Message: errorResponse.Message.Message}
			}
			if errorResponse.Message.Type == "userNotImpersonated" {
				return nil, &UserNotImpersonatedError{Message: errorResponse.Message.Message}
			}
			if errorResponse.Message.Type == "notFound" {
				return nil, &NotFoundError{Message: errorResponse.Message.Message}
			}
			if errorResponse.Message.Type == "usernameAlreadyTaken" {
				return nil, &UsernameAlreadyTakenError{Message: errorResponse.Message.Message}
			}
			if errorResponse.Message.Type == "userAlreadyExists" {
				return nil, &UserAlreadyExistsError{Message: errorResponse.Message.Message}
			}
			if errorResponse.Message.Type == "bearerExpired" {
				return nil, &BearerExpiredError{Message: errorResponse.Message.Message}
			}
			if errorResponse.Message.Type == "sessionInvalid" {
				return nil, &SessionInvalidError{Message: errorResponse.Message.Message}
			}

			return nil, &UnexpectedError{Message: fmt.Sprintf("Unexpected error.\nType: %v\nMessage: %v", errorResponse.Message.Type, errorResponse.Message.Message)}
		}

		return nil, err
	}

	return resp.Body, nil
}

type UnexpectedError struct {
	Message string
}

func (e *UnexpectedError) Error() string {
	return e.Message
}

type ConfigError struct {
	Message string
}

func (e *ConfigError) Error() string {
	return e.Message
}

type BearerMalformedError struct {
	Message string
}

func (e *BearerMalformedError) Error() string {
	return e.Message
}

type UserDeleteFailedError struct {
	Message string
}

func (e *UserDeleteFailedError) Error() string {
	return e.Message
}

type PasswordInvalidError struct {
	Message string
}

func (e *PasswordInvalidError) Error() string {
	return e.Message
}

type UserAlreadyImpersonatedError struct {
	Message string
}

func (e *UserAlreadyImpersonatedError) Error() string {
	return e.Message
}

type UserNotImpersonatedError struct {
	Message string
}

func (e *UserNotImpersonatedError) Error() string {
	return e.Message
}

type NotFoundError struct {
	Message string
}

func (e *NotFoundError) Error() string {
	return e.Message
}

type UsernameAlreadyTakenError struct {
	Message string
}

func (e *UsernameAlreadyTakenError) Error() string {
	return e.Message
}

type UserAlreadyExistsError struct {
	Message string
}

func (e *UserAlreadyExistsError) Error() string {
	return e.Message
}

type BearerExpiredError struct {
	Message string
}

func (e *BearerExpiredError) Error() string {
	return e.Message
}

type SessionInvalidError struct {
	Message string
}

func (e *SessionInvalidError) Error() string {
	return e.Message
}
