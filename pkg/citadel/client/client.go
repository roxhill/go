package client

import (
	"bytes"
	"encoding/json"
	"github.com/everlutionsk/go/internal/citadel"
)

const (
	sessionResolveAction       = "/sessions.resolve"
	sessionRevokeAction        = "/sessions.revoke"
	sessionResolveBearerAction = "/sessions.bearerResolve"
	sessionRevokeBearerAction  = "/sessions.bearerRevoke"
)

func NewClient(config *Config) Client {
	return &client{
		baseUrl: config.BaseUrl,
		request: citadel.NewRequest(citadel.NewPreSharedKeyConfig(config.PreSharedKey)),
	}
}

type Client interface {
	SessionResolve(request *SessionResolveRequest) (*SessionResolveResponse, error)
	SessionRevoke(request *SessionRevokeRequest) (*SessionRevokeResponse, error)
	SessionResolveBearer(request *BearerSessionRequest) (*SessionResolveBearerResponse, error)
	SessionRevokeBearer(request *BearerSessionRequest) (*SessionRevokeBearerResponse, error)
}

type client struct {
	baseUrl string
	request citadel.Request
}

func (c *client) SessionResolve(request *SessionResolveRequest) (*SessionResolveResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	responseBody, err := c.request.Post(sessionResolveAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}

	defer (*responseBody).Close()

	response := &SessionResolveResponse{}
	err = json.NewDecoder(*responseBody).Decode(response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (c *client) SessionRevoke(request *SessionRevokeRequest) (*SessionRevokeResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	responseBody, err := c.request.Post(sessionRevokeAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}

	defer (*responseBody).Close()

	response := &SessionRevokeResponse{}
	err = json.NewDecoder(*responseBody).Decode(response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (c *client) SessionResolveBearer(request *BearerSessionRequest) (*SessionResolveBearerResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	responseBody, err := c.request.Post(sessionResolveBearerAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}

	defer (*responseBody).Close()

	response := &SessionResolveBearerResponse{}
	err = json.NewDecoder(*responseBody).Decode(response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (c *client) SessionRevokeBearer(request *BearerSessionRequest) (*SessionRevokeBearerResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	responseBody, err := c.request.Post(sessionRevokeBearerAction, bytes.NewBuffer(requestBody))

	if err != nil {
		return nil, err
	}

	defer (*responseBody).Close()

	response := &SessionRevokeBearerResponse{}
	err = json.NewDecoder(*responseBody).Decode(response)

	if err != nil {
		return nil, err
	}

	return response, nil
}
