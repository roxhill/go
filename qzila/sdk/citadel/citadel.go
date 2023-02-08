package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	inviteUserAction         = "/users.invite"
	getUserAction            = "/users.get"
	deleteUserAction         = "/users.delete"
	listUsersAction          = "/users.list"
	updateUserAction         = "/users.update"
	getUserMetadataAction    = "/users.metadata.get"
	setUserMetadataAction    = "/users.metadata.set"
	deleteUserMetadataAction = "/users.metadata.delete"
	adminResetPasswordAction = "/users.adminResetPassword"
	verifyJwtAction          = "/users.verifyJwt"
)

const (
	UserActive              = "active"
	UserDisabled            = "disabled"
	UserLocked              = "locked"
	UserInvited             = "invited"
	UserInvitationConfirmed = "invitationConfirmed"
)

const (
	AuthFlowEmailCode = "emailCode"
	AuthFlowPassword  = "password"
)

const (
	SecondFactorEmail      = "email"
	SecondFactorSms        = "sms"
	SecondFactorPrivateKey = "privateKey"
	SecondFactorTotp       = "totp"
)

type GetUserRequest struct {
	Id string `json:"userId"`
}

func (c *Client) GetUser(request *GetUserRequest) (*User, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal user: %v", err)
	}

	responseBody, err := c.request(getUserAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch the user: %v", err)
	}

	defer responseBody.Close()

	response := &User{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type ListUsersRequest struct {
	Cursor string `json:"cursor"`
	Limit  int    `json:"limit"`
}

type ListUsersResponse struct {
	Users  []User `json:"items"`
	Cursor string `json:"cursor"`
}

func (c *Client) ListUsers(request *ListUsersRequest) (*ListUsersResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal user: %v", err)
	}

	responseBody, err := c.request(listUsersAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch the list of the users: %v", err)
	}

	defer responseBody.Close()

	response := &ListUsersResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type User struct {
	Id                     string   `json:"id"`
	AllowedAuthFlows       []string `json:"allowedAuthFlows"`
	RequiresPasswordChange bool     `json:"requiresPasswordChange"`
	Status                 string   `json:"status"`
	Username               string   `json:"username"`
	FailedPasswordAttempts int      `json:"failedPasswordAttempts"`
	Mfa                    bool     `json:"mfa"`
	EmailAddress           string   `json:"emailAddress"`
	EnabledMfaMethods      []string `json:"enabledMfaMethods"`
	Language               string   `json:"language"`
	PhoneNumber            string   `json:"phoneNumber"`
}

type Client struct {
	baseUrl      string
	client       *http.Client
	apiKey       string
	preSharedKey string
}

type ClientConfig struct {
	baseUrl      string
	apiKey       string
	preSharedKey string
}

func NewClient(config *ClientConfig) *Client {
	return &Client{
		baseUrl:      config.baseUrl,
		client:       &http.Client{},
		apiKey:       config.apiKey,
		preSharedKey: config.preSharedKey,
	}
}

func (client *Client) request(action string, body io.Reader) (io.ReadCloser, error) {
	req, err := http.NewRequest("POST", client.baseUrl+action, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create POST request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", client.apiKey)

	resp, err := client.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send POST request: %v", err)
	}

	return resp.Body, nil
}
