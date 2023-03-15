package citadel

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
	adminMigrateUsersAction  = "/users.adminMigrateUsers"
	verifyJwtAction          = "/users.verifyJwt"
)

const (
	UserActive              = "active"
	UserDisabled            = "disabled"
	UserLocked              = "locked"
	UserInvited             = "invited"
	UserInvitationConfirmed = "invitationConfirmed"
	UserMigrated            = "migrated"
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

type InviteUserRequest struct {
	Username            string   `json:"username"`
	EmailAddress        string   `json:"emailAddress"`
	AllowedAuthFlows    []string `json:"allowedAuthFlows"`
	RedirectUri         string   `json:"redirectUri"`
	ExpirationInSeconds int      `json:"expirationInSeconds"`
	Language            string   `json:"language"`
}

type InviteUserResponse struct {
	UserId string `json:"userId"`
}

func (c *client) InviteUser(request *InviteUserRequest) (*InviteUserResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(inviteUserAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch response: %v", err)
	}

	defer responseBody.Close()

	response := &InviteUserResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type GetUserRequest struct {
	UserId string `json:"userId"`
}

type GetUserResponse struct {
	UserId                 string   `json:"id"`
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

func (c *client) GetUser(request *GetUserRequest) (*GetUserResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal user: %v", err)
	}

	responseBody, err := c.request(getUserAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch the user: %v", err)
	}

	defer responseBody.Close()

	response := &GetUserResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type DeleteUserRequest struct {
	UserId string `json:"userId"`
}

type DeleteUserResponse struct {
	Status string `json:"status"`
}

func (c *client) DeleteUser(request *DeleteUserRequest) (*DeleteUserResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(deleteUserAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch response: %v", err)
	}

	defer responseBody.Close()

	response := &DeleteUserResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type ListUsersRequest struct {
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit"`
}

type ListUsersResponse struct {
	Users  []GetUserResponse `json:"items"`
	Cursor string            `json:"cursor,omitempty"`
}

func (c *client) ListUsers(request *ListUsersRequest) (*ListUsersResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(listUsersAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch response: %v", err)
	}

	defer responseBody.Close()

	response := &ListUsersResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type UpdateUserRequest struct {
	UserId       string `json:"userId"`
	Username     string `json:"username,omitempty"`
	EmailAddress string `json:"emailAddress,omitempty"`
	PhoneNumber  string `json:"phoneNumber,omitempty"`
	Status       string `json:"status,omitempty"`
}

func (c *client) UpdateUser(request *UpdateUserRequest) (*GetUserResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(updateUserAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch response: %v", err)
	}

	defer responseBody.Close()

	response := &GetUserResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type GetAllUserMetadataRequest struct {
	UserId string `json:"userId"`
}

type GetAllUserMetadataResponse struct {
	Items []MetadataItem `json:"items"`
}

type MetadataItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (c *client) GetAllUserMetadata(request *GetAllUserMetadataRequest) (*GetAllUserMetadataResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(getUserMetadataAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch response: %v", err)
	}

	defer responseBody.Close()

	response := &GetAllUserMetadataResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type SetUserMetadataRequest struct {
	UserId   string         `json:"userId"`
	Metadata []MetadataItem `json:"metadata"`
}

type SetUserMetadataResponse struct {
	Status string `json:"status"`
}

func (c *client) SetUserMetadata(request *SetUserMetadataRequest) (*SetUserMetadataResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(setUserMetadataAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch response: %v", err)
	}

	defer responseBody.Close()

	response := &SetUserMetadataResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type DeleteUserMetadataRequest struct {
	UserId   string   `json:"userId"`
	Metadata []string `json:"metadata"`
}

type DeleteUserMetadataResponse struct {
	Status string `json:"status"`
}

func (c *client) DeleteUserMetadata(request *DeleteUserMetadataRequest) (*DeleteUserMetadataResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(deleteUserMetadataAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch response: %v", err)
	}

	defer responseBody.Close()

	response := &DeleteUserMetadataResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type AdminResetPasswordRequest struct {
	UserId              string `json:"userId"`
	RedirectUri         string `json:"redirectUri"`
	ExpirationInSeconds int    `json:"expirationInSeconds"`
}

type AdminResetPasswordResponse struct {
	Status string `json:"status"`
}

func (c *client) AdminResetPassword(request *AdminResetPasswordRequest) (*AdminResetPasswordResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(adminResetPasswordAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch response: %v", err)
	}

	defer responseBody.Close()

	response := &AdminResetPasswordResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type AdminMigrateBcryptUsersRequest struct {
	Items []BcryptUserMigrationRequest `json:"items"`
}

type BcryptUserMigrationRequest struct {
	Username               string         `json:"username"`
	EmailAddress           string         `json:"emailAddress"`
	PhoneNumber            string         `json:"phoneNumber,omitempty"`
	Password               BcryptPassword `json:"password"`
	RequiresPasswordChange bool           `json:"requiresPasswordChange"`
	AllowedAuthFlows       []string       `json:"allowedAuthFlows"`
	Language               string         `json:"language"`
}

type BcryptPassword struct {
	Algorithm string `json:"algorithm"`
	Hash      string `json:"hash"`
}

type AdminMigrateUsersResponse struct {
	Items []UserId `json:"items"`
}

type UserId struct {
	UserId string `json:"userId"`
}

func (c *client) AdminMigrateBcryptUsers(request *AdminMigrateBcryptUsersRequest) (*AdminMigrateUsersResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(adminMigrateUsersAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch response: %v", err)
	}

	defer responseBody.Close()

	response := &AdminMigrateUsersResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type AdminMigrateSha512UsersRequest struct {
	Items []Sha512UserMigrationRequest `json:"items"`
}

type Sha512UserMigrationRequest struct {
	Username               string         `json:"username"`
	EmailAddress           string         `json:"emailAddress"`
	PhoneNumber            string         `json:"phoneNumber,omitempty"`
	Password               Sha512Password `json:"password"`
	RequiresPasswordChange bool           `json:"requiresPasswordChange"`
	AllowedAuthFlows       []string       `json:"allowedAuthFlows"`
	Language               string         `json:"language"`
}

type Sha512Password struct {
	Algorithm  string `json:"algorithm"`
	Hash       string `json:"hash"`
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
}

func (c *client) AdminMigrateSha512Users(request *AdminMigrateSha512UsersRequest) (*AdminMigrateUsersResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(adminMigrateUsersAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch response: %v", err)
	}

	defer responseBody.Close()

	response := &AdminMigrateUsersResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type VerifyJwtRequest struct {
	Jwt                 string          `json:"jwt"`
	Expectations        JwtExpectations `json:"expectations"`
	ExpirationInSeconds int             `json:"expirationInSeconds"`
}

type VerifyJwtResponse struct {
	IsValid bool   `json:"isValid"`
	Reason  string `json:"reason,omitempty"`
}

type JwtExpectations struct {
	Kind     string `json:"kind"`
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	MaxAge   int    `json:"maxAge"`
}

func (c *client) VerifyJwt(request *VerifyJwtRequest) (*VerifyJwtResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(verifyJwtAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch response: %v", err)
	}

	defer responseBody.Close()

	response := &VerifyJwtResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type Client interface {
	InviteUser(request *InviteUserRequest) (*InviteUserResponse, error)
	GetUser(request *GetUserRequest) (*GetUserResponse, error)
	DeleteUser(request *DeleteUserRequest) (*DeleteUserResponse, error)
	ListUsers(request *ListUsersRequest) (*ListUsersResponse, error)
	UpdateUser(request *UpdateUserRequest) (*GetUserResponse, error)
	GetAllUserMetadata(request *GetAllUserMetadataRequest) (*GetAllUserMetadataResponse, error)
	SetUserMetadata(request *SetUserMetadataRequest) (*SetUserMetadataResponse, error)
	DeleteUserMetadata(request *DeleteUserMetadataRequest) (*DeleteUserMetadataResponse, error)
	AdminResetPassword(request *AdminResetPasswordRequest) (*AdminResetPasswordResponse, error)
	AdminMigrateBcryptUsers(request *AdminMigrateBcryptUsersRequest) (*AdminMigrateUsersResponse, error)
	AdminMigrateSha512Users(request *AdminMigrateSha512UsersRequest) (*AdminMigrateUsersResponse, error)
	VerifyJwt(request *VerifyJwtRequest) (*VerifyJwtResponse, error)
}

type client struct {
	baseUrl      string
	client       *http.Client
	apiKey       string
	preSharedKey string
}

type ClientConfig struct {
	BaseUrl      string
	ApiKey       string
	PreSharedKey string
}

func NewClient(config *ClientConfig) Client {
	return &client{
		baseUrl:      config.BaseUrl,
		client:       &http.Client{},
		apiKey:       config.ApiKey,
		preSharedKey: config.PreSharedKey,
	}
}

func (c *client) request(action string, body io.Reader) (io.ReadCloser, error) {
	req, err := http.NewRequest("POST", c.baseUrl+action, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create POST request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send POST request: %v", err)
	}

	return resp.Body, nil
}
