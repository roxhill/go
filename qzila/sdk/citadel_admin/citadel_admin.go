package citadel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	createUserAction            = "/users.create"
	getUserAction               = "/users.get"
	deleteUserAction            = "/users.delete"
	listUsersAction             = "/users.list"
	updateUserAction            = "/users.update"
	setUserPasswordAction       = "/users.setPassword"
	getUserMetadataAction       = "/users.metadata.get"
	setUserMetadataAction       = "/users.metadata.set"
	deleteUserMetadataAction    = "/users.metadata.delete"
	adminMigrateUsersAction     = "/users.adminMigrateUsers"
	adminImpersonateStartAction = "/users.adminImpersonate"
	adminImpersonateStopAction  = "/users.adminStopImpersonating"
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

const (
	LanguageEn = "en"
)

const (
	BcryptPasswordAlgorithm = "bcrypt"
	Sha512PasswordAlgorithm = "sha512"
)

type UserResponse struct {
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
	CreatedByAdmin         bool     `json:"createdByAdmin"`
}

type CreateUserRequest struct {
	UserId       string `json:"userId"`
	Username     string `json:"username"`
	EmailAddress string `json:"emailAddress"`
	Status       string `json:"status"`
	Language     string `json:"language"`
	Password     string `json:"password"`
}

type CreateUserResponse struct {
	User UserResponse `json:"user"`
}

func (c *client) CreateUser(request *CreateUserRequest) (*CreateUserResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(createUserAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer responseBody.Close()

	response := &CreateUserResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type GetUserRequest struct {
	UserId string `json:"userId"`
}

func (c *client) GetUser(request *GetUserRequest) (*UserResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal user: %v", err)
	}

	responseBody, err := c.request(getUserAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch the user: %v", err)
	}

	defer responseBody.Close()

	response := &UserResponse{}
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
		return nil, fmt.Errorf("%v", err)
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
	Users  []UserResponse `json:"items"`
	Cursor string         `json:"cursor,omitempty"`
}

func (c *client) ListUsers(request *ListUsersRequest) (*ListUsersResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(listUsersAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
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

func (c *client) UpdateUser(request *UpdateUserRequest) (*UserResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(updateUserAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer responseBody.Close()

	response := &UserResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type SetUserPasswordRequest struct {
	UserId   string `json:"userId"`
	Password string `json:"password"`
}

type SetUserPasswordResponse struct {
	Status string `json:"status"`
}

func (c *client) SetUserPassword(request *SetUserPasswordRequest) (*SetUserPasswordResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(setUserPasswordAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer responseBody.Close()

	response := &SetUserPasswordResponse{}
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
		return nil, fmt.Errorf("%v", err)
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
		return nil, fmt.Errorf("%v", err)
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
		return nil, fmt.Errorf("%v", err)
	}

	defer responseBody.Close()

	response := &DeleteUserMetadataResponse{}
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
	UserId       string         `json:"userId"`
	Username     string         `json:"username"`
	EmailAddress string         `json:"emailAddress"`
	PhoneNumber  string         `json:"phoneNumber,omitempty"`
	Status       string         `json:"status"`
	Password     BcryptPassword `json:"password"`
	Language     string         `json:"language"`
}

type BcryptPassword struct {
	Algorithm string `json:"alg"`
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
		return nil, fmt.Errorf("%v", err)
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
	UserId       string         `json:"userId"`
	Username     string         `json:"username"`
	EmailAddress string         `json:"emailAddress"`
	PhoneNumber  string         `json:"phoneNumber,omitempty"`
	Status       string         `json:"status"`
	Password     Sha512Password `json:"password"`
	Language     string         `json:"language"`
}

type Sha512Password struct {
	Algorithm  string `json:"alg"`
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
		return nil, fmt.Errorf("%v", err)
	}

	defer responseBody.Close()

	response := &AdminMigrateUsersResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type AdminImpersonateStartRequest struct {
	Sid    string `json:"sid"`
	UserId string `json:"userId"`
}

type AdminImpersonateStartResponse struct {
	Status string `json:"status"`
}

func (c *client) AdminImpersonateStart(request *AdminImpersonateStartRequest) (*AdminImpersonateStartResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(adminImpersonateStartAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer responseBody.Close()

	response := &AdminImpersonateStartResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type AdminImpersonateStopRequest struct {
	Sid string `json:"sid"`
}

type AdminImpersonateStopResponse struct {
	Status string `json:"status"`
}

func (c *client) AdminImpersonateStop(request *AdminImpersonateStopRequest) (*AdminImpersonateStopResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(adminImpersonateStopAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer responseBody.Close()

	response := &AdminImpersonateStopResponse{}
	err = json.NewDecoder(responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

type Client interface {
	CreateUser(request *CreateUserRequest) (*CreateUserResponse, error)
	GetUser(request *GetUserRequest) (*UserResponse, error)
	DeleteUser(request *DeleteUserRequest) (*DeleteUserResponse, error)
	ListUsers(request *ListUsersRequest) (*ListUsersResponse, error)
	UpdateUser(request *UpdateUserRequest) (*UserResponse, error)
	SetUserPassword(request *SetUserPasswordRequest) (*SetUserPasswordResponse, error)
	GetAllUserMetadata(request *GetAllUserMetadataRequest) (*GetAllUserMetadataResponse, error)
	SetUserMetadata(request *SetUserMetadataRequest) (*SetUserMetadataResponse, error)
	DeleteUserMetadata(request *DeleteUserMetadataRequest) (*DeleteUserMetadataResponse, error)
	AdminMigrateBcryptUsers(request *AdminMigrateBcryptUsersRequest) (*AdminMigrateUsersResponse, error)
	AdminMigrateSha512Users(request *AdminMigrateSha512UsersRequest) (*AdminMigrateUsersResponse, error)
	AdminImpersonateStart(request *AdminImpersonateStartRequest) (*AdminImpersonateStartResponse, error)
	AdminImpersonateStop(request *AdminImpersonateStopRequest) (*AdminImpersonateStopResponse, error)
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
	req.Header.Set("Authorization", c.apiKey)
	req.Header.Set("x-sdk-version", "0.8.0-go")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send POST request: %v", err)
	}

	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized {
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
