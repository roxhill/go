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
	changeUserPasswordAction    = "/users.changePassword"
	getUserMetadataAction       = "/users.metadata.get"
	setUserMetadataAction       = "/users.metadata.set"
	deleteUserMetadataAction    = "/users.metadata.delete"
	adminMigrateUsersAction     = "/users.adminMigrateUsers"
	adminImpersonateStartAction = "/users.adminImpersonate"
	adminImpersonateStopAction  = "/users.adminStopImpersonating"
)

const (
	UserActive   = "active"
	UserDisabled = "disabled"
	UserLocked   = "locked"
)

const (
	SecondFactorEmail = "emailCode"
	SecondFactorSms   = "smsCode"
)

const (
	LanguageEn = "en"
)

const (
	BcryptPasswordAlgorithm = "bcrypt"
	Sha512PasswordAlgorithm = "sha512"
)

type UserResponse struct {
	UserId            string   `json:"id"`
	Status            string   `json:"status"`
	Username          string   `json:"username"`
	EmailAddress      string   `json:"emailAddress"`
	DisableMfa        bool     `json:"disableMfa"`
	AllowedMfaMethods []string `json:"allowedMfaMethods"`
	Language          string   `json:"language"`
	PhoneNumber       string   `json:"phoneNumber"`
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
	UserId            string   `json:"userId"`
	Username          string   `json:"username,omitempty"`
	EmailAddress      string   `json:"emailAddress,omitempty"`
	PhoneNumber       string   `json:"phoneNumber,omitempty"`
	Status            string   `json:"status,omitempty"`
	DisableMfa        *bool    `json:"disableMfa,omitempty"`
	AllowedMfaMethods []string `json:"allowedMfaMethods,omitempty"`
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

type ChangeUserPasswordRequest struct {
	UserId      string `json:"userId"`
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

type ChangeUserPasswordResponse struct {
	Status string `json:"status"`
}

func (c *client) ChangeUserPassword(request *ChangeUserPasswordRequest) (*ChangeUserPasswordResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request(changeUserPasswordAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer responseBody.Close()

	response := &ChangeUserPasswordResponse{}
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
	DisableMfa   bool           `json:"disableMfa"`
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
	DisableMfa   bool           `json:"disableMfa"`
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
	ChangeUserPassword(request *ChangeUserPasswordRequest) (*ChangeUserPasswordResponse, error)
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
	req.Header.Set("Authorization", c.apiKey)
	req.Header.Set("x-sdk-version", "0.10.1-go")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	// Handle Api Gateway errors
	if resp.StatusCode == http.StatusInternalServerError ||
		resp.StatusCode == http.StatusServiceUnavailable ||
		resp.StatusCode == http.StatusGatewayTimeout ||
		resp.StatusCode == http.StatusBadGateway ||
		resp.StatusCode == http.StatusUnauthorized ||
		resp.StatusCode == http.StatusForbidden {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			err := &UnexpectedError{
				Message: fmt.Sprintf("HTTP %d - API error: %v", resp.StatusCode, string(bodyBytes)),
			}

			return nil, err
		}

		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		errorResponse := &ErrorResponse{}

		// Decode the error response
		err = json.NewDecoder(resp.Body).Decode(errorResponse)
		if err != nil {
			return nil, err
		}

		// Check the error type and return the appropriate error
		switch errorResponse.Message.Type {
		case "configError":
			return nil, &ConfigError{Message: errorResponse.Message.Message}
		case "bearerMalformed":
			return nil, &BearerMalformedError{Message: errorResponse.Message.Message}
		case "userDeleteFailed":
			return nil, &UserDeleteFailedError{Message: errorResponse.Message.Message}
		case "passwordInvalid":
			return nil, &PasswordInvalidError{Message: errorResponse.Message.Message}
		case "userAlreadyImpersonated":
			return nil, &UserAlreadyImpersonatedError{Message: errorResponse.Message.Message}
		case "userNotImpersonated":
			return nil, &UserNotImpersonatedError{Message: errorResponse.Message.Message}
		case "notFound":
			return nil, &NotFoundError{Message: errorResponse.Message.Message}
		case "usernameAlreadyTaken":
			return nil, &UsernameAlreadyTakenError{Message: errorResponse.Message.Message}
		case "userAlreadyExists":
			return nil, &UserAlreadyExistsError{Message: errorResponse.Message.Message}
		case "bearerExpired":
			return nil, &BearerExpiredError{Message: errorResponse.Message.Message}
		case "sessionInvalid":
			return nil, &SessionInvalidError{Message: errorResponse.Message.Message}
		default:
			return nil, &UnexpectedError{Message: fmt.Sprintf("Unexpected error.\nType: %v\nMessage: %v", errorResponse.Message.Type, errorResponse.Message.Message)}
		}
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
