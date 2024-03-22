package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/everlutionsk/go/internal/citadel"
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

func NewClient(config *ClientConfig) Client {
	return &client{
		baseUrl: config.BaseUrl,
		request: citadel.NewRequest(citadel.NewAPIKeyConfig(config.ApiKey, config.PreSharedKey)),
	}
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
	baseUrl string
	request citadel.Request
}

func (c *client) CreateUser(request *CreateUserRequest) (*CreateUserResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request.Post(createUserAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer (*responseBody).Close()

	response := &CreateUserResponse{}
	err = json.NewDecoder(*responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

func (c *client) GetUser(request *GetUserRequest) (*UserResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal user: %v", err)
	}

	responseBody, err := c.request.Post(getUserAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch the user: %v", err)
	}

	defer (*responseBody).Close()

	response := &UserResponse{}
	err = json.NewDecoder(*responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

func (c *client) DeleteUser(request *DeleteUserRequest) (*DeleteUserResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request.Post(deleteUserAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer (*responseBody).Close()

	response := &DeleteUserResponse{}
	err = json.NewDecoder(*responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

func (c *client) ListUsers(request *ListUsersRequest) (*ListUsersResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request.Post(listUsersAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer (*responseBody).Close()

	response := &ListUsersResponse{}
	err = json.NewDecoder(*responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

func (c *client) UpdateUser(request *UpdateUserRequest) (*UserResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request.Post(updateUserAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer (*responseBody).Close()

	response := &UserResponse{}
	err = json.NewDecoder(*responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

func (c *client) SetUserPassword(request *SetUserPasswordRequest) (*SetUserPasswordResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request.Post(setUserPasswordAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer (*responseBody).Close()

	response := &SetUserPasswordResponse{}
	err = json.NewDecoder(*responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

func (c *client) GetAllUserMetadata(request *GetAllUserMetadataRequest) (*GetAllUserMetadataResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request.Post(getUserMetadataAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer (*responseBody).Close()

	response := &GetAllUserMetadataResponse{}
	err = json.NewDecoder(*responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

func (c *client) SetUserMetadata(request *SetUserMetadataRequest) (*SetUserMetadataResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request.Post(setUserMetadataAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer (*responseBody).Close()

	response := &SetUserMetadataResponse{}
	err = json.NewDecoder(*responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

func (c *client) DeleteUserMetadata(request *DeleteUserMetadataRequest) (*DeleteUserMetadataResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request.Post(deleteUserMetadataAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer (*responseBody).Close()

	response := &DeleteUserMetadataResponse{}
	err = json.NewDecoder(*responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

func (c *client) AdminMigrateBcryptUsers(request *AdminMigrateBcryptUsersRequest) (*AdminMigrateUsersResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request.Post(adminMigrateUsersAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer (*responseBody).Close()

	response := &AdminMigrateUsersResponse{}
	err = json.NewDecoder(*responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

func (c *client) AdminMigrateSha512Users(request *AdminMigrateSha512UsersRequest) (*AdminMigrateUsersResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request.Post(adminMigrateUsersAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer (*responseBody).Close()

	response := &AdminMigrateUsersResponse{}
	err = json.NewDecoder(*responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

func (c *client) AdminImpersonateStart(request *AdminImpersonateStartRequest) (*AdminImpersonateStartResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request.Post(adminImpersonateStartAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer (*responseBody).Close()

	response := &AdminImpersonateStartResponse{}
	err = json.NewDecoder(*responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

func (c *client) AdminImpersonateStop(request *AdminImpersonateStopRequest) (*AdminImpersonateStopResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	responseBody, err := c.request.Post(adminImpersonateStopAction, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	defer (*responseBody).Close()

	response := &AdminImpersonateStopResponse{}
	err = json.NewDecoder(*responseBody).Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}
