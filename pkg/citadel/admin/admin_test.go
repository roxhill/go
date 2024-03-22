package admin

import (
	"encoding/json"
	"fmt"
	"testing"
)

// TestCreateUserHappyPath tests the happy path for creating a user.
func TestCreateUserHappyPath(t *testing.T) {
	mockedUserID := "user-id"
	expectedResponse := CreateUserResponse{
		User: UserResponse{
			UserId: mockedUserID,
		},
	}
	responseBody, err := json.Marshal(expectedResponse)
	if err != nil {
		t.Fatalf("Failed to marshal expected response: %v", err)
	}

	mockReq := &MockRequester{
		ResponseBody: string(responseBody),
	}

	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	request := &CreateUserRequest{}
	response, err := c.CreateUser(request)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if response == nil {
		t.Errorf("expected a response, got nil")
	}

	if response.User.UserId != mockedUserID {
		t.Errorf("expected user ID %s, got %s", mockedUserID, response.User.UserId)
	}
}

// TestCreateUserPostError simulates an error from the HTTP client.
func TestCreateUserPostError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseErr: fmt.Errorf("failed to post"),
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.CreateUser(&CreateUserRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestCreateUserDecodeError simulates a decode error from the HTTP client.
func TestCreateUserDecodeError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseBody: `{"invalidJson"}`,
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.CreateUser(&CreateUserRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestGetUserHappyPath tests the happy path for getting a user.
func TestGetUserHappyPath(t *testing.T) {
	mockedUserID := "user-id"
	expectedResponse := UserResponse{
		UserId: mockedUserID,
	}
	responseBody, err := json.Marshal(expectedResponse)
	if err != nil {
		t.Fatalf("Failed to marshal expected response: %v", err)
	}

	mockReq := &MockRequester{
		ResponseBody: string(responseBody),
	}

	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	request := &GetUserRequest{
		UserId: mockedUserID,
	}
	response, err := c.GetUser(request)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if response == nil {
		t.Errorf("expected a response, got nil")
	}

	if response.UserId != mockedUserID {
		t.Errorf("expected user ID %s, got %s", mockedUserID, response.UserId)
	}
}

// TestGetUserPostError simulates an error from the HTTP client.
func TestGetUserPostError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseErr: fmt.Errorf("failed to post"),
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.GetUser(&GetUserRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestGetUserDecodeError simulates a decode error from the HTTP client.
func TestGetUserDecodeError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseBody: `{"invalidJson"}`,
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.GetUser(&GetUserRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestDeleteUserHappyPath tests the happy path for deleting a user.
func TestDeleteUserHappyPath(t *testing.T) {
	mockedUserID := "user-id-to-delete"
	expectedResponse := DeleteUserResponse{
		Status: "true",
	}
	responseBody, err := json.Marshal(expectedResponse)
	if err != nil {
		t.Fatalf("Failed to marshal expected response: %v", err)
	}

	mockReq := &MockRequester{
		ResponseBody: string(responseBody),
	}

	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	request := &DeleteUserRequest{
		UserId: mockedUserID,
	}
	response, err := c.DeleteUser(request)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if response == nil {
		t.Errorf("expected a response, got nil")
	}

	if response.Status != "true" {
		t.Errorf("expected success to be true, got false")
	}
}

// TestDeleteUserPostError simulates an error from the HTTP client.
func TestDeleteUserPostError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseErr: fmt.Errorf("failed to post"),
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.DeleteUser(&DeleteUserRequest{UserId: "user-id-to-delete"})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestDeleteUserDecodeError simulates a decode error from the HTTP client.
func TestDeleteUserDecodeError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseBody: `{"invalidJson"}`,
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.DeleteUser(&DeleteUserRequest{UserId: "user-id-to-delete"})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestListUsersHappyPath tests the happy path for listing users.
func TestListUsersHappyPath(t *testing.T) {
	expectedResponse := ListUsersResponse{
		Users: []UserResponse{
			{UserId: "user-id-1", Username: "User One"},
			{UserId: "user-id-2", Username: "User Two"},
		},
	}
	responseBody, err := json.Marshal(expectedResponse)
	if err != nil {
		t.Fatalf("Failed to marshal expected response: %v", err)
	}

	mockReq := &MockRequester{
		ResponseBody: string(responseBody),
	}

	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	response, err := c.ListUsers(&ListUsersRequest{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if response == nil {
		t.Errorf("expected a response, got nil")
	}

	if len(response.Users) != len(expectedResponse.Users) {
		t.Errorf("expected %d users, got %d", len(expectedResponse.Users), len(response.Users))
	}
}

// TestListUsersPostError simulates an error from the HTTP client.
func TestListUsersPostError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseErr: fmt.Errorf("failed to post"),
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.ListUsers(&ListUsersRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestListUsersDecodeError simulates a decode error from the HTTP client.
func TestListUsersDecodeError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseBody: `{"invalidJson"}`,
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.ListUsers(&ListUsersRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestUpdateUserHappyPath tests the happy path for updating a user.
func TestUpdateUserHappyPath(t *testing.T) {
	mockedUserID := "user-id"
	mockedUserName := "Updated User"
	expectedResponse := UserResponse{
		UserId:   mockedUserID,
		Username: mockedUserName,
	}
	responseBody, err := json.Marshal(expectedResponse)
	if err != nil {
		t.Fatalf("Failed to marshal expected response: %v", err)
	}

	mockReq := &MockRequester{
		ResponseBody: string(responseBody),
	}

	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	request := UpdateUserRequest{
		UserId:   mockedUserID,
		Username: mockedUserName,
	}
	response, err := c.UpdateUser(&request)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if response == nil {
		t.Errorf("expected a response, got nil")
	}

	if response.UserId != mockedUserID || response.Username != mockedUserName {
		t.Errorf("expected user ID %s and name %s, got ID %s and name %s", mockedUserID, mockedUserName, response.UserId, response.Username)
	}
}

// TestUpdateUserPostError simulates an error from the HTTP client.
func TestUpdateUserPostError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseErr: fmt.Errorf("failed to post"),
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.UpdateUser(&UpdateUserRequest{UserId: "user-id"})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestUpdateUserDecodeError simulates a decode error from the HTTP client.
func TestUpdateUserDecodeError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseBody: `{"invalidJson"}`,
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.UpdateUser(&UpdateUserRequest{UserId: "user-id"})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestSetUserPasswordHappyPath tests the happy path for setting a user's password.
func TestSetUserPasswordHappyPath(t *testing.T) {
	mockedUserID := "user-id"
	expectedResponse := SetUserPasswordResponse{
		Status: "true",
	}
	responseBody, err := json.Marshal(expectedResponse)
	if err != nil {
		t.Fatalf("Failed to marshal expected response: %v", err)
	}

	mockReq := &MockRequester{
		ResponseBody: string(responseBody),
	}

	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	request := &SetUserPasswordRequest{
		UserId:   mockedUserID,
		Password: "newPassword!",
	}
	response, err := c.SetUserPassword(request)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if response == nil {
		t.Errorf("expected a response, got nil")
	}

	if response.Status != "true" {
		t.Errorf("expected success to be true, got false")
	}
}

// TestSetUserPasswordPostError simulates an error from the HTTP client.
func TestSetUserPasswordPostError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseErr: fmt.Errorf("failed to post"),
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.SetUserPassword(&SetUserPasswordRequest{UserId: "user-id"})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestSetUserPasswordDecodeError simulates a decode error from the HTTP client.
func TestSetUserPasswordDecodeError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseBody: `{"invalidJson"}`,
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.SetUserPassword(&SetUserPasswordRequest{UserId: "user-id"})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestGetUserMetadataHappyPath tests the happy path for getting user metadata.
func TestGetAllUserMetadataHappyPath(t *testing.T) {
	mockedUserID := "user-id"
	expectedResponse := GetAllUserMetadataResponse{
		Items: []MetadataItem{
			{Key: "key1", Value: "value1"},
			{Key: "key2", Value: "value2"},
		},
	}
	responseBody, err := json.Marshal(expectedResponse)
	if err != nil {
		t.Fatalf("Failed to marshal expected response: %v", err)
	}

	mockReq := &MockRequester{
		ResponseBody: string(responseBody),
	}

	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	request := &GetAllUserMetadataRequest{
		UserId: mockedUserID,
	}
	response, err := c.GetAllUserMetadata(request)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if response == nil || len(response.Items) != len(expectedResponse.Items) {
		t.Errorf("expected a response with %d items, got %d", len(expectedResponse.Items), len(response.Items))
	}

	for i, item := range response.Items {
		expectedItem := expectedResponse.Items[i]
		if item.Key != expectedItem.Key || item.Value != expectedItem.Value {
			t.Errorf("expected item %d key to be %s and value to be %s, got key %s and value %s", i, expectedItem.Key, expectedItem.Value, item.Key, item.Value)
		}
	}
}

// TestGetAllUserMetadataPostError simulates an error from the HTTP client.
func TestGetAllUserMetadataPostError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseErr: fmt.Errorf("failed to post"),
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.GetAllUserMetadata(&GetAllUserMetadataRequest{UserId: "user-id"})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestGetAllUserMetadataDecodeError simulates a decode error from the HTTP client.
func TestGetAllUserMetadataDecodeError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseBody: `{"invalidJson"}`,
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.GetAllUserMetadata(&GetAllUserMetadataRequest{UserId: "user-id"})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestSetUserMetadataHappyPath tests the happy path for setting user metadata.
func TestSetUserMetadataHappyPath(t *testing.T) {
	mockedUserID := "user-id"
	expectedResponse := SetUserMetadataResponse{
		Status: "true",
	}
	responseBody, err := json.Marshal(expectedResponse)
	if err != nil {
		t.Fatalf("Failed to marshal expected response: %v", err)
	}

	mockReq := &MockRequester{
		ResponseBody: string(responseBody),
	}

	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	request := &SetUserMetadataRequest{
		UserId: mockedUserID,
		Metadata: []MetadataItem{
			{Key: "key1", Value: "value1"},
			{Key: "key2", Value: "value2"},
		},
	}
	response, err := c.SetUserMetadata(request)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if response == nil {
		t.Errorf("expected a response, got nil")
	}

	if response.Status != "true" {
		t.Errorf("expected success to be true, got %v", response.Status)
	}
}

// TestSetUserMetadataPostError simulates an error from the HTTP client.
func TestSetUserMetadataPostError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseErr: fmt.Errorf("failed to post"),
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.SetUserMetadata(&SetUserMetadataRequest{UserId: "user-id"})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestSetUserMetadataDecodeError simulates a decode error from the HTTP client.
func TestSetUserMetadataDecodeError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseBody: `{"invalidJson"}`,
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.SetUserMetadata(&SetUserMetadataRequest{UserId: "user-id"})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestDeleteUserMetadataHappyPath tests the happy path for deleting user metadata.
func TestDeleteUserMetadataHappyPath(t *testing.T) {
	mockedUserID := "user-id"
	keyToDelete := "key-to-delete"
	expectedResponse := DeleteUserMetadataResponse{
		Status: "true",
	}
	responseBody, err := json.Marshal(expectedResponse)
	if err != nil {
		t.Fatalf("Failed to marshal expected response: %v", err)
	}

	mockReq := &MockRequester{
		ResponseBody: string(responseBody),
	}

	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	request := &DeleteUserMetadataRequest{
		UserId: mockedUserID,
		Metadata: []string{
			keyToDelete,
		},
	}
	response, err := c.DeleteUserMetadata(request)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if response == nil {
		t.Errorf("expected a response, got nil")
	}

	if response.Status != "true" {
		t.Errorf("expected success to be true, got %v", response.Status)
	}
}

// TestDeleteUserMetadataPostError simulates an error from the HTTP client.
func TestDeleteUserMetadataPostError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseErr: fmt.Errorf("failed to post"),
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.DeleteUserMetadata(&DeleteUserMetadataRequest{UserId: "user-id", Metadata: []string{"key-to-delete"}})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestDeleteUserMetadataDecodeError simulates a decode error from the HTTP client.
func TestDeleteUserMetadataDecodeError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseBody: `{"invalidJson"}`,
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.DeleteUserMetadata(&DeleteUserMetadataRequest{UserId: "user-id", Metadata: []string{"key-to-delete"}})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestAdminMigrateBcryptUsersHappyPath tests the happy path for migrating users to bcrypt.
func TestAdminMigrateBcryptUsersHappyPath(t *testing.T) {
	expectedResponse := AdminMigrateUsersResponse{
		Items: []UserId{
			{UserId: "user-id-1"},
		},
	}
	responseBody, err := json.Marshal(expectedResponse)
	if err != nil {
		t.Fatalf("Failed to marshal expected response: %v", err)
	}

	mockReq := &MockRequester{
		ResponseBody: string(responseBody),
	}

	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	request := &AdminMigrateBcryptUsersRequest{}
	response, err := c.AdminMigrateBcryptUsers(request)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if response == nil {
		t.Errorf("expected a response, got nil")
	}

	if len(response.Items) != 1 {
		t.Errorf("expected 1 item, got %d", len(response.Items))
	}
}

// TestAdminMigrateBcryptUsersPostError simulates an error from the HTTP client.
func TestAdminMigrateBcryptUsersPostError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseErr: fmt.Errorf("failed to post"),
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.AdminMigrateBcryptUsers(&AdminMigrateBcryptUsersRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestAdminMigrateBcryptUsersDecodeError simulates a decode error from the HTTP client.
func TestAdminMigrateBcryptUsersDecodeError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseBody: `{"invalidJson"}`,
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.AdminMigrateBcryptUsers(&AdminMigrateBcryptUsersRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestAdminMigrateSha512UsersHappyPath tests the happy path for migrating users to SHA-512.
func TestAdminMigrateSha512UsersHappyPath(t *testing.T) {
	expectedResponse := AdminMigrateUsersResponse{
		Items: []UserId{
			{UserId: "user-id-1"},
		},
	}
	responseBody, err := json.Marshal(expectedResponse)
	if err != nil {
		t.Fatalf("Failed to marshal expected response: %v", err)
	}

	mockReq := &MockRequester{
		ResponseBody: string(responseBody),
	}

	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	request := &AdminMigrateSha512UsersRequest{}
	response, err := c.AdminMigrateSha512Users(request)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if response == nil {
		t.Errorf("expected a response, got nil")
	}

	if len(response.Items) != 1 {
		t.Errorf("expected 1 item, got %d", len(response.Items))
	}
}

// TestAdminMigrateSha512UsersPostError simulates an error from the HTTP client.
func TestAdminMigrateSha512UsersPostError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseErr: fmt.Errorf("failed to post"),
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.AdminMigrateSha512Users(&AdminMigrateSha512UsersRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestAdminMigrateSha512UsersDecodeError simulates a decode error from the HTTP client.
func TestAdminMigrateSha512UsersDecodeError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseBody: `{"invalidJson"}`,
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.AdminMigrateSha512Users(&AdminMigrateSha512UsersRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestAdminImpersonateStartHappyPath tests the happy path for starting impersonation.
func TestAdminImpersonateStartHappyPath(t *testing.T) {
	expectedResponse := AdminImpersonateStartResponse{
		Status: "true",
	}
	responseBody, err := json.Marshal(expectedResponse)
	if err != nil {
		t.Fatalf("Failed to marshal expected response: %v", err)
	}

	mockReq := &MockRequester{
		ResponseBody: string(responseBody),
	}

	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	request := &AdminImpersonateStartRequest{
		UserId: "user-id-to-impersonate",
	}
	response, err := c.AdminImpersonateStart(request)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if response == nil {
		t.Errorf("expected a response, got nil")
	}

	if response.Status != "true" {
		t.Errorf("expected success to be true, got false")
	}
}

// TestAdminImpersonateStartPostError simulates an error from the HTTP client.
func TestAdminImpersonateStartPostError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseErr: fmt.Errorf("failed to post"),
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.AdminImpersonateStart(&AdminImpersonateStartRequest{UserId: "user-id-to-impersonate"})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestAdminImpersonateStartDecodeError simulates a decode error from the HTTP client.
func TestAdminImpersonateStartDecodeError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseBody: `{"invalidJson"}`,
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.AdminImpersonateStart(&AdminImpersonateStartRequest{UserId: "user-id-to-impersonate"})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestAdminImpersonateStopHappyPath tests the happy path for stopping impersonation.
func TestAdminImpersonateStopHappyPath(t *testing.T) {
	expectedResponse := AdminImpersonateStopResponse{
		Status: "true",
	}
	responseBody, err := json.Marshal(expectedResponse)
	if err != nil {
		t.Fatalf("Failed to marshal expected response: %v", err)
	}

	mockReq := &MockRequester{
		ResponseBody: string(responseBody),
	}

	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	response, err := c.AdminImpersonateStop(&AdminImpersonateStopRequest{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if response == nil {
		t.Errorf("expected a response, got nil")
	}

	if response.Status != "true" {
		t.Errorf("expected success to be true, got false")
	}
}

// TestAdminImpersonateStopPostError simulates an error from the HTTP client.
func TestAdminImpersonateStopPostError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseErr: fmt.Errorf("failed to post"),
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.AdminImpersonateStop(&AdminImpersonateStopRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestAdminImpersonateStopDecodeError simulates a decode error from the HTTP client.
func TestAdminImpersonateStopDecodeError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseBody: `{"invalidJson"}`,
	}
	c := NewClient(&ClientConfig{BaseUrl: "https://example.com", ApiKey: "key", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.AdminImpersonateStop(&AdminImpersonateStopRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}
