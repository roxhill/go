package client

import (
	"encoding/json"
	"fmt"
	"testing"
)

// TestSessionResolveHappyPath tests the happy path for the SessionResolve method.
func TestSessionResolveHappyPath(t *testing.T) {
	mockedSessionID := "session-id"
	expectedResponse := SessionResolveResponse{
		Session: ResolvedSession{
			Id: mockedSessionID,
		},
	}
	responseBody, err := json.Marshal(expectedResponse)
	if err != nil {
		t.Fatalf("Failed to marshal expected response: %v", err)
	}
	mockReq := &MockRequester{
		ResponseBody: string(responseBody),
	}
	c := NewClient(&Config{BaseUrl: "https://example.com", PreSharedKey: "key"})
	c.(*client).request = mockReq

	response, err := c.SessionResolve(&SessionResolveRequest{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if response == nil {
		t.Errorf("expected a response, got nil")
	}
	if response.Session.Id != mockedSessionID {
		t.Errorf("expected session ID %s, got %s", mockedSessionID, response.Session.Id)
	}
}

// TestSessionResolvePostError tests the error path for the SessionResolve method.
func TestSessionResolvePostError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseErr: fmt.Errorf("failed to post"),
	}
	c := NewClient(&Config{BaseUrl: "https://example.com", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.SessionResolve(&SessionResolveRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestSessionResolveDecodeError tests the error path for the SessionResolve method.
func TestSessionResolveDecodeError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseBody: `{"invalidJson"}`,
	}
	c := NewClient(&Config{BaseUrl: "https://example.com", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.SessionResolve(&SessionResolveRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestSessionRevokeHappyPath tests the happy path for the SessionRevoke method.
func TestSessionRevokeHappyPath(t *testing.T) {
	mockedSessionResponse := map[string]string{"status": "success"}
	expectedResponse := SessionRevokeResponse{
		ResponseHeaders: mockedSessionResponse,
	}
	responseBody, err := json.Marshal(expectedResponse)
	if err != nil {
		t.Fatalf("Failed to marshal expected response: %v", err)
	}
	mockReq := &MockRequester{
		ResponseBody: string(responseBody),
	}
	c := NewClient(&Config{BaseUrl: "https://example.com", PreSharedKey: "key"})
	c.(*client).request = mockReq

	response, err := c.SessionRevoke(&SessionRevokeRequest{})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if response == nil {
		t.Errorf("expected a response, got nil")
	}

	if response.ResponseHeaders["status"] != "success" {
		t.Errorf("expected status success, got %s", response.ResponseHeaders["status"])
	}
}

// TestSessionRevokePostError tests the error path for the SessionRevoke method.
func TestSessionRevokePostError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseErr: fmt.Errorf("failed to post"),
	}
	c := NewClient(&Config{BaseUrl: "https://example.com", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.SessionRevoke(&SessionRevokeRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestSessionRevokeDecodeError tests the error path for the SessionRevoke method.
func TestSessionRevokeDecodeError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseBody: `{"invalidJson"}`,
	}
	c := NewClient(&Config{BaseUrl: "https://example.com", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.SessionRevoke(&SessionRevokeRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestSessionResolveBearerHappyPath tests the happy path for the SessionResolveBearer method.
func TestSessionResolveBearerHappyPath(t *testing.T) {
	mockedBearerToken := "bearer-token"
	expectedResponse := SessionResolveBearerResponse{
		Session: ResolvedSession{
			Id: mockedBearerToken,
		},
	}
	responseBody, err := json.Marshal(expectedResponse)
	if err != nil {
		t.Fatalf("Failed to marshal expected response: %v", err)
	}
	mockReq := &MockRequester{
		ResponseBody: string(responseBody),
	}
	c := NewClient(&Config{BaseUrl: "https://example.com", PreSharedKey: "key"})
	c.(*client).request = mockReq

	response, err := c.SessionResolveBearer(&BearerSessionRequest{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if response == nil {
		t.Errorf("expected a response, got nil")
	}

	if response.Session.Id != mockedBearerToken {
		t.Errorf("expected bearer token %s, got %s", mockedBearerToken, response.Session.Id)
	}
}

// TestSessionResolveBearerPostError tests the error path for the SessionResolveBearer method.
func TestSessionResolveBearerPostError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseErr: fmt.Errorf("failed to post"),
	}
	c := NewClient(&Config{BaseUrl: "https://example.com", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.SessionResolveBearer(&BearerSessionRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestSessionResolveBearerDecodeError tests the error path for the SessionResolveBearer method.
func TestSessionResolveBearerDecodeError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseBody: `{"invalidJson"}`,
	}
	c := NewClient(&Config{BaseUrl: "https://example.com", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.SessionResolveBearer(&BearerSessionRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestSessionRevokeBearerHappyPath tests the happy path for the SessionRevokeBearer method.
func TestSessionRevokeBearerHappyPath(t *testing.T) {
	mockedBearerToken := "bearer-token"
	expectedResponse := SessionRevokeBearerResponse{
		Status: "status-true",
	}
	responseBody, err := json.Marshal(expectedResponse)
	if err != nil {
		t.Fatalf("Failed to marshal expected response: %v", err)
	}
	mockReq := &MockRequester{
		ResponseBody: string(responseBody),
	}
	c := NewClient(&Config{BaseUrl: "https://example.com", PreSharedKey: "key"})
	c.(*client).request = mockReq

	response, err := c.SessionRevokeBearer(&BearerSessionRequest{Token: mockedBearerToken})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if response == nil {
		t.Errorf("expected a response, got nil")
	}

	if response.Status != "status-true" {
		t.Errorf("expected status true, got %s", response.Status)
	}
}

// TestSessionRevokeBearerPostError tests the error path for the SessionRevokeBearer method.
func TestSessionRevokeBearerPostError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseErr: fmt.Errorf("failed to post"),
	}
	c := NewClient(&Config{BaseUrl: "https://example.com", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.SessionRevokeBearer(&BearerSessionRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// TestSessionRevokeBearerDecodeError tests the error path for the SessionRevokeBearer method.
func TestSessionRevokeBearerDecodeError(t *testing.T) {
	mockReq := &MockRequester{
		ResponseBody: `{"invalidJson"}`,
	}
	c := NewClient(&Config{BaseUrl: "https://example.com", PreSharedKey: "key"})
	c.(*client).request = mockReq

	_, err := c.SessionRevokeBearer(&BearerSessionRequest{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}
