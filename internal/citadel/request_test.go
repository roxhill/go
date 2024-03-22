package citadel

import (
	"bytes"
	"fmt"
	"github.com/everlutionsk/go/pkg/citadel"
	"io/ioutil"
	"net/http"
	"testing"
)

// setupMockRequest initializes a request with a mock HTTP client.
// The doFunc parameter allows customization of the mock client's behavior.
func setupMockRequest(doFunc func(req *http.Request) (*http.Response, error)) request {
	return request{
		client: &mockHTTPClient{
			doFunc: doFunc,
		},
	}
}

// TestPost_Success demonstrates a successful POST request.
func TestPost_Success(t *testing.T) {
	r := setupMockRequest(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(bytes.NewBufferString(`OK`)),
		}, nil
	})

	body := bytes.NewBufferString(`{"key":"value"}`)
	respBody, err := r.Post("https://example.com", body)

	if respBody == nil {
		t.Fatal("Expected response body, got nil")
	}

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

// TestPost_HTTPClientError simulates an error from the HTTP client.
func TestPost_HTTPClientError(t *testing.T) {
	r := setupMockRequest(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("client error")
	})

	body := bytes.NewBufferString(`{"key":"value"}`)
	respBody, err := r.Post("https://example.com", body)

	// Ensure that the response body is nil.
	if respBody != nil {
		t.Fatalf("Expected response body to be nil, got %v", respBody)
	}

	// Ensure that the error is not nil.
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}

// TestPost_BadRequest simulates receiving a 400 Bad Request status code.
func TestPost_BadRequest(t *testing.T) {
	r := setupMockRequest(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       ioutil.NopCloser(bytes.NewBufferString(`{"id":"errorId","message":"Error message"}`)),
		}, nil
	})

	body := bytes.NewBufferString(`{"key":"value"}`)
	respBody, err := r.Post("http://example.com", body)

	httpErr, ok := err.(*citadel.HTTPError)
	if !ok {
		t.Fatalf("Expected error to be of type *HTTPError, got %T", err)
	}

	if respBody != nil {
		t.Fatalf("Expected response body to be nil, got %v", respBody)
	}

	if httpErr.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status code %d, got %d", http.StatusBadRequest, httpErr.StatusCode)
	}
	if httpErr.ID != "errorId" {
		t.Errorf("Expected ID %q, got %q", "errorId", httpErr.ID)
	}
	if httpErr.Message != "Error message" {
		t.Errorf("Expected message %q, got %q", "Error message", httpErr.Message)
	}
}

func TestPostAPIKeyHeader(t *testing.T) {
	tests := []struct {
		name         string
		config       Config
		expectedKey  string
		expectHeader bool
	}{
		{
			name: "With API Key",
			config: Config{
				apiKey: "test-api-key",
			},
			expectedKey:  "test-api-key",
			expectHeader: true,
		},
		{
			name:         "Without API Key",
			config:       Config{}, // No API key set
			expectedKey:  "",
			expectHeader: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockHTTPClient{
				doFunc: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       ioutil.NopCloser(bytes.NewBufferString("OK")),
					}, nil
				},
			}

			r := request{
				client: mockClient,
				apiKey: tt.config.apiKey,
			}

			_, _ = r.Post("https://example.com", bytes.NewBufferString(`{}`))

			apiKeyHeader := mockClient.lastRequest.Header.Get(headerAuthorization)
			if tt.expectHeader && apiKeyHeader != tt.expectedKey {
				t.Errorf("Expected API key header to be '%s', got '%s'", tt.expectedKey, apiKeyHeader)
			} else if !tt.expectHeader && apiKeyHeader != "" {
				t.Errorf("Expected no API key header, found '%s'", apiKeyHeader)
			}
		})
	}
}
