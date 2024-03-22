package citadel

import (
	"net/http"
)

// mockHTTPClient simulates the httpClient interface for testing.
type mockHTTPClient struct {
	// Add fields to simulate different scenarios
	doFunc      func(req *http.Request) (*http.Response, error)
	lastRequest *http.Request // Add this to capture the last request made
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.lastRequest = req // Capture the request
	return m.doFunc(req)
}
