package citadel

import (
	"encoding/json"
	"github.com/everlutionsk/go/pkg/citadel"
	"io"
	"net/http"
)

const (
	headerContentType   = "Content-Type"
	headerSDKVersion    = "x-sdk-version"
	headerAuthorization = "Authorization"

	sdkVersion                 = "0.8.4-go"
	contentTypeApplicationJSON = "application/json"
)

func NewRequest(config Config) Request {
	return request{
		client:       &http.Client{},
		apiKey:       config.apiKey,
		preSharedKey: config.preSharedKey,
	}
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Request interface {
	Post(url string, body io.Reader) (*io.ReadCloser, error)
}

type request struct {
	client       httpClient
	apiKey       string
	preSharedKey string
}

func (r request) Post(url string, body io.Reader) (*io.ReadCloser, error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set(headerContentType, contentTypeApplicationJSON)
	req.Header.Set(headerSDKVersion, sdkVersion)

	// Add the API key to the request headers if it's provided.
	if r.apiKey != "" {
		// Assuming the API expects the API key in a header called "X-API-Key"
		req.Header.Set(headerAuthorization, r.apiKey)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusBadRequest {
		var httpErr citadel.HTTPError
		if err := json.NewDecoder(resp.Body).Decode(&httpErr); err != nil {
			return nil, err
		}
		httpErr.StatusCode = resp.StatusCode
		return nil, &httpErr
	}

	return &resp.Body, nil
}
