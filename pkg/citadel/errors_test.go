package citadel

import "testing"

// TestHTTPError_Error checks that the HTTPError.Error() method returns the expected string.
func TestHTTPError_Error(t *testing.T) {
	tests := []struct {
		name       string
		httpError  HTTPError
		wantErrMsg string
	}{
		{
			name: "BadRequest",
			httpError: HTTPError{
				StatusCode: 400,
				ID:         "BadRequest",
				Message:    "Invalid request parameters",
			},
			wantErrMsg: "HTTP 400 - API error (BadRequest): Invalid request parameters",
		},
		{
			name: "NotFound",
			httpError: HTTPError{
				StatusCode: 404,
				ID:         "NotFound",
				Message:    "Resource not found",
			},
			wantErrMsg: "HTTP 404 - API error (NotFound): Resource not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := tt.httpError.Error()
			if errMsg != tt.wantErrMsg {
				t.Errorf("HTTPError.Error() = %v, want %v", errMsg, tt.wantErrMsg)
			}
		})
	}
}
