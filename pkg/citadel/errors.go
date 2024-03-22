package citadel

import "fmt"

type HTTPError struct {
	StatusCode int
	ID         string
	Message    string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d - API error (%v): %v", e.StatusCode, e.ID, e.Message)
}
