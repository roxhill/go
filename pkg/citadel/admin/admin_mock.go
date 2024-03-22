package admin

import (
	"io"
	"io/ioutil"
	"strings"
)

type MockRequester struct {
	ResponseBody string
	ResponseErr  error
}

func (m *MockRequester) Post(url string, body io.Reader) (*io.ReadCloser, error) {
	if m.ResponseErr != nil {
		return nil, m.ResponseErr
	}
	results := ioutil.NopCloser(strings.NewReader(m.ResponseBody))
	return &results, nil
}
