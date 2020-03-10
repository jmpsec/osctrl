package utils

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHTTPResponse(t *testing.T) {
	rr := httptest.NewRecorder()

	HTTPResponse(rr, JSONApplicationUTF8, http.StatusOK, []byte("JSON Content-Type"))
	assert.Equal(t, rr.Header().Get(ContentType), JSONApplicationUTF8)
	assert.Equal(t, rr.Body.String(), "JSON Content-Type")

	rr = httptest.NewRecorder()
	HTTPResponse(rr, "", http.StatusOK, []byte("empty Content-Type"))
	assert.Equal(t, rr.Header().Get(ContentType), "")
	assert.Equal(t, rr.Body.String(), "empty Content-Type")

	rr = httptest.NewRecorder()
	type DataJSON struct {
		Key1 string `json:"key1"`
		Key2 string `json:"key2"`
	}
	data := DataJSON{
		Key1: "value1",
		Key2: "value2",
	}
	HTTPResponse(rr, JSONApplication, http.StatusOK, data)
	assert.Equal(t, rr.Header().Get(ContentType), JSONApplication)
	assert.Equal(t, rr.Body.String(), `{"key1":"value1","key2":"value2"}`)
}

func serverMock() *httptest.Server {
	handler := http.NewServeMux()
	handler.HandleFunc("/server/testing", testingMock)
	srv := httptest.NewServer(handler)
	return srv
}

func testingMock(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("the test works"))
}

func TestSendRequest(t *testing.T) {
	server := serverMock()
	defer server.Close()

	code, body, err := SendRequest(http.MethodPost, server.URL+"/server/testing", nil, map[string]string{})
	assert.NoError(t, err)
	assert.Equal(t, code, http.StatusOK)
	assert.Equal(t, body, []byte("the test works"))
}
