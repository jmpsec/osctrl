package utils

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHTTPResponse(t *testing.T) {
	t.Run("json content-type", func(t *testing.T) {
		rr := httptest.NewRecorder()
		HTTPResponse(rr, JSONApplicationUTF8, http.StatusOK, []byte("JSON Content-Type"))
		assert.Equal(t, JSONApplicationUTF8, rr.Header().Get(ContentType))
		assert.Equal(t, "JSON Content-Type", rr.Body.String())
	})

	t.Run("empty content-type", func(t *testing.T) {
		rr := httptest.NewRecorder()
		HTTPResponse(rr, "", http.StatusOK, []byte("Empty Content-Type"))
		assert.Equal(t, "", rr.Header().Get(ContentType))
		assert.Equal(t, "Empty Content-Type", rr.Body.String())
	})

	t.Run("json body", func(t *testing.T) {
		rr := httptest.NewRecorder()
		type DataJSON struct {
			Key1 string `json:"key1"`
			Key2 string `json:"key2"`
		}
		data := DataJSON{
			Key1: "value1",
			Key2: "value2",
		}
		HTTPResponse(rr, JSONApplication, http.StatusOK, data)
		assert.Equal(t, JSONApplication, rr.Header().Get(ContentType))
		assert.Equal(t, `{"key1":"value1","key2":"value2"}`, rr.Body.String())
	})
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

	t.Run("invalid url", func(t *testing.T) {
		_, _, err := SendRequest(http.MethodPost, "http://whatever/notfound", nil, map[string]string{})
		assert.Error(t, err)
	})
	t.Run("url not found", func(t *testing.T) {
		code, _, err := SendRequest(http.MethodPost, server.URL+"/notfound", nil, map[string]string{})
		assert.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, code)
	})
	t.Run("url not found", func(t *testing.T) {
		code, body, err := SendRequest(http.MethodPost, server.URL+"/server/testing", nil, map[string]string{})
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, code)
		assert.Equal(t, []byte("the test works"), body)
	})
}

func TestDebugHTTPDump(t *testing.T) {
	t.Run("no debug", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://whatever/server/path", nil)
		output := DebugHTTP(req, false, false)
		assert.Equal(t, ``, output)
	})

	t.Run("debug no body", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://whatever/server/path", nil)
		output := DebugHTTP(req, true, false)
		expected := fmt.Sprintf("%s\n", "---------------- request")
		expected += fmt.Sprintf("%s\r\n", "GET /server/path HTTP/1.1")
		expected += fmt.Sprintf("%s\r\n\r\n\n", "Host: whatever")
		expected += fmt.Sprintf("%s\n", "---------------- No Body")
		expected += fmt.Sprintf("%s\n", "---------------- end")
		assert.Equal(t, expected, output)
	})

	t.Run("debug with body", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://whatever/server/path", nil)
		output := DebugHTTP(req, true, false)
		expected := fmt.Sprintf("%s\n", "---------------- request")
		expected += fmt.Sprintf("%s\r\n", "GET /server/path HTTP/1.1")
		expected += fmt.Sprintf("%s\r\n\r\n\n", "Host: whatever")
		expected += fmt.Sprintf("%s\n", "---------------- No Body")
		expected += fmt.Sprintf("%s\n", "---------------- end")
		assert.Equal(t, expected, output)
	})
}
