package strict

import (
	"net/http"
	"net/http/httptest"
)

// httptestRequest returns a GET / request with no cookies, used by tests that
// only need an *http.Request placeholder.
func httptestRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
}

// httptestResponseWriter returns a fresh response recorder.
func httptestResponseWriter() *httptest.ResponseRecorder {
	return httptest.NewRecorder()
}
