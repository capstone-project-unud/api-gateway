package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGatewayBoundary(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Service-Token") != "" {
			t.Error("service token leaked from public request")
		}
		w.Header().Set("Set-Cookie", "capstone_session=test; HttpOnly; SameSite=Strict; Path=/")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()
	app := New(Config{AuthURL: backend.URL, UserURL: backend.URL, CapstoneURL: backend.URL, AllowedOrigin: "http://localhost:3000"})
	cases := []struct {
		path, origin string
		status       int
	}{
		{"/api/v1/users", "http://localhost:3000", 200},
		{"/api/v1/capstone/projects", "http://localhost:3000", 200},
		{"/api/v1/auth/login", "https://evil.example", 403},
		{"/internal/credentials/id", "", 404},
		{"/api/v1/internal/users", "", 404},
	}
	for _, tc := range cases {
		t.Run(tc.path+tc.origin, func(t *testing.T) {
			r := httptest.NewRequest("POST", tc.path, strings.NewReader(`{}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("X-Service-Token", "attacker-controlled")
			resp, e := app.Test(r)
			if e != nil {
				t.Fatal(e)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.status {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("status=%d body=%s", resp.StatusCode, b)
			}
			if tc.status == 200 && !strings.Contains(resp.Header.Get("Set-Cookie"), "HttpOnly") {
				t.Error("cookie lost")
			}
			if tc.status == 200 && resp.Header.Get("Content-Type") != "application/json" {
				t.Error("upstream JSON content type changed")
			}
		})
	}
}

func TestMultipartIsLimitedToUploadEndpoints(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer upstream.Close()
	app := New(Config{CapstoneURL: upstream.URL, AllowedOrigin: "http://localhost:3000"})
	for _, test := range []struct {
		path   string
		status int
	}{{"/api/v1/capstone/signature", 204}, {"/api/v1/capstone/files", 204}, {"/api/v1/capstone/proposals", 415}} {
		req := httptest.NewRequest("POST", test.path, strings.NewReader("--boundary--"))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
		req.Header.Set("Origin", "http://localhost:3000")
		res, e := app.Test(req)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != test.status {
			t.Fatalf("%s: status %d", test.path, res.StatusCode)
		}
	}
}
