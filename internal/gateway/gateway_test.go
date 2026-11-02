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
	app := New(Config{AuthURL: backend.URL, UserURL: backend.URL, AllowedOrigin: "http://localhost:3000"})
	cases := []struct {
		path, origin string
		status       int
	}{
		{"/api/v1/users", "http://localhost:3000", 200},
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
