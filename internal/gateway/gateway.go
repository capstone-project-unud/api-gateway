package gateway

import (
	"bytes"
	"capstone/api-gateway/internal/accesslog"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	AuthURL, UserURL, AllowedOrigin string
	TrustBFF                        bool
	CapstoneURL                     string
	Redis                           *redis.Client
}

func New(cfg Config) *fiber.App {
	client := &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	app := fiber.New(fiber.Config{AppName: "capstone-gateway", BodyLimit: 11 * 1024 * 1024, ReadTimeout: 30 * time.Second, WriteTimeout: 65 * time.Second, ErrorHandler: func(c fiber.Ctx, e error) error {
		code := 500
		msg := "Gateway mengalami gangguan."
		var fe *fiber.Error
		if errors.As(e, &fe) {
			code = fe.Code
			msg = fe.Message
		}
		return c.Status(code).JSON(fiber.Map{"error": fiber.Map{"message": msg}})
	}})
	app.Use(accesslog.New("api-gateway"))
	app.Use(recover.New())
	app.Use(func(c fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("Referrer-Policy", "same-origin")
		c.Set("Cache-Control", "no-store")
		origin := c.Get("Origin")
		if origin != "" && origin != cfg.AllowedOrigin {
			return fiber.NewError(403, "Origin tidak diizinkan.")
		}
		if c.Get("Sec-Fetch-Site") == "cross-site" {
			return fiber.ErrForbidden
		}
		if origin == cfg.AllowedOrigin {
			c.Set("Access-Control-Allow-Origin", origin)
			c.Set("Access-Control-Allow-Credentials", "true")
			c.Set("Vary", "Origin")
		}
		if c.Method() == "OPTIONS" {
			c.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, OPTIONS")
			c.Set("Access-Control-Allow-Headers", "Content-Type")
			return c.SendStatus(204)
		}
		upload := c.Path() == "/api/v1/capstone/files" && c.Method() == "POST" && strings.HasPrefix(c.Get("Content-Type"), "multipart/form-data;")
		if !upload && c.Method() != "GET" && c.Method() != "HEAD" && !strings.HasPrefix(c.Get("Content-Type"), "application/json") {
			return fiber.NewError(415, "Gunakan Content-Type application/json.")
		}
		return c.Next()
	})
	clientIP := func(c fiber.Ctx) string {
		if cfg.TrustBFF {
			return c.Get("X-Client-IP", c.IP())
		}
		return c.IP()
	}
	if cfg.Redis == nil {
		app.Use(limiter.New(limiter.Config{Max: 180, Expiration: time.Minute, KeyGenerator: clientIP}))
	} else {
		app.Use(func(c fiber.Ctx) error {
			if c.Path() == "/health" {
				return c.Next()
			}
			key := fmt.Sprintf("capstone:rate:%x", sha256.Sum256([]byte(clientIP(c))))
			count, err := cfg.Redis.Eval(c.Context(), `local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],60) end; return n`, []string{key}).Int64()
			if err != nil {
				return fiber.NewError(503, "Pembatasan akses belum tersedia. Silakan coba kembali.")
			}
			if count > 180 {
				c.Set("Retry-After", "60")
				return fiber.NewError(429, "Terlalu banyak permintaan. Coba lagi sebentar.")
			}
			return c.Next()
		})
	}
	app.Get("/health", func(c fiber.Ctx) error { return c.JSON(fiber.Map{"service": "api-gateway", "status": "ok"}) })
	app.All("/api/v1/*", func(c fiber.Ctx) error {
		path := c.Path()
		base := ""
		if path == "/api/v1/auth/login" || path == "/api/v1/auth/logout" || path == "/api/v1/auth/password" {
			base = cfg.AuthURL
		} else if path == "/api/v1/me" || path == "/api/v1/users" || strings.HasPrefix(path, "/api/v1/users/") {
			base = cfg.UserURL
		} else if strings.HasPrefix(path, "/api/v1/capstone/") && cfg.CapstoneURL != "" {
			base = cfg.CapstoneURL
		} else {
			return fiber.ErrNotFound
		}
		upstream, e := url.Parse(base)
		if e != nil {
			return fiber.ErrServiceUnavailable
		}
		upstream.Path = path
		upstream.RawQuery = string(c.Request().URI().QueryString())
		req, e := http.NewRequestWithContext(c.Context(), c.Method(), upstream.String(), bytes.NewReader(c.Body()))
		if e != nil {
			return e
		}
		for _, key := range []string{"Content-Type", "Cookie", "Accept"} {
			if value := c.Get(key); value != "" {
				req.Header.Set(key, value)
			}
		}
		req.Header.Set("X-Client-IP", clientIP(c))
		resp, e := client.Do(req)
		if e != nil {
			return fiber.NewError(503, "Layanan belum tersedia. Silakan coba kembali.")
		}
		defer resp.Body.Close()
		for _, key := range []string{"Content-Type", "Retry-After", "Content-Disposition"} {
			for _, value := range resp.Header.Values(key) {
				c.Set(key, value)
			}
		}
		for _, value := range resp.Header.Values("Set-Cookie") {
			c.Response().Header.Add("Set-Cookie", value)
		}
		body, e := io.ReadAll(io.LimitReader(resp.Body, 64*1024*1024+1))
		if e != nil {
			return fiber.ErrBadGateway
		}
		if len(body) > 64*1024*1024 {
			return fiber.NewError(502, "Ukuran respons terlalu besar. Gunakan filter yang lebih spesifik.")
		}
		return c.Status(resp.StatusCode).Send(body)
	})
	return app
}
