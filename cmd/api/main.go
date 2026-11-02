package main

import (
	"capstone/api-gateway/internal/gateway"
	"context"
	"github.com/joho/godotenv"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	_ = godotenv.Load()
	auth, users, origin := os.Getenv("AUTH_SERVICE_URL"), os.Getenv("USER_SERVICE_URL"), os.Getenv("ALLOWED_ORIGIN")
	if auth == "" || users == "" || origin == "" {
		log.Fatal("AUTH_SERVICE_URL, USER_SERVICE_URL and ALLOWED_ORIGIN are required")
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	app := gateway.New(gateway.Config{AuthURL: auth, UserURL: users, AllowedOrigin: origin, TrustBFF: os.Getenv("TRUST_BFF") == "true"})
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() { <-ctx.Done(); _ = app.ShutdownWithTimeout(10 * time.Second) }()
	host := os.Getenv("BIND_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	if e := app.Listen(host + ":" + port); e != nil {
		log.Fatal(e)
	}
}
