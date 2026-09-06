package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sentinel-agent/internal/hub"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	authToken := os.Getenv("ENTERPRISE_AUTH_TOKEN")
	enrollmentToken := os.Getenv("HUB_ENROLLMENT_TOKEN")
	if authToken == "" || enrollmentToken == "" {
		slog.Error("ENTERPRISE_AUTH_TOKEN and HUB_ENROLLMENT_TOKEN are required")
		os.Exit(1)
	}

	tlsConfig, err := hub.TLSConfig(
		envOrDefault("HUB_CERT_PATH", "/etc/sentinel/hub/certs/server.crt"),
		envOrDefault("HUB_KEY_PATH", "/etc/sentinel/hub/certs/server.key"),
		envOrDefault("HUB_CLIENT_CA_PATH", "/etc/sentinel/hub/certs/agent-ca.crt"),
	)
	if err != nil {
		slog.Error("could not configure TLS", "error", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr: envOrDefault("HUB_LISTEN_ADDR", ":8443"),
		Handler: hub.NewServer(hub.Config{
			AuthToken:                authToken,
			EnrollmentToken:          enrollmentToken,
			CollectorIntervalSeconds: envIntOrDefault("HUB_COLLECTOR_INTERVAL_SECONDS", 30),
			LogLevel:                 envOrDefault("HUB_LOG_LEVEL", "INFO"),
			UpdateManifestURL:        os.Getenv("HUB_UPDATE_MANIFEST_URL"),
		}).Handler(),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	}()

	slog.Info("SentinelCore HUB listening", "addr", server.Addr, "tls_min_version", "1.3")
	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("HUB stopped unexpectedly", "error", err)
		os.Exit(1)
	}
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envIntOrDefault(key string, fallback int) int {
	value := 0
	if _, err := fmt.Sscanf(os.Getenv(key), "%d", &value); err != nil || value <= 0 {
		return fallback
	}
	return value
}
